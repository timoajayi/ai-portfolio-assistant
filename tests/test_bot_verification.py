"""Provisional protocol and issuance tests: all HTTP transports are mocked."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import hashlib
import gzip
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import uuid4
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

from src import usage
from src.bot_verification import SITEVERIFY_URL, TurnstileAdapter, VerifiedSessionService, VerificationError
from src.config import Settings
from src.usage import UsageDenied, UsageLedger
from tests.offline import OfflineTestCase
from tests.test_ip_admission import IPFixture


class BotFixture(IPFixture):
    def setUp(self):
        super().setUp()
        self.ledger.set_disabled(True)
        self.ledger.migrate_verification(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.settings = replace(self.settings, bot_verification_enabled=True, session_issuance_enabled=True,
                                bot_secret='offline-provider-secret-not-real', bot_hostnames=('portfolio.example.test',),
                                bot_action='portfolio_session', bot_timeout_seconds=0.1)
        self.proof = 'offline-proof-sensitive-marker'
        self.request = uuid4().hex
        self.binding = hashlib.sha256(b'fixed-synthetic-gateway').digest()
        self.calls = []
        self.handler = lambda request: httpx.Response(200, json=self.success())
        async def transport(request):
            self.calls.append(request)
            return await self.handler(request) if asyncio.iscoroutinefunction(self.handler) else self.handler(request)
        self.adapter = TurnstileAdapter(self.settings, transport=httpx.MockTransport(transport), clock=lambda: self.now)
        self.service = VerifiedSessionService(self.adapter)

    def success(self, **changes):
        return {'success': True, 'hostname': 'portfolio.example.test', 'action': 'portfolio_session',
                'challenge_ts': self.now.isoformat(), 'error-codes': [], **changes}

    def claims(self):
        with sqlite3.connect(self.usage_path) as db:
            return db.execute('SELECT * FROM verification_claims ORDER BY request_id').fetchall()

    def issue(self, proof=None, request=None):
        return asyncio.run(self.service.issue(self.settings, self.scope, self.proof if proof is None else proof,
                                              uuid4().hex if request is None else request))

    def assert_no_new_session(self, operation, error=(VerificationError, UsageDenied)):
        before = self.rows()['sessions']
        with self.assertRaises(error): operation()
        self.assertEqual(self.rows()['sessions'], before)
        self.client_factory.assert_not_called()


class BotProtocolTests(BotFixture):
    def test_success_uses_fixed_https_endpoint_and_only_proof_and_secret(self):
        result = asyncio.run(self.adapter.verify(self.proof))
        self.assertEqual(result.challenged_at, self.now)
        self.assertEqual(len(self.calls), 1)
        request = self.calls[0]
        self.assertEqual(str(request.url), SITEVERIFY_URL)
        self.assertEqual(request.method, 'POST')
        self.assertNotIn(self.proof, str(request.url))
        self.assertIn(b'response=', request.content)
        self.assertIn(b'secret=', request.content)
        self.assertNotIn(b'remoteip', request.content)

    def test_identity_negotiation_avoids_compressed_provider_response(self):
        # Reproduce a provider that compresses when HTTPX advertises compression.
        def negotiated(request):
            if request.headers.get('accept-encoding') != 'identity':
                return httpx.Response(200, content=gzip.compress(json.dumps(self.success()).encode()),
                    headers={'Content-Type': 'application/json', 'Content-Encoding': 'gzip'})
            return httpx.Response(200, json=self.success())
        self.handler = negotiated
        before = self.ledger.status()
        result = self.issue()
        self.assertEqual(self.calls[0].headers.get_list('accept-encoding'), ['identity'])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.ledger.lookup_session(hashlib.sha256(result['token'].encode()).digest())['verified'], 1)
        self.assertEqual(self.claims()[0][4], 'issued')
        self.assertEqual(self.ledger.status(), before)
        self.client_factory.assert_not_called()

    def test_identity_negotiation_preserves_failed_verification_rejection(self):
        def failed(request):
            self.assertEqual(request.headers.get_list('accept-encoding'), ['identity'])
            return httpx.Response(200, json={'success': False, 'error-codes': ['invalid-input-response']})
        self.handler = failed
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'failed')
        self.assertEqual(len(self.calls), 1)

    def test_identity_negotiation_preserves_streamed_response_size_limit(self):
        class Oversized(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b' ' * 4096
                yield b' ' * 4097
        def oversized(request):
            self.assertEqual(request.headers.get_list('accept-encoding'), ['identity'])
            return httpx.Response(200, stream=Oversized(),
                headers={'Content-Type': 'application/json', 'Content-Encoding': 'identity'})
        self.handler = oversized
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'failed')

    def test_documented_optional_metadata_does_not_reject_valid_success(self):
        self.handler = lambda request: httpx.Response(200, json=self.success(
            metadata={'ephemeral_id': 'offline-optional-metadata'}))
        self.assertEqual(asyncio.run(self.adapter.verify(self.proof)).challenged_at, self.now)

    def test_optional_metadata_cannot_override_verification_policy(self):
        for changes in ({'success': False}, {'success': 1}, {'hostname': 'attacker.test'},
                        {'action': 'wrong'}, {'error-codes': ['internal-error']},
                        {'challenge_ts': (self.now - timedelta(seconds=301)).isoformat()}):
            with self.subTest(changes=changes):
                self.handler = lambda request: httpx.Response(200, json=self.success(
                    metadata={'success': True, 'verified': True}, **changes))
                with self.assertRaises(VerificationError):
                    asyncio.run(self.adapter.verify(self.proof))
        for field in ('success', 'hostname', 'action', 'challenge_ts'):
            body = self.success(metadata={})
            del body[field]
            self.handler = lambda request: httpx.Response(200, json=body)
            with self.assertRaises(VerificationError):
                asyncio.run(self.adapter.verify(self.proof))

    def test_invalid_metadata_and_unknown_top_level_fields_remain_rejected(self):
        for changes in ({'metadata': None}, {'metadata': []}, {'metadata': 'invalid'},
                        {'metadata': {}, 'verified': True}):
            with self.subTest(changes=changes):
                self.handler = lambda request: httpx.Response(200, json=self.success(**changes))
                with self.assertRaises(VerificationError):
                    asyncio.run(self.adapter.verify(self.proof))

    def test_disabled_adapter_never_constructs_transport(self):
        adapter = TurnstileAdapter(replace(self.settings, bot_verification_enabled=False))
        with patch('src.bot_verification.httpx.AsyncHTTPTransport') as transport:
            with self.assertRaises(VerificationError): asyncio.run(adapter.verify(self.proof))
            transport.assert_not_called()

    def test_tls_redirect_proxy_and_retry_configuration(self):
        with patch('src.bot_verification.httpx.AsyncHTTPTransport', return_value=self.adapter.transport) as transport:
            adapter = TurnstileAdapter(self.settings, clock=lambda: self.now)
            asyncio.run(adapter.verify(self.proof))
        transport.assert_called_once_with(verify=True, retries=0, trust_env=False)

    def test_wrong_hostname_action_false_success_and_errors_rejected(self):
        for changes in ({'hostname': 'attacker.test'}, {'action': 'other'}, {'success': False}, {'success': 1},
                        {'error-codes': ['invalid-input-response']}, {'error-codes': False}, {'message': self.proof}):
            with self.subTest(changes=changes):
                self.handler = lambda request: httpx.Response(200, json=self.success(**changes))
                with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))

    def test_missing_required_fields_and_malformed_types_rejected(self):
        for field in ('success', 'hostname', 'action', 'challenge_ts'):
            body = self.success()
            del body[field]
            self.handler = lambda request: httpx.Response(200, json=body)
            with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))
        for value in (None, [], 'invalid', {'success': True, 'hostname': []}):
            self.handler = lambda request: httpx.Response(200, json=value)
            with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))

    def test_invalid_duplicate_nonfinite_json_and_oversize_rejected(self):
        for content in (b'not-json', b'{"success":false,"success":true}', b'{"success":NaN}', b' ' * 8193):
            self.handler = lambda request: httpx.Response(200, content=content, headers={'Content-Type': 'application/json'})
            with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))

    def test_streamed_oversize_ignores_false_length(self):
        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b' ' * 4096
                yield b' ' * 4097
        self.handler = lambda request: httpx.Response(200, stream=Stream(), headers={'Content-Type': 'application/json', 'Content-Length': '2'})
        with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))

    def test_redirect_and_status_failures_never_retry(self):
        for status in (301, 302, 307, 429, 500):
            self.calls.clear()
            self.handler = lambda request: httpx.Response(status, headers={'Location': 'https://attacker.test'})
            with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))
            self.assertEqual(len(self.calls), 1)

    def test_connection_failure_and_transport_timeout_never_retry(self):
        for error in (httpx.ConnectError('PRIVATE'), httpx.ReadTimeout('PRIVATE')):
            self.calls.clear()
            def fail(request): raise error
            self.handler = fail
            with self.assertRaises(VerificationError) as caught: asyncio.run(self.adapter.verify(self.proof))
            self.assertNotIn('PRIVATE', str(caught.exception))
            self.assertEqual(len(self.calls), 1)

    def test_absolute_deadline_bounds_response_streaming(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(1)
                yield b'{}'
        self.handler = lambda request: httpx.Response(200, stream=Slow(), headers={'Content-Type': 'application/json'})
        with self.assertRaises(VerificationError) as caught: asyncio.run(self.adapter.verify(self.proof))
        self.assertEqual(caught.exception.status, 504)

    def test_age_boundary_future_naive_and_expired_rejected(self):
        for seconds, accepted in ((0, True), (300, True), (300.001, False), (-0.001, False)):
            challenged = self.now - timedelta(seconds=seconds)
            self.handler = lambda request: httpx.Response(200, json=self.success(challenge_ts=challenged.isoformat()))
            if accepted: asyncio.run(self.adapter.verify(self.proof))
            else:
                with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))
        self.handler = lambda request: httpx.Response(200, json=self.success(challenge_ts='2026-11-09T12:00:00'))
        with self.assertRaises(VerificationError): asyncio.run(self.adapter.verify(self.proof))


class VerifiedIssuanceTests(BotFixture):
    def test_success_creates_exactly_one_verified_session_without_gemini_accounting(self):
        before = self.ledger.status()
        result = self.issue()
        session = self.ledger.lookup_session(hashlib.sha256(result['token'].encode()).digest())
        self.assertEqual(session['verified'], 1)
        self.assertEqual(result['expires_at'], int(self.now.timestamp()) + 14400)
        self.assertEqual(self.ledger.status(), before)
        self.assertEqual(self.claims()[0][4], 'issued')
        self.assertEqual(self.claims()[0][0], hashlib.sha256(self.proof.encode()).digest())
        for marker in (self.proof, result['token'], self.settings.bot_secret):
            self.assertNotIn(marker.encode(), self.usage_path.read_bytes())
        self.client_factory.assert_not_called()

    def test_metadata_success_issues_verified_session_without_persisting_metadata(self):
        marker = 'optional-metadata-sensitive-marker'
        self.handler = lambda request: httpx.Response(200, json=self.success(metadata={'ephemeral_id': marker}))
        before = self.ledger.status()
        result = self.issue()
        session = self.ledger.lookup_session(hashlib.sha256(result['token'].encode()).digest())
        self.assertEqual(session['verified'], 1)
        self.assertEqual(self.claims()[0][4], 'issued')
        self.assertNotIn(marker.encode(), self.usage_path.read_bytes())
        self.assertEqual(self.ledger.status(), before)
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(len(self.calls), 1)

    def test_invalid_and_replayed_proof_do_not_issue(self):
        self.issue()
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(len(self.calls), 1)
        for proof in ('', ' ', 'x' * 2049, '\u2603'):
            self.assert_no_new_session(lambda: self.issue(proof))
        self.assertEqual(len(self.calls), 1)

    def test_failure_remains_consumed_after_restart(self):
        self.handler = lambda request: httpx.Response(200, json={'success': False})
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'failed')
        code = '''
import sys
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
from uuid import uuid4
with ExitStack() as guard:
 for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','dotenv.load_dotenv'):
  guard.enter_context(patch(target,side_effect=AssertionError('offline')))
 from src.usage import UsageLedger,UsageDenied
 try:
  UsageLedger(Path(sys.argv[1])).claim_verification(bytes.fromhex(sys.argv[2]),uuid4().hex,b'x'*32)
  print('UNSAFE')
 except UsageDenied as e: print(e.category)
'''
        result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path), hashlib.sha256(self.proof.encode()).hexdigest()],
                                capture_output=True, text=True, timeout=10, env={'PATH': os.defpath})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'verification_replay')

    def test_concurrent_duplicate_proofs_make_one_provider_call_and_session(self):
        async def delayed(request):
            await asyncio.sleep(0.03)
            return httpx.Response(200, json=self.success())
        self.handler = delayed
        async def run():
            return await asyncio.gather(*(self.service.issue(self.settings, self.scope, self.proof, uuid4().hex)
                                          for _ in range(8)), return_exceptions=True)
        results = asyncio.run(run())
        self.assertEqual(sum(type(r) is dict for r in results), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.claims()), 1)

    def test_issuance_quotas_rechecked_atomically_after_verification(self):
        self.settings = replace(self.settings, session_issuance_minute_limit=1)
        self.adapter.settings = self.settings
        self.issue('proof-first')
        self.assert_no_new_session(lambda: self.issue('proof-second'))
        self.assertEqual([row[4] for row in self.claims()].count('issued'), 1)

    def test_concurrent_valid_proofs_compete_for_final_issuance_slot(self):
        self.settings = replace(self.settings, session_issuance_minute_limit=1)
        self.adapter.settings = self.settings
        async def run():
            return await asyncio.gather(*(self.service.issue(self.settings, self.scope, 'proof-' + str(i), uuid4().hex)
                                          for i in range(2)), return_exceptions=True)
        results = asyncio.run(run())
        self.assertEqual(sum(type(r) is dict for r in results), 1)
        self.assertEqual([r[4] for r in self.claims()].count('issued'), 1)

    def test_no_sql_transaction_held_during_provider_verification(self):
        def handler(request):
            with sqlite3.connect(self.usage_path, timeout=0.01) as db:
                db.execute('BEGIN IMMEDIATE')
            return httpx.Response(200, json=self.success())
        self.handler = handler
        self.issue()

    def test_either_emergency_control_blocks_before_provider(self):
        self.ledger.set_disabled(True)
        self.assert_no_new_session(lambda: self.issue())
        self.ledger.set_disabled(False)
        self.ledger.set_issuance_disabled(True)
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.calls, [])

    def test_emergency_disabled_during_provider_prevents_finalization(self):
        def handler(request):
            self.ledger.set_issuance_disabled(True)
            return httpx.Response(200, json=self.success())
        self.handler = handler
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'failed')

    def test_failed_finalization_leaves_no_session_and_no_replay(self):
        with patch.object(self.ledger, 'finalize_verification', side_effect=UsageDenied()):
            self.assert_no_new_session(lambda: self.issue())
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(len(self.calls), 1)

    def test_failed_terminal_update_keeps_pending_claim_and_logs_only_category(self):
        self.handler = lambda request: httpx.Response(200, json={'success': False})
        with patch.object(self.ledger, 'fail_verification', side_effect=UsageDenied()), patch('src.bot_verification.logger.warning') as log:
            self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'pending')
        self.assertNotIn(self.proof, str(log.call_args_list))
        self.assertNotIn(self.settings.bot_secret, str(log.call_args_list))
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(len(self.calls), 1)

    def test_finalization_failure_after_insert_rolls_back_session_and_issuance(self):
        issue = self.ledger._issue_session
        def fail(*args, **kwargs):
            issue(*args, **kwargs)
            raise UsageDenied()
        before = self.rows()
        with patch.object(self.ledger, '_issue_session', side_effect=fail):
            self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.claims()[0][4], 'failed')

    def test_pending_claim_survives_uncertain_failure_and_recovery_never_refunds(self):
        digest = hashlib.sha256(self.proof.encode()).digest()
        self.ledger.claim_verification(digest, self.request, self.binding)
        with self.assertRaises(UsageDenied): self.ledger.recover_verifications(workers_stopped=True)
        self.ledger.set_disabled(True)
        with self.assertRaises(UsageDenied): self.ledger.recover_verifications()
        self.ledger.recover_verifications(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.calls, [])

    def test_durable_attempt_limits_and_pending_capacity(self):
        self.ledger.claim_verification(b'a' * 32, uuid4().hex, self.binding, minute_limit=1)
        with self.assertRaises(UsageDenied) as caught:
            self.ledger.claim_verification(b'b' * 32, uuid4().hex, self.binding, minute_limit=1)
        self.assertEqual(caught.exception.status, 429)
        with self.assertRaises(UsageDenied):
            self.ledger.claim_verification(b'c' * 32, uuid4().hex, self.binding, concurrent=1)

    def test_multiple_process_duplicate_claim_is_atomic(self):
        code = '''
import sys
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch
from contextlib import ExitStack
with ExitStack() as guards:
 for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','dotenv.load_dotenv'):
  guards.enter_context(patch(target,side_effect=AssertionError('offline')))
 from src.usage import UsageLedger,UsageDenied
 try:
  UsageLedger(Path(sys.argv[1]),busy_ms=2000).claim_verification(b'p'*32,uuid4().hex,b'b'*32)
  print('claimed')
 except UsageDenied as e: print(e.category)
'''
        def child(_):
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path)], capture_output=True,
                                    text=True, timeout=10, env={'PATH': os.defpath})
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(child, range(8)))
        self.assertEqual(results.count('claimed'), 1)
        self.assertEqual(results.count('verification_replay'), 7)

    def test_local_capacity_is_nonblocking_and_released(self):
        self.assertTrue(self.service.capacity.acquire(blocking=False))
        self.assertTrue(self.service.capacity.acquire(blocking=False))
        self.assert_no_new_session(lambda: self.issue())
        self.service.capacity.release()
        self.service.capacity.release()
        self.issue()

    def test_cancellation_consumes_claim_and_releases_local_capacity(self):
        async def run():
            entered = asyncio.Event()
            async def blocked(request):
                entered.set()
                await asyncio.sleep(10)
            self.handler = blocked
            task = asyncio.create_task(self.service.issue(self.settings, self.scope, self.proof, uuid4().hex))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
        before = self.rows()['sessions']
        asyncio.run(run())
        self.assertEqual(self.rows()['sessions'], before)
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.service.capacity.acquire(blocking=False))
        self.service.capacity.release()

    def test_freshness_is_rechecked_under_finalization_lock(self):
        finalize = self.ledger.finalize_verification
        def stale(*args, **kwargs):
            self.now += timedelta(seconds=301)
            return finalize(*args, **kwargs)
        with patch.object(self.ledger, 'finalize_verification', side_effect=stale):
            self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.claims()[0][4], 'failed')

    def test_request_binding_and_repeated_finalization_fail_closed(self):
        digest = hashlib.sha256(self.proof.encode()).digest()
        self.ledger.claim_verification(digest, self.request, self.binding)
        args = (digest, self.request, b'x' * 32, b'y' * 32)
        with self.assertRaises(UsageDenied):
            self.ledger.finalize_verification(*args, verified_until=int(self.now.timestamp()) + 300)
        self.issue('different-proof')
        issued = next(row for row in self.claims() if row[4] == 'issued')
        with self.assertRaises(UsageDenied):
            self.ledger.finalize_verification(issued[0], issued[1], issued[2], b'z' * 32,
                                              verified_until=int(self.now.timestamp()) + 300)


class VerificationMigrationTests(BotFixture):
    def restore_v4(self):
        self.ledger.set_disabled(True)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE verification_claims')
            db.execute('PRAGMA user_version=4')

    def test_migration_preserves_all_records_controls_and_reservations(self):
        self.admit_ip(0)
        self.ledger.reserve()
        self.ledger.issue_session(b'x' * 32)
        self.restore_v4()
        before = self.rows()
        self.ledger.migrate_verification(workers_stopped=True)
        self.assertEqual(self.rows(), before)
        self.assertTrue(self.ledger.status()['disabled'])

    def test_migration_requires_shutdown_confirmation_and_rolls_back(self):
        self.restore_v4()
        with self.assertRaises(UsageDenied): self.ledger.migrate_verification()
        validate = usage._validate_database
        def fail(db, version=None):
            validate(db, version)
            if version == 5: raise UsageDenied()
        before = self.usage_path.read_bytes()
        with patch('src.usage._validate_database', side_effect=fail):
            with self.assertRaises(UsageDenied): self.ledger.migrate_verification(workers_stopped=True)
        self.assertEqual(before, self.usage_path.read_bytes())
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied): self.ledger.migrate_verification(workers_stopped=True)

    def test_version_four_runtime_fails_closed_without_migration(self):
        self.restore_v4()
        self.ledger.set_disabled(False)
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.calls, [])

    def test_missing_index_and_malformed_claims_rejected(self):
        with sqlite3.connect(self.usage_path) as db: db.execute('DROP INDEX verification_recent')
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.calls, [])

    def test_same_columns_without_state_constraint_fail_closed(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE verification_claims')
            db.execute(usage.VERIFICATION_SCHEMA[0].replace(" CHECK(state IN ('pending','failed','issued'))", ''))
            db.execute(usage.VERIFICATION_SCHEMA[1])
        self.assert_no_new_session(lambda: self.issue())
        self.assertEqual(self.calls, [])

    def test_invalid_claim_state_and_same_column_missing_checks_rejected(self):
        self.ledger.claim_verification(b'a' * 32, uuid4().hex, self.binding)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute("UPDATE verification_claims SET state='issued'")
        with self.assertRaises(UsageDenied): self.issue()
        self.assertEqual(self.calls, [])

    def test_migration_sql_failure_rolls_back(self):
        self.restore_v4()
        with patch('src.usage.VERIFICATION_SCHEMA', (usage.VERIFICATION_SCHEMA[0], 'INVALID SQL')):
            with self.assertRaises(UsageDenied): self.ledger.migrate_verification(workers_stopped=True)
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 4)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_schema WHERE name='verification_claims'").fetchone()[0], 0)

    def test_missing_corrupt_and_locked_storage_no_provider_calls(self):
        for content in (None, b'not-sqlite'):
            path = Path(self.temporary) / ('missing' if content is None else 'corrupt')
            if content: path.write_bytes(content)
            with patch('src.usage.UsageLedger.from_settings', return_value=UsageLedger(path)):
                with self.assertRaises(UsageDenied): self.issue()
            self.assertEqual(path.read_bytes() if path.exists() else None, content)
        self.ledger.busy_ms = 20
        with sqlite3.connect(self.usage_path) as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(UsageDenied): self.issue()
        self.assertEqual(self.calls, [])


class VerificationHTTPTests(BotFixture):
    def setUp(self):
        super().setUp()
        self.api = self.load('src.api')
        self.api.app.state.chat_controls.settings = self.settings
        self.api.app.state.verification_service = self.service
        from src.reliability import RateLimiter
        self.api.app.state.chat_controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.headers = {'Authorization': 'Bearer ' + 's' * 43}
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))

    def post(self, **kwargs):
        kwargs.setdefault('headers', self.headers)
        kwargs.setdefault('json', {'proof': self.proof})
        return self.http.post('/internal/verified-sessions', **kwargs)

    def test_disabled_feature_and_missing_wrong_duplicate_bearer(self):
        controls = self.api.app.state.chat_controls
        controls.settings = replace(self.settings, bot_verification_enabled=False)
        self.assertEqual(self.post().status_code, 404)
        controls.settings = self.settings
        for headers in ({}, {'Authorization': 'Bearer ' + 'w' * 43},
                        [('Authorization', self.headers['Authorization']), ('Authorization', self.headers['Authorization'])]):
            self.assertEqual(self.post(headers=headers).status_code, 401)
        self.assertEqual(self.calls, [])

    def test_success_token_cookie_and_logs_are_controlled(self):
        response = self.post()
        self.assertEqual(response.status_code, 201, response.text)
        token = response.json()['token']
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertNotIn('set-cookie', response.headers)
        for marker in (token, self.proof, self.settings.bot_secret):
            self.assertNotIn(marker, str(self.logs.call_args_list) + str(response.headers))
        self.client_factory.assert_not_called()

    def test_origin_method_type_body_limits_and_untrusted_flags(self):
        self.assertEqual(self.http.get('/internal/verified-sessions', headers=self.headers).status_code, 405)
        self.assertEqual(self.post(headers={**self.headers, 'Origin': 'https://portfolio.example.test'}).status_code, 403)
        self.assertEqual(self.http.post('/internal/verified-sessions', content='{}', headers=self.headers).status_code, 415)
        self.assertEqual(self.post(json={'proof': self.proof, 'verified': True}).status_code, 422)
        self.assertEqual(self.post(json={'proof': 'x' * 2049}).status_code, 422)
        self.assertEqual(self.http.post('/internal/verified-sessions', content=b' ' * 4097,
                                       headers={**self.headers, 'Content-Type': 'application/json'}).status_code, 413)
        self.assertEqual(self.calls, [])

    def test_malformed_ambiguous_json_and_trailing_alias_rejected(self):
        for content in ('{"proof":"first","proof":"second"}', '{invalid', '{"proof":NaN}'):
            response = self.http.post('/internal/verified-sessions', content=content,
                                      headers={**self.headers, 'Content-Type': 'application/json'})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.http.post('/internal/verified-sessions/', json={'proof': self.proof}).status_code, 401)
        self.assertEqual(self.calls, [])

    def test_cors_preflight_and_origin_requests_receive_no_cors_permission(self):
        headers = {'Origin': 'http://localhost:3000', 'Access-Control-Request-Method': 'POST'}
        response = self.http.options('/internal/verified-sessions', headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('access-control-allow-origin', response.headers)
        response = self.post(headers={**self.headers, 'Origin': 'http://localhost:3000'})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('access-control-allow-origin', response.headers)
        self.assertEqual(self.calls, [])

    def test_errors_do_not_echo_proof_or_provider_content(self):
        self.handler = lambda request: httpx.Response(200, json={'success': False, 'private': self.settings.bot_secret})
        response = self.post()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {'detail': 'Verification unavailable.'})
        self.assertNotIn(self.proof, response.text + str(self.logs.call_args_list))
        self.assertNotIn(self.settings.bot_secret, response.text + str(self.logs.call_args_list))

    def test_health_and_readiness_still_public_without_verification(self):
        self.assertEqual(self.http.get('/health').status_code, 200)
        self.assertEqual(self.http.get('/ready').status_code, 200)
        self.assertEqual(self.calls, [])


class VerificationConfigurationTests(OfflineTestCase):
    def test_default_missing_configuration_is_disabled(self):
        with patch.dict(os.environ, {}, clear=True): self.assertFalse(Settings.from_env().bot_verification_enabled)

    def test_enabled_without_required_configuration_fails_closed(self):
        with patch.dict(os.environ, {'BOT_VERIFICATION_ENABLED': 'true'}):
            with self.assertRaises(ValueError): Settings.from_env()

    def test_invalid_configuration_does_not_echo_values(self):
        for name, value in (('BOT_VERIFICATION_ENABLED', 'PRIVATE'), ('BOT_TIMEOUT_SECONDS', 'nan'),
                            ('BOT_MAX_AGE_SECONDS', '301'), ('BOT_MAX_CONCURRENT', '0')):
            with patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError) as caught: Settings.from_env()
                self.assertNotIn(value, str(caught.exception))

    def test_enabled_policy_requires_secret_hostnames_and_expected_action(self):
        valid = {'BOT_VERIFICATION_ENABLED': 'true', 'STAGING_AUTH_ENABLED': 'true', 'STAGING_AUTH_TOKEN': 's' * 43,
                 'SESSION_ISSUANCE_ENABLED': 'true', 'BOT_PROVIDER_SECRET': 'fake-offline-secret',
                 'BOT_ALLOWED_HOSTNAMES': 'portfolio.example.test', 'BOT_EXPECTED_ACTION': 'portfolio_session'}
        with patch.dict(os.environ, valid):
            self.assertTrue(Settings.from_env().bot_verification_enabled)
            for key, value in (('BOT_PROVIDER_SECRET', ''), ('BOT_ALLOWED_HOSTNAMES', '*'),
                               ('BOT_ALLOWED_HOSTNAMES', 'https://portfolio.example.test'),
                               ('BOT_EXPECTED_ACTION', ''), ('BOT_ALLOWED_HOSTNAMES', 'bad-.test')):
                with patch.dict(os.environ, {key: value}):
                    with self.assertRaises(ValueError): Settings.from_env()
