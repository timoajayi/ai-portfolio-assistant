"""Atomic admission probes use temporary version 3 ledgers and fake providers."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Barrier, Event
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from src.config import Settings
from src.diagnostics import ChatDiagnostics, ChatDeadlineExceeded, current_diagnostics
from src.session_admission import admitted_session
from src.usage import UsageDenied, paid_call
from tests.offline import OfflineTestCase
from tests.test_issuance import IssuanceFixture


class AdmissionFixture(IssuanceFixture):
    def setUp(self):
        super().setUp()
        self.raw = base64.urlsafe_b64encode(b'\x01' * 32).rstrip(b'=').decode()
        self.digest = hashlib.sha256(self.raw.encode()).digest()
        self.session = self.ledger.create_session(self.digest, int(self.now.timestamp()) + 14400, verified=True)
        self.settings = replace(Settings.from_env(), staging_auth_enabled=True, staging_auth_token='s' * 43,
                                session_admission_enabled=True)
        self.scope = {'type': 'http', 'method': 'POST', 'query_string': b'', 'headers': [
            (b'authorization', ('Bearer ' + 's' * 43).encode()), (b'x-portfolio-session', self.raw.encode())]}
        self.stack.enter_context(patch('src.usage.UsageLedger.from_settings', return_value=self.ledger))

    def admit(self):
        with admitted_session(self.settings, self.scope):
            pass

    def events(self):
        return self.ledger.recent_session_usage(self.session, 0)

    def assert_denied(self, scope=None, status=None):
        before = self.snapshot()
        provider = Mock()
        with self.assertRaises(UsageDenied) as caught:
            with admitted_session(self.settings, self.scope if scope is None else scope):
                paid_call('generation', provider)
        if status is not None:
            self.assertEqual(caught.exception.status, status)
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        self.assertNotIn(self.raw, str(caught.exception))
        provider.assert_not_called()
        self.assertEqual(self.snapshot(), before)


class SessionAdmissionSecurityTests(AdmissionFixture):
    def test_feature_disabled_or_auth_disabled_denies_without_accounting(self):
        original = self.settings
        for field in ('session_admission_enabled', 'staging_auth_enabled'):
            self.settings = replace(original, **{field: False})
            self.assert_denied()
        self.settings = original

    def test_missing_wrong_and_duplicate_gateway_credentials(self):
        session = self.scope['headers'][1]
        for headers in ([session], [(b'authorization', b'Bearer ' + b'w' * 43), session],
                        [self.scope['headers'][0], self.scope['headers'][0], session]):
            self.assert_denied({**self.scope, 'headers': headers}, 401)

    def test_missing_duplicate_and_ambiguous_session_headers(self):
        authorization, session = self.scope['headers']
        for headers in ([authorization], [authorization, session, session],
                        [authorization, (b'x-portfolio-session', self.raw.encode() + b',other')]):
            self.assert_denied({**self.scope, 'headers': headers}, 401)

    def test_malformed_and_noncanonical_tokens(self):
        for raw in (b'', b'x' * 42, b'x' * 44, b' ' + self.raw.encode(), b'x' * 43, b'\xff' * 43):
            self.assert_denied({**self.scope, 'headers': [self.scope['headers'][0], (b'x-portfolio-session', raw)]}, 401)

    def test_unknown_session_is_rejected(self):
        unknown = base64.urlsafe_b64encode(b'\x02' * 32).rstrip(b'=')
        self.assert_denied({**self.scope, 'headers': [self.scope['headers'][0], (b'x-portfolio-session', unknown)]}, 401)

    def test_expired_session_is_rejected_at_absolute_expiry(self):
        self.now += timedelta(hours=4)
        self.assert_denied(status=401)

    def test_revoked_session_is_rejected(self):
        self.ledger.revoke_session(self.session)
        self.assert_denied(status=401)

    def test_unverified_session_and_forged_claims_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE sessions SET verified=0')
        scope = {**self.scope, 'headers': [*self.scope['headers'], (b'x-verified', b'true'),
                                          (b'x-expires-at', b'999999999999'), (b'x-session-id', b'chosen')]}
        self.assert_denied(scope, 401)

    def test_browser_origin_query_credentials_and_wrong_method_rejected(self):
        for scope in ({**self.scope, 'method': 'GET'}, {**self.scope, 'query_string': b'token=ignored'},
                      {**self.scope, 'headers': [*self.scope['headers'], (b'origin', b'https://example.com')]}):
            self.assert_denied(scope, 401)

    def test_forwarded_identity_does_not_bypass_session_limit(self):
        for _ in range(3):
            self.admit()
        for peer in (b'1.2.3.4', b'5.6.7.8'):
            self.assert_denied({**self.scope, 'headers': [*self.scope['headers'], (b'x-forwarded-for', peer)]}, 429)

    def test_deleted_session_cannot_admit_or_refund_global_usage(self):
        self.admit()
        self.now += timedelta(hours=5)
        self.ledger.set_disabled(True)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0), 1)
        self.ledger.set_disabled(False)
        self.assert_denied(status=401)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_schema_version_missing_corrupt_and_unwritable_storage_fail_closed(self):
        for content in (None, b'not a database'):
            path = Path(self.temporary) / ('missing.db' if content is None else 'corrupt.db')
            if content:
                path.write_bytes(content)
            from src.usage import UsageLedger
            with patch('src.usage.UsageLedger.from_settings', return_value=UsageLedger(path)):
                provider = Mock()
                with self.assertRaises(UsageDenied):
                    with admitted_session(self.settings, self.scope):
                        paid_call('generation', provider)
                provider.assert_not_called()
            self.assertEqual(path.read_bytes() if path.exists() else None, content)
        self.usage_path.chmod(0o400)
        try:
            with self.assertRaises(UsageDenied):
                self.admit()
        finally:
            self.usage_path.chmod(0o600)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=4')
        with self.assertRaises(UsageDenied):
            self.admit()

    def test_locked_database_fails_closed_without_admission(self):
        self.ledger.busy_ms = 20
        with sqlite3.connect(self.usage_path) as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(UsageDenied):
                self.admit()
        self.assertEqual(self.events(), [])
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_existing_chat_and_routes_unchanged_no_session_endpoint_added(self):
        api = self.load('src.api')
        with TestClient(api.app, headers=self.authorize_legacy_staging(api)) as http:
            self.assertEqual(http.post('/internal/chat', json={'message': 'Docker?'}).status_code, 404)
            response = http.post('/chat', json={'message': 'Show me all projects'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(set(response.json()), {'answer'})
        self.assertEqual(self.events(), [])

    def test_tokens_never_logged_or_echoed_by_existing_http_errors(self):
        api = self.load('src.api')
        controls = api.app.state.chat_controls
        controls.settings = self.settings
        with patch('src.reliability.logger.info') as logs, TestClient(api.app) as http:
            self.admit()
            response = http.post('/chat', json={'message': 'Docker?'},
                                 headers={'Authorization': 'Bearer ' + self.raw,
                                          'X-Portfolio-Session': self.raw})
            self.assertEqual(response.status_code, 401)
            self.assertNotIn(self.raw, response.text + str(logs.call_args_list))
        self.client_factory.assert_not_called()

    def test_invalid_injected_settings_cannot_enable_adapter(self):
        original = self.settings
        for field, value in (('session_admission_enabled', 'false'), ('staging_auth_token', ''),
                             ('staging_auth_token', '\u2603' * 43)):
            self.settings = replace(original, **{field: value})
            self.assert_denied()
        self.settings = original


class SessionAdmissionAccountingTests(AdmissionFixture):
    def test_three_per_minute_fourth_denied_and_exact_boundary(self):
        for _ in range(3):
            self.admit()
        self.assert_denied(status=429)
        self.now += timedelta(seconds=59)
        self.assert_denied(status=429)
        self.now += timedelta(seconds=1)
        self.admit()
        self.assertEqual(len(self.events()), 4)

    def test_twelve_per_hour_thirteenth_denied_and_boundary(self):
        for _ in range(4):
            for _ in range(3):
                self.admit()
            self.now += timedelta(seconds=60)
        self.assert_denied(status=429)
        self.now += timedelta(seconds=3360)
        self.admit()
        self.assertEqual(len(self.events()), 13)

    def test_global_daily_rejection_creates_no_session_event(self):
        self.ledger.daily = 1
        self.admit()
        self.assert_denied(status=429)
        self.assertEqual(len(self.events()), 1)

    def test_global_monthly_rejection_rolls_back_daily_update(self):
        self.ledger.monthly = 1
        self.admit()
        self.assert_denied(status=429)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_global_durable_concurrency_is_preserved(self):
        self.ledger.reserve()
        self.ledger.reserve()
        self.assert_denied(status=503)
        self.assertEqual(self.events(), [])

    def test_global_emergency_disable_and_between_provider_attempts(self):
        self.ledger.set_disabled(True)
        self.assert_denied(status=503)
        self.ledger.set_disabled(False)
        provider = Mock()
        with admitted_session(self.settings, self.scope):
            paid_call('embedding', provider)
            self.ledger.set_disabled(True)
            with self.assertRaises(UsageDenied):
                paid_call('generation', provider)
        provider.assert_called_once()
        self.assertEqual(len(self.events()), 1)

    def test_provider_attempts_counted_no_transaction_during_calls(self):
        def provider():
            # A second writer can acquire the lock while provider work runs.
            with sqlite3.connect(self.usage_path, timeout=0.01) as db:
                db.execute('BEGIN IMMEDIATE')
        with admitted_session(self.settings, self.scope):
            paid_call('embedding', provider)
            paid_call('generation', provider)
        self.assertEqual(self.ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1})

    def test_failed_provider_is_not_refunded(self):
        with self.assertRaises(TimeoutError):
            with admitted_session(self.settings, self.scope):
                paid_call('generation', Mock(side_effect=TimeoutError()))
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)
        self.assertEqual(self.ledger.status()['periods']['day']['generation_ops'], 1)
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_expiration_and_revocation_during_admitted_work_do_not_refund(self):
        provider = Mock()
        with admitted_session(self.settings, self.scope):
            paid_call('embedding', provider)
            self.ledger.revoke_session(self.session)
            self.now += timedelta(hours=5)
            paid_call('generation', provider)
        self.assertEqual(provider.call_count, 2)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)
        self.assert_denied(status=401)

    def test_clock_rollback_cannot_refill_session_window(self):
        self.now += timedelta(seconds=120)
        self.admit()
        self.now -= timedelta(seconds=60)
        self.assert_denied(status=503)  # Still within lifetime, behind latest admission.

    def test_failure_after_global_reservation_rolls_back_both_accountings(self):
        before = self.snapshot()
        reserve = self.ledger._reserve
        def fail(db, day, month):
            reserve(db, day, month)
            raise UsageDenied()
        with patch.object(self.ledger, '_reserve', side_effect=fail):
            self.assert_denied()
        self.assertEqual(before, self.snapshot())

    def test_deadline_prevents_late_provider_attempt_and_keeps_admission(self):
        import time
        diagnostics = ChatDiagnostics(time.monotonic(), 1)
        token = current_diagnostics.set(diagnostics)
        provider = Mock()
        try:
            with admitted_session(self.settings, self.scope):
                diagnostics.stop()
                with self.assertRaises(ChatDeadlineExceeded):
                    paid_call('generation', provider)
            self.assertEqual(len(self.events()), 1)
            provider.assert_not_called()
        finally:
            current_diagnostics.reset(token)

    def test_stopped_deadline_prevents_admission(self):
        import time
        diagnostics = ChatDiagnostics(time.monotonic(), 1)
        diagnostics.stop()
        token = current_diagnostics.set(diagnostics)
        try:
            with self.assertRaises(ChatDeadlineExceeded):
                self.admit()
        finally:
            current_diagnostics.reset(token)
        self.assertEqual(self.events(), [])


class SessionAdmissionConcurrencyTests(AdmissionFixture):
    def test_parallel_final_session_slot(self):
        self.admit()
        self.admit()
        def reserve(_):
            try:
                return self.ledger.reserve_session(self.digest)
            except UsageDenied:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, range(16)))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(len(self.events()), 3)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 3)
        self.assertEqual(self.ledger.status()['active'], 1)

    def test_different_sessions_share_global_final_slot(self):
        self.ledger.daily = 1
        digests = [hashlib.sha256(bytes([i])).digest() for i in range(8)]
        for digest in digests:
            self.ledger.create_session(digest, int(self.now.timestamp()) + 3600, verified=True)
        def reserve(digest):
            try:
                return self.ledger.reserve_session(digest)
            except UsageDenied:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, digests))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_revocation_racing_admission_has_one_serial_outcome(self):
        gate = Barrier(2)
        def revoke():
            gate.wait()
            self.ledger.revoke_session(self.session)
        def reserve():
            gate.wait()
            try:
                return self.ledger.reserve_session(self.digest)
            except UsageDenied:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            revocation = pool.submit(revoke)
            reservation = pool.submit(reserve).result(timeout=3)
            revocation.result(timeout=3)
        expected = int(reservation is not None)
        self.assertEqual(len(self.events()), expected)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], expected)
        self.assert_denied(status=401)

    def test_worker_retains_slot_until_provider_exits(self):
        entered, finish = Event(), Event()
        def provider():
            entered.set()
            self.assertTrue(finish.wait(3))
        def run():
            with admitted_session(self.settings, self.scope):
                paid_call('generation', provider)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(run)
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.ledger.status()['active'], 1)
                self.assertEqual(len(self.events()), 1)
            finally:
                finish.set()
                future.result(timeout=3)
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_fresh_process_restart_and_concurrent_final_slot(self):
        self.admit()
        self.admit()
        code = '''
import sys
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch
from datetime import datetime,timezone
with ExitStack() as guards:
 for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','dotenv.load_dotenv'):
  guards.enter_context(patch(target,side_effect=AssertionError('offline')))
 from src.usage import UsageLedger,UsageDenied
 l=UsageLedger(Path(sys.argv[1]),busy_ms=2000,clock=lambda:datetime(2026,11,9,12,tzinfo=timezone.utc))
 try:
  l.reserve_session(bytes.fromhex(sys.argv[2]))
  print('admitted')
 except UsageDenied as error: print(error.category)
'''
        def child(_):
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path), self.digest.hex()],
                                    capture_output=True, text=True, timeout=10, env={'PATH': os.defpath})
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(child, range(8)))
        self.assertEqual(results.count('admitted'), 1)
        self.assertEqual(results.count('usage_session_budget'), 7)
        self.assertEqual(child(10), 'usage_session_budget')


class SessionAdmissionConfigurationTests(OfflineTestCase):
    def test_missing_config_is_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(Settings.from_env().session_admission_enabled)

    def test_invalid_flag_and_limits_fail_closed(self):
        for name, value in (('SESSION_ADMISSION_ENABLED', 'private-invalid'),
                            ('SESSION_ADMISSION_MINUTE_LIMIT', '0'), ('SESSION_ADMISSION_HOUR_LIMIT', '10001')):
            with patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError) as caught:
                    Settings.from_env()
                self.assertNotIn(value, str(caught.exception))

    def test_enabled_without_gateway_auth_is_invalid(self):
        with patch.dict(os.environ, {'SESSION_ADMISSION_ENABLED': 'true'}):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_provisional_defaults(self):
        settings = Settings.from_env()
        self.assertFalse(settings.session_admission_enabled)
        self.assertEqual((settings.session_admission_minute_limit, settings.session_admission_hour_limit), (3, 12))
