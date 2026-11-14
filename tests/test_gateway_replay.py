"""Consume-once security tests: synthetic keys, offline guards, temporary SQLite."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from unittest.mock import Mock, patch
from uuid import uuid4

from src import usage
from src.gateway_assertions import (GatewayAssertionVerifier, VerificationKey, VerifiedGatewayAssertion,
                                    AssertionError as InvalidAssertion)
from src.gateway_replay import GatewayReplayService
from src.usage import UsageDenied, UsageLedger
from tests.offline import OfflineTestCase

FIXTURE = json.loads((Path(__file__).parent / 'fixtures/gateway_assertions_v1.json').read_text())
NOW = FIXTURE['now']
BODY = base64.b64decode(FIXTURE['vectors'][0]['body_base64'])
SESSION = FIXTURE['session_token']
PUBLIC_KEY = bytes.fromhex(FIXTURE['policy']['currentKey']['secret_hex'])


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


_VERIFIERS = {}


def configured_verifier(issuer='portfolio-gateway', audience='portfolio-backend', kid='gateway-key-1', secret=PUBLIC_KEY):
    scope = (issuer, audience, kid, secret)
    if scope not in _VERIFIERS:
        _VERIFIERS[scope] = GatewayAssertionVerifier(issuer=issuer, audience=audience, ip_source='offline-ingress-v1',
            current_key=VerificationKey(kid, secret, NOW - 100, NOW + 1000000))
    return _VERIFIERS[scope]


def assertion(*, issuer='portfolio-gateway', audience='portfolio-backend', kid='gateway-key-1',
              secret=PUBLIC_KEY, nonce=None, now=NOW, visitor='192.0.2.42', body=BODY):
    header = {'typ': 'portfolio-gateway-assertion-v1', 'alg': 'HS256', 'kid': kid}
    payload = {**FIXTURE['vectors'][0]['payload'], 'iss': issuer, 'aud': audience,
               'iat': now, 'exp': now + 30, 'visitor_ip': visitor,
               'body_sha256': hashlib.sha256(body).hexdigest()}
    if nonce is not None:
        payload['jti'] = nonce
    wire = '.'.join(encode(json.dumps(v, separators=(',', ':')).encode()) for v in (header, payload))
    wire += '.' + encode(hmac.digest(secret, wire.encode(), 'sha256'))
    verifier = configured_verifier(issuer, audience, kid, secret)
    return verifier.verify(wire, session_token=SESSION, body=body, now=now), wire


# Fresh interpreters must verify original wire data. Objects/seals are NOT sent
# across processes. Network and dotenv access are blocked before any app import.
CHILD = r'''
import json,sys,socket
from datetime import datetime,timezone
from pathlib import Path
from unittest.mock import patch
for target in ('socket.socket.connect','socket.socket.connect_ex','socket.create_connection','socket.getaddrinfo','dotenv.load_dotenv'):
 patch(target,side_effect=RuntimeError('Offline subprocess')).start()
from src.gateway_assertions import GatewayAssertionVerifier,VerificationKey
from src.gateway_replay import GatewayReplayService
from src.usage import UsageLedger,UsageDenied
f=json.loads(Path('tests/fixtures/gateway_assertions_v1.json').read_text())
k=f['policy']['currentKey']
ledger=UsageLedger(Path(sys.argv[1]),clock=lambda:datetime.fromtimestamp(f['now'],timezone.utc),busy_ms=2000)
if sys.argv[2]=='migrate':
 ledger.migrate_gateway_replay(workers_stopped=True)
 print('MIGRATED')
else:
 v=GatewayAssertionVerifier(issuer=f['policy']['issuer'],audience=f['policy']['audience'],ip_source=f['policy']['ipSource'],
  current_key=VerificationKey(k['kid'],bytes.fromhex(k['secret_hex']),k['notBefore'],k['notAfter']))
 import base64
 a=v.verify(f['vectors'][0]['assertion'],session_token=f['session_token'],body=base64.b64decode(f['vectors'][0]['body_base64']),now=f['now'])
 if len(sys.argv)>3:
  Path(sys.argv[3]).write_text('ready')
  import time
  while not Path(sys.argv[4]).exists(): time.sleep(.005)
 try:
  GatewayReplayService(ledger,v).claim(a)
  print('ACCEPT')
 except UsageDenied:
  print('REJECT')
'''


class ReplayFixture(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.now = NOW
        self.ledger = UsageLedger(self.usage_path, busy_ms=100,
                                 clock=lambda: datetime.fromtimestamp(self.now, timezone.utc))
        self.ledger.set_disabled(True)
        self.ledger.migrate(workers_stopped=True)
        self.ledger.migrate_issuance(workers_stopped=True)
        self.ledger.migrate_identity(hashlib.sha256(b'offline-ip-key').digest(), workers_stopped=True)
        self.ledger.migrate_verification(workers_stopped=True)
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.service = GatewayReplayService(self.ledger, configured_verifier())
        self.verified, self.wire = assertion()

    def rows(self):
        with sqlite3.connect(self.usage_path) as db:
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")]
            return {name: db.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall() for name in tables}

    def count(self):
        return len(self.rows()['gateway_replay_claims'])

    def reject(self, value=None, service=None):
        provider = Mock()
        with self.assertRaises(UsageDenied) as error:
            (service or self.service).claim(self.verified if value is None else value)
            provider()
        provider.assert_not_called()
        self.assertEqual(str(error.exception), 'Paid operation unavailable.')
        return error.exception

    def child(self, action='claim'):
        return subprocess.run([sys.executable, '-B', '-c', CHILD, str(self.usage_path), action],
                              text=True, capture_output=True, timeout=15, check=True).stdout.strip()


class GatewayReplayTests(ReplayFixture):
    def test_first_claim_then_duplicate_rejected(self):
        self.service.claim(self.verified)
        before = self.rows()
        self.assertEqual(self.reject().category, 'assertion_replay')
        self.assertEqual(self.count(), 1)
        self.assertEqual(before, self.rows())

    def test_concurrent_duplicates_separate_connections_exactly_one_winner(self):
        barrier = threading.Barrier(12)
        def attempt(_):
            ledger = UsageLedger(self.usage_path, busy_ms=2000, clock=self.ledger.clock)
            barrier.wait()
            try:
                GatewayReplayService(ledger, configured_verifier()).claim(self.verified)
                return True
            except UsageDenied:
                return False
        with ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(sum(pool.map(attempt, range(12))), 1)
        self.assertEqual(self.count(), 1)

    def test_separate_process_race_exactly_one_winner_and_restart_rejects(self):
        gate = Path(self.temporary) / 'gate'
        children = []
        try:
            for n in range(5):
                ready = Path(self.temporary) / f'ready-{n}'
                children.append(subprocess.Popen([sys.executable, '-B', '-c', CHILD, str(self.usage_path),
                    'claim', str(ready), str(gate)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            deadline = time.monotonic() + 12
            while not all((Path(self.temporary) / f'ready-{n}').exists() for n in range(5)):
                self.assertLess(time.monotonic(), deadline, 'Fresh processes failed to reach barrier')
                time.sleep(.01)
            gate.write_text('go')
            results = []
            for child in children:
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr)
                results.append(stdout.strip())
            self.assertEqual(results.count('ACCEPT'), 1)
            self.assertEqual(results.count('REJECT'), 4)
            self.assertEqual(self.child(), 'REJECT')
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)
        self.assertEqual(self.count(), 1)

    def test_failure_cancellation_and_lost_response_do_not_refund(self):
        for number, failure in enumerate((RuntimeError, asyncio.CancelledError, ConnectionError)):
            value, _ = assertion(nonce=encode(hashlib.sha256(str(number).encode()).digest()))
            try:
                self.service.claim(value)
                raise failure('synthetic downstream failure')
            except (RuntimeError, asyncio.CancelledError, ConnectionError):
                pass
            self.reject(value)
        self.assertEqual(self.count(), 3)

    def test_plain_fields_constructed_objects_and_subclasses_fail_closed(self):
        for value in (self.wire, self.verified.__class__, {}, object(), 'header',
                      object.__new__(VerifiedGatewayAssertion)):
            self.reject(value)
        with self.assertRaises(TypeError):
            VerifiedGatewayAssertion(**{'issuer': 'attacker'})
        self.assertEqual(self.count(), 0)

    def test_attestation_rejects_mutation_even_when_seal_is_copied(self):
        for field, value in (('issuer', 'attacker'), ('key_id', 'other-key'), ('nonce', encode(b'Q'*31+b'R')),
                             ('expires_at', NOW+60), ('visitor_ip', '192.0.2.99'),
                             ('body_sha256', '0'*64), ('_attestation', b'X'*32),
                             ('replay_protection_required', False), ('_key_not_after', NOW+999999)):
            altered = copy.copy(self.verified)
            object.__setattr__(altered, field, value)
            self.reject(altered)
        self.assertEqual(self.count(), 0)

    def test_only_pinned_verifier_can_supply_results(self):
        for kwargs in ({'issuer': 'caller-selected'}, {'audience': 'caller-selected'},
                       {'secret': b'foreign configuration secret key!!'}):
            value, _ = assertion(**kwargs)
            self.reject(value)
        same_config = GatewayAssertionVerifier(issuer='portfolio-gateway', audience='portfolio-backend',
            ip_source='offline-ingress-v1', current_key=VerificationKey('gateway-key-1', PUBLIC_KEY, NOW-100, NOW+1000000))
        foreign_result = same_config.verify(self.wire, session_token=SESSION, body=BODY, now=NOW)
        self.reject(foreign_result)
        altered = copy.copy(foreign_result)
        object.__setattr__(altered, '_verifier_context', configured_verifier()._context)
        self.reject(altered)  # copying the context cannot forge its MAC
        self.assertEqual(self.count(), 0)

    def test_missing_verifier_and_arbitrary_context_rejected(self):
        for value in (None, {}, 'caller-identity', object()):
            with self.assertRaises(UsageDenied):
                GatewayReplayService(self.ledger, value)
        with self.assertRaises(TypeError):
            self.service.claim(self.verified, identity='192.0.2.42')
        self.assertEqual(self.count(), 0)

    def test_key_secret_rotation_with_same_kid_cannot_reset_nonce(self):
        self.service.claim(self.verified)
        value, _ = assertion(secret=b'R'*32)
        rotated = GatewayReplayService(self.ledger, configured_verifier(secret=b'R'*32))
        self.reject(value, service=rotated)
        self.assertEqual(self.count(), 1)

    def test_real_async_cancellation_after_claim_keeps_claim(self):
        async def scenario():
            claimed = asyncio.Event()
            async def downstream():
                self.service.claim(self.verified)
                claimed.set()
                await asyncio.Event().wait()
            task = asyncio.create_task(downstream())
            await claimed.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        asyncio.run(scenario())
        self.reject()
        self.assertEqual(self.count(), 1)

    def test_copy_of_valid_result_still_cannot_replay(self):
        self.service.claim(copy.copy(self.verified))
        self.reject(self.verified)

    def test_expiration_exact_boundary_and_future_skew_rechecked(self):
        self.now = NOW + 30
        self.reject()
        self.assertEqual(self.count(), 0)
        self.now = NOW
        future, _ = assertion(now=NOW + 6)
        self.reject(future)
        within_skew, _ = assertion(now=NOW + 5)
        self.service.claim(within_skew)
        self.assertEqual(self.count(), 1)
        self.assertEqual(self.rows()['gateway_replay_claims'][0][1] - NOW, 35)

    def test_invalid_crypto_or_nonce_never_produces_eligible_result(self):
        for nonce in ('x', encode(b'\0'*32), encode(b'X'*32)):
            with self.assertRaises(InvalidAssertion):
                assertion(nonce=nonce)
        self.reject(self.wire[:-1] + 'X')
        self.assertEqual(self.count(), 0)

    def test_same_nonce_resigned_different_body_address_or_expiry_still_rejected(self):
        self.service.claim(self.verified)
        for kwargs in ({'body': b'{"message":"different"}'}, {'visitor': '192.0.2.77'}, {'now': NOW+1}):
            value, wire = assertion(**kwargs)
            self.assertNotEqual(wire, self.wire)
            self.reject(value)
        self.now = NOW + 86400
        value, _ = assertion(now=self.now)
        self.reject(value)  # permanent tombstone, even after old assertion expired
        self.assertEqual(self.count(), 1)

    def test_different_json_encoding_same_nonce_cannot_bypass_claim(self):
        self.service.claim(self.verified)
        vector = FIXTURE['vectors'][0]
        message = encode(json.dumps(vector['header'], indent=2).encode()) + '.' + encode(
            json.dumps(dict(reversed(list(vector['payload'].items()))), indent=1).encode())
        wire = message + '.' + encode(hmac.digest(PUBLIC_KEY, message.encode(), 'sha256'))
        self.assertNotEqual(wire, self.wire)
        result = configured_verifier().verify(wire, session_token=SESSION, body=BODY, now=NOW)
        self.reject(result)
        self.assertEqual(self.count(), 1)

    def test_distinct_issuer_audience_or_key_scope_has_distinct_identifier(self):
        self.service.claim(self.verified)
        for kwargs in ({'issuer': 'another-gateway'}, {'audience': 'another-backend'},
                       {'kid': 'next-key', 'secret': b'P' * 32}):
            value, _ = assertion(**kwargs)
            scoped_service = GatewayReplayService(self.ledger, configured_verifier(**kwargs))
            scoped_service.claim(value)
            self.reject(value, service=scoped_service)
        self.assertEqual(self.count(), 4)

    def test_clock_rollback_rejected_and_restart_does_not_reset_watermark(self):
        self.now = NOW + 10
        value, _ = assertion(now=self.now)
        self.service.claim(value)
        self.now = NOW + 9
        fresh, _ = assertion(now=self.now, nonce=encode(hashlib.sha256(b'fresh').digest()))
        self.reject(fresh)
        self.assertEqual(self.child(), 'REJECT')  # child's clock is below persisted floor
        self.assertEqual(self.count(), 1)

    def test_expiration_after_waiting_for_transaction_denied(self):
        original = self.ledger._transaction
        @contextmanager
        def delayed(*args, **kwargs):
            with original(*args, **kwargs) as db:
                self.now = NOW + 30
                yield db
        with patch.object(self.ledger, '_transaction', delayed):
            self.reject()
        self.assertEqual(self.count(), 0)

    def test_expiration_during_transaction_rolls_back(self):
        with patch.object(self.ledger, '_now', side_effect=[NOW, NOW, NOW + 30]):
            self.reject()
        self.assertEqual(self.count(), 0)

    def test_expiration_during_commit_rejects_execution_without_refund(self):
        with patch.object(self.ledger, '_now', side_effect=[NOW, NOW, NOW, NOW + 30]):
            self.reject()
        self.assertEqual(self.count(), 1)
        self.reject()  # ordinary time cannot resurrect an already consumed nonce

    def test_transaction_failure_rolls_back_and_never_authorizes_execution(self):
        original = self.ledger._transaction
        @contextmanager
        def fail_commit(*args, **kwargs):
            with original(*args, **kwargs) as db:
                yield db
                raise sqlite3.OperationalError('PRIVATE STORAGE ERROR')
        with patch.object(self.ledger, '_transaction', fail_commit):
            self.reject()
        self.assertEqual(self.count(), 0)

    def test_post_commit_storage_failure_sanitized_and_not_refunded(self):
        original = self.ledger._transaction
        @contextmanager
        def fail_close(*args, **kwargs):
            with original(*args, **kwargs) as db:
                yield db
            raise OSError('PRIVATE CLOSE FAILURE')
        with patch.object(self.ledger, '_transaction', fail_close):
            self.reject()
        self.assertEqual(self.count(), 1)
        self.reject()

    def test_clock_rollback_within_transaction_denied_without_claim(self):
        with patch.object(self.ledger, '_now', side_effect=[NOW, NOW+1, NOW]):
            self.reject()
        self.assertEqual(self.count(), 0)

    def test_emergency_disable_does_not_delete_replay_claims(self):
        self.service.claim(self.verified)
        self.ledger.set_disabled(True)
        new, _ = assertion(nonce=encode(hashlib.sha256(b'emergency').digest()))
        self.reject(new)
        self.ledger.set_disabled(False)
        self.reject(self.verified)
        self.assertEqual(self.count(), 1)

    def test_read_only_missing_corrupt_or_unavailable_storage(self):
        self.usage_path.chmod(0o400)
        self.reject()
        self.usage_path.chmod(0o600)
        missing = Path(self.temporary) / 'missing-parent' / 'usage.sqlite3'
        self.reject(service=GatewayReplayService(UsageLedger(missing, clock=self.ledger.clock), configured_verifier()))
        self.assertFalse(missing.exists())
        self.usage_path.write_bytes(b'CORRUPT SQLITE')
        self.reject()
        self.assertEqual(self.usage_path.read_bytes(), b'CORRUPT SQLITE')

    def test_bounded_busy_wait_locked_database_fails_closed(self):
        with sqlite3.connect(self.usage_path, isolation_level=None) as db:
            db.execute('BEGIN IMMEDIATE')
            started = time.monotonic()
            self.reject()
            self.assertLess(time.monotonic() - started, 1)
            db.execute('ROLLBACK')
        self.assertEqual(self.count(), 0)

    def test_schema_missing_or_mismatched_rejected_without_repair(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE gateway_replay_claims')
        self.reject()
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 6)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_schema WHERE name='gateway_replay_claims'").fetchone()[0], 0)

    def test_wrong_version_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=99')
        self.reject()

    def test_cleanup_and_reservation_recovery_never_delete_claims(self):
        self.service.claim(self.verified)
        self.ledger.create_session(hashlib.sha256(b'cleanup session').digest(), NOW+1)
        self.now = NOW + 86400*2
        self.ledger.set_disabled(True)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0), 1)
        self.ledger.recover(workers_stopped=True)
        self.ledger.recover_verifications(workers_stopped=True)
        self.assertEqual(self.count(), 1)
        self.ledger.set_disabled(False)
        value, _ = assertion(now=self.now)
        self.reject(value)

    def test_no_sensitive_data_in_storage_logs_or_errors(self):
        with patch('logging.Logger._log') as log:
            self.service.claim(self.verified)
            self.reject()
        log.assert_not_called()
        with sqlite3.connect(self.usage_path) as db:
            dump = '\n'.join(db.iterdump())
        for value in (SESSION, BODY.decode(), self.verified.visitor_ip, self.verified.nonce,
                      PUBLIC_KEY.hex(), self.wire, self.verified.session_sha256, self.verified.body_sha256):
            self.assertNotIn(value, dump)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_replay_identifier_independent_calculation_and_scope_separation(self):
        self.service.claim(self.verified)
        data = json.dumps(['portfolio-gateway-assertion-v1', self.verified.issuer, self.verified.audience,
                           self.verified.key_id, self.verified.nonce], separators=(',', ':')).encode('ascii')
        digest = hashlib.sha256(b'portfolio-gateway-replay-id-v1\0' + data).digest()
        self.assertEqual(self.rows()['gateway_replay_claims'][0][0], digest)

    def test_provider_guard_not_granted_by_claim(self):
        self.service.claim(self.verified)
        self.ledger.set_disabled(True)
        from src.usage import paid_call
        provider = Mock()
        with self.assertRaises(UsageDenied):
            paid_call('generation', provider)
        provider.assert_not_called()

    def test_validation_budget_exhaustion_fails_closed(self):
        with patch.object(usage, 'VALIDATION_MAX_STEPS', 1), patch.object(usage, 'SQL_PROGRESS_INTERVAL', 1):
            self.reject()
        self.assertEqual(self.count(), 0)


class GatewayReplayMigrationTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.ledger = UsageLedger(self.usage_path, clock=lambda: datetime.fromtimestamp(NOW, timezone.utc))
        self.ledger.set_disabled(True)
        self.ledger.migrate(workers_stopped=True)
        self.ledger.migrate_issuance(workers_stopped=True)
        self.tag = hashlib.sha256(b'offline-ip-key').digest()
        self.ledger.migrate_identity(self.tag, workers_stopped=True)
        self.ledger.migrate_verification(workers_stopped=True)

    def snapshot(self):
        with sqlite3.connect(self.usage_path) as db:
            return (db.execute('PRAGMA user_version').fetchone()[0],
                    db.execute('SELECT * FROM sqlite_schema ORDER BY name').fetchall(),
                    {table: db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()
                     for table, in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")})

    def populate(self):
        self.ledger.set_disabled(False)
        self.ledger.set_issuance_disabled(False)
        self.digest = hashlib.sha256(b'old verified session').digest()
        self.session = self.ledger.create_session(self.digest, NOW+14400, verified=True)
        self.ledger.issue_session(hashlib.sha256(b'old issuance').digest())
        self.identity = hashlib.sha256(b'synthetic identity').digest()
        self.reservation = self.ledger.reserve_session(self.digest, identity_digest=self.identity, identity_key_tag=self.tag)
        self.ledger.operation(self.reservation, 'embedding')
        self.ledger.operation(self.reservation, 'generation')
        for number in range(3):
            proof = hashlib.sha256(f'proof-{number}'.encode()).digest()
            request, binding = uuid4().hex, hashlib.sha256(f'binding-{number}'.encode()).digest()
            self.ledger.claim_verification(proof, request, binding)
            if number == 0:
                self.ledger.fail_verification(proof, request, binding)
            elif number == 2:
                self.ledger.finalize_verification(proof, request, binding, hashlib.sha256(b'issued').digest(),
                                                  verified_until=NOW+30)
        self.ledger.set_disabled(True)

    def test_actual_v5_migration_preserves_all_accounting_and_shutdown_states(self):
        self.populate()
        before = self.snapshot()
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        version, schema, rows = self.snapshot()
        self.assertEqual(before[0], 5)
        self.assertEqual(version, 6)
        self.assertEqual({name: rows[name] for name in before[2]}, before[2])
        self.assertEqual([row for row in schema if row[1] in {r[1] for r in before[1]}], before[1])
        self.assertEqual(rows['gateway_replay_control'], [(1, NOW)])
        self.assertEqual(rows['gateway_replay_claims'], [])
        self.assertTrue(self.ledger.status()['disabled'])
        self.assertEqual(self.ledger.status()['active'], 1)
        self.assertEqual({row[4] for row in rows['verification_claims']}, {'issued', 'pending', 'failed'})
        with self.ledger._transaction(version=6):
            pass  # full strict metadata and data-invariant validation

    def test_v6_session_ip_global_and_provider_controls_preserved(self):
        self.populate()
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied) as error:
            self.ledger.reserve_session(self.digest, minute_limit=1)
        self.assertEqual(error.exception.category, 'usage_session_budget')
        other = hashlib.sha256(b'other verified').digest()
        self.ledger.create_session(other, NOW+14400, verified=True)
        with self.assertRaises(UsageDenied) as error:
            self.ledger.reserve_session(other, identity_digest=self.identity, identity_key_tag=self.tag, identity_minute_limit=1)
        self.assertEqual(error.exception.category, 'usage_identity_budget')
        self.ledger.daily = 1
        with self.assertRaises(UsageDenied) as error:
            self.ledger.reserve()
        self.assertEqual(error.exception.category, 'usage_budget')
        self.ledger.daily = 100
        self.ledger.monthly = 1
        with self.assertRaises(UsageDenied) as error:
            self.ledger.reserve()
        self.assertEqual(error.exception.category, 'usage_budget')
        self.ledger.monthly = 1000
        self.ledger.concurrent = 1
        with self.assertRaises(UsageDenied) as error:
            self.ledger.reserve()
        self.assertEqual(error.exception.category, 'usage_capacity')
        for kind in ('embedding', 'generation'):
            with self.assertRaises(UsageDenied):
                self.ledger.operation(self.reservation, kind)  # prior attempts not reset
        self.ledger.release(self.reservation)
        self.ledger.concurrent = 2
        self.ledger.reserve_session(other)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 2)
        self.assertEqual(self.ledger.lookup_session(other)['verified'], 1)

    def test_verified_issuance_remains_functional_on_v6_without_paid_counter_changes(self):
        self.populate()
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.ledger.set_disabled(False)
        before = self.ledger.status()
        proof, binding = hashlib.sha256(b'v6 proof').digest(), hashlib.sha256(b'v6 binding').digest()
        request = uuid4().hex
        digest = hashlib.sha256(b'v6 verified session').digest()
        self.ledger.claim_verification(proof, request, binding)
        self.ledger.finalize_verification(proof, request, binding, digest, verified_until=NOW+30)
        self.assertEqual(self.ledger.lookup_session(digest)['verified'], 1)
        self.assertEqual(self.ledger.status(), before)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_sql_failure_rolls_back_schema_version_and_rows(self):
        self.populate()
        before = self.snapshot()
        with patch.object(usage, 'GATEWAY_REPLAY_SCHEMA', (*usage.GATEWAY_REPLAY_SCHEMA, 'INVALID SQL')):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.assertEqual(self.snapshot(), before)

    def test_final_validation_failure_rolls_back_everything(self):
        before = self.snapshot()
        validate = usage._validate_database
        def fail(db, version=None):
            validate(db, version)
            if version == 6:
                raise UsageDenied()
        with patch.object(usage, '_validate_database', fail):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.assertEqual(self.snapshot(), before)

    def test_migration_requires_disabled_paid_state_and_worker_confirmation(self):
        before = self.snapshot()
        for confirm in (False, None, 'true', 1):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate_gateway_replay(workers_stopped=confirm)
        self.assertEqual(self.snapshot(), before)
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied):
            self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.assertEqual(self.snapshot()[0], 5)

    def test_repeat_migration_fails_without_mutation(self):
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        before = self.snapshot()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.assertEqual(before, self.snapshot())

    def test_malformed_prior_schema_refuses_migration(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP INDEX verification_recent')
        before = self.snapshot()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.assertEqual(before, self.snapshot())

    def test_fresh_process_explicit_migration_and_restart(self):
        before = self.snapshot()[2]
        result = subprocess.run([sys.executable, '-B', '-c', CHILD, str(self.usage_path), 'migrate'],
                                text=True, capture_output=True, timeout=10, check=True)
        self.assertEqual(result.stdout.strip(), 'MIGRATED')
        self.assertEqual(self.snapshot()[0], 6)
        self.assertEqual({k:v for k,v in self.snapshot()[2].items() if k in before}, before)
        self.ledger.set_disabled(False)
        self.assertEqual(self.child_claim(), 'ACCEPT')
        self.assertEqual(self.child_claim(), 'REJECT')

    def child_claim(self):
        return subprocess.run([sys.executable, '-B', '-c', CHILD, str(self.usage_path), 'claim'],
                              text=True, capture_output=True, timeout=10, check=True).stdout.strip()

    def test_operator_cli_migration_without_provider_or_environment_files(self):
        from src.usage_admin import main
        before = self.snapshot()
        with patch('sys.stdout'):
            self.assertEqual(main(['--database', str(self.usage_path), 'migrate-v6']), 1)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(main(['--database', str(self.usage_path), 'migrate-v6', '--confirm-workers-stopped']), 0)
        self.assertEqual(self.snapshot()[0], 6)
        self.dotenv.assert_not_called()
        self.client_factory.assert_not_called()

    def test_runtime_and_application_startup_never_migrate(self):
        self.ledger.status()
        self.assertEqual(self.snapshot()[0], 5)
        value, _ = assertion()
        with self.assertRaises(UsageDenied):
            GatewayReplayService(self.ledger, configured_verifier()).claim(value)
        self.assertEqual(self.snapshot()[0], 5)
        from fastapi.testclient import TestClient
        api = self.load('src.api')
        with TestClient(api.app) as client:
            self.assertEqual(client.get('/ready').status_code, 200)
            self.assertEqual(client.post('/internal/session-chat', json={'message':'synthetic'}).status_code, 404)
        self.assertEqual(self.snapshot()[0], 5)
        self.assertFalse(any('migrate' in route.path for route in api.app.routes))


class GatewayReplaySchemaTests(ReplayFixture):
    def test_missing_required_primary_key_and_constraints_fail_closed(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE gateway_replay_claims')
            db.execute('CREATE TABLE gateway_replay_claims(replay_digest BLOB NOT NULL, expires_at INTEGER NOT NULL, '
                       'claimed_at INTEGER NOT NULL, protocol TEXT NOT NULL)')
        self.reject()

    def test_invalid_persisted_claim_and_clock_state_fail_closed(self):
        self.service.claim(self.verified)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('UPDATE gateway_replay_control SET high_water=-1')
        self.reject()

    def test_watermark_cannot_be_lower_than_existing_claim(self):
        self.service.claim(self.verified)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE gateway_replay_control SET high_water=?', (NOW-1,))
        self.reject()

    def test_missing_singleton_clock_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DELETE FROM gateway_replay_control')
        self.reject()
