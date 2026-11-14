"""Trusted-identity accounting with synthetic IPs, private temporary databases."""

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
from unittest.mock import Mock, patch

from src import usage
from src.config import Settings
from src.identity import TrustedIP, identity_key, identity_key_tag
from src.ip_admission import admitted_identity
from src.usage import UsageDenied, chat_usage, paid_call
from tests.offline import OfflineTestCase
from tests.test_session_admission import AdmissionFixture


class IPFixture(AdmissionFixture):
    def setUp(self):
        super().setUp()
        self.key_text = base64.urlsafe_b64encode(b'k' * 32).rstrip(b'=').decode()
        self.key = identity_key(self.key_text)
        self.tag = identity_key_tag(self.key)
        self.ledger.set_disabled(True)
        self.ledger.migrate_identity(self.tag, workers_stopped=True)
        self.ledger.set_disabled(False)
        self.settings = replace(self.settings, ip_admission_enabled=True, ip_rate_hmac_key=self.key_text)
        self.identity = TrustedIP('192.0.2.10')
        self.scopes = {}

    def scope_for(self, number):
        if number not in self.scopes:
            raw = base64.urlsafe_b64encode(hashlib.sha256(str(number).encode()).digest()).rstrip(b'=')
            digest = hashlib.sha256(raw).digest()
            self.ledger.create_session(digest, int(self.now.timestamp()) + 172800, verified=True)
            self.scopes[number] = {**self.scope, 'headers': [self.scope['headers'][0], (b'x-portfolio-session', raw)]}
        return self.scopes[number]

    def admit_ip(self, number=0, identity=None):
        with admitted_identity(self.settings, self.scope_for(number), self.identity if identity is None else identity):
            pass

    def rows(self):
        with sqlite3.connect(self.usage_path) as db:
            return {name: db.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall() for name in (
                'control', 'periods', 'active', 'sessions', 'session_events', 'issuance_control',
                'issuance_events', 'ip_control', 'ip_events')}

    def assert_rejected(self, identity, *, settings=None, scope=None, status=None):
        scope = self.scope_for(0) if scope is None else scope
        before = self.rows()
        provider = Mock()
        with self.assertRaises(UsageDenied) as caught:
            with admitted_identity(self.settings if settings is None else settings, scope, identity):
                paid_call('generation', provider)
        if status is not None:
            self.assertEqual(caught.exception.status, status)
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        self.assertNotIn('192.0.2.', str(caught.exception))
        provider.assert_not_called()
        self.assertEqual(before, self.rows())


class IPIdentityTests(OfflineTestCase):
    def test_normalization_and_ipv4_mapped_aliases(self):
        key = b'x' * 32
        self.assertEqual(TrustedIP('192.0.2.10').digest(key), TrustedIP('::ffff:192.0.2.10').digest(key))
        self.assertEqual(TrustedIP('2001:db8::a').digest(key), TrustedIP('2001:0DB8:0:0:0:0:0:a').digest(key))
        self.assertNotEqual(TrustedIP('192.0.2.10').digest(key), TrustedIP('192.0.2.11').digest(key))
        self.assertNotEqual(TrustedIP('192.0.2.10').digest(key), TrustedIP('192.0.2.10').digest(b'y' * 32))

    def test_invalid_ambiguous_or_scoped_addresses_fail_without_echo(self):
        for address in (None, 123, b'192.0.2.10', '192.0.2.10:443', '192.0.2.10/24',
                        '192.000.002.010', 'fe80::1%en0', ' 192.0.2.10', '192.0.2.10,198.51.100.1'):
            with self.assertRaises(ValueError) as caught:
                TrustedIP(address)
            self.assertEqual(str(caught.exception), 'Trusted identity is invalid.')

    def test_identity_repr_does_not_show_address_or_packed_bytes(self):
        identity = TrustedIP('192.0.2.10')
        self.assertEqual(repr(identity), 'TrustedIP()')


class IPAdmissionTests(IPFixture):
    def test_disabled_missing_malformed_identity_and_keys_fail_closed(self):
        with self.assertRaises(UsageDenied):
            with admitted_identity(self.settings, self.scope):
                self.fail('Missing identity must not admit')
        self.assert_rejected(self.identity, settings=replace(self.settings, ip_admission_enabled=False))
        for identity in (None, '192.0.2.10', b'192.0.2.10', {'ip': '192.0.2.10'}):
            self.assert_rejected(identity)
        for key in ('', 'short', 'x' * 43, '\u2603' * 43):
            self.assert_rejected(self.identity, settings=replace(self.settings, ip_rate_hmac_key=key))

    def test_key_rotation_does_not_reset_or_bypass_allowance(self):
        self.admit_ip()
        changed = base64.urlsafe_b64encode(b'z' * 32).rstrip(b'=').decode()
        self.assert_rejected(self.identity, settings=replace(self.settings, ip_rate_hmac_key=changed))

    def test_bearer_and_session_authentication_are_still_mandatory(self):
        scope = self.scope_for(0)
        self.assert_rejected(self.identity, scope={**scope, 'headers': scope['headers'][1:]}, status=401)
        self.assert_rejected(self.identity, scope={**scope, 'headers': scope['headers'][:1]}, status=401)
        self.assert_rejected(self.identity, settings=replace(self.settings, session_admission_enabled=False))

    def test_forwarding_headers_never_establish_identity_or_change_it(self):
        scope = self.scope_for(0)
        for header in (b'x-forwarded-for', b'x-real-ip', b'cf-connecting-ip', b'x-identity'):
            self.assert_rejected(None, scope={**scope, 'headers': [*scope['headers'], (header, b'192.0.2.10')]})

    def test_ten_per_minute_eleventh_denied_and_exact_boundary(self):
        for number in range(10):
            self.admit_ip(number)
        self.assert_rejected(self.identity, scope=self.scope_for(10), status=429)
        self.now += timedelta(seconds=59)
        self.assert_rejected(self.identity, scope=self.scope_for(10), status=429)
        self.now += timedelta(seconds=1)
        self.admit_ip(10)
        self.assertEqual(len(self.rows()['ip_events']), 11)

    def test_sixty_per_rolling_day_not_calendar_day(self):
        start = self.now
        for number in range(60):
            self.now = start + timedelta(seconds=60 * (number // 10))
            self.admit_ip(number)
        self.now = start + timedelta(hours=23, minutes=59)
        self.assert_rejected(self.identity, scope=self.scope_for(60), status=429)
        self.now = start + timedelta(hours=24)
        self.admit_ip(60)
        self.assertEqual(len(self.rows()['ip_events']), 61)

    def test_multiple_sessions_share_one_identity_limit(self):
        self.settings = replace(self.settings, ip_admission_minute_limit=1)
        self.admit_ip(0)
        self.assert_rejected(self.identity, scope=self.scope_for(1), status=429)

    def test_different_identities_have_separate_limits(self):
        self.settings = replace(self.settings, ip_admission_minute_limit=1)
        self.admit_ip(0)
        self.admit_ip(1, TrustedIP('198.51.100.5'))
        self.assertEqual(len(self.rows()['ip_events']), 2)

    def test_session_cleanup_and_deletion_cannot_refund_ip_usage(self):
        self.settings = replace(self.settings, ip_admission_day_limit=1)
        self.admit_ip(0)
        self.now += timedelta(seconds=61)
        # Shorten only this synthetic session's expiry while keeping its event valid.
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE sessions SET expires_at=created_at+1 WHERE id IN (SELECT session_id FROM session_events)')
        self.ledger.set_disabled(True)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0), 1)
        self.ledger.set_disabled(False)
        self.assertEqual(len(self.rows()['session_events']), 0)
        self.assert_rejected(self.identity, scope=self.scope_for(1), status=429)
        self.assertEqual(len(self.rows()['ip_events']), 1)

    def test_session_limits_remain_stricter(self):
        for _ in range(3):
            self.admit_ip()
        self.assert_rejected(self.identity, status=429)
        self.assertEqual(len(self.rows()['ip_events']), 3)

    def test_global_daily_monthly_and_concurrency_rejections_roll_back(self):
        self.ledger.daily = 1
        self.admit_ip(0)
        self.assert_rejected(self.identity, scope=self.scope_for(1), status=429)
        self.ledger.daily = 100
        self.ledger.monthly = 1
        self.assert_rejected(self.identity, scope=self.scope_for(1), status=429)
        self.ledger.monthly = 1000
        self.ledger.reserve()
        self.ledger.reserve()
        self.assert_rejected(self.identity, scope=self.scope_for(1), status=503)

    def test_global_emergency_disable_and_provider_attempts(self):
        self.ledger.set_disabled(True)
        self.assert_rejected(self.identity)
        self.ledger.set_disabled(False)
        provider = Mock()
        with admitted_identity(self.settings, self.scope_for(0), self.identity):
            paid_call('embedding', provider)
            self.ledger.set_disabled(True)
            with self.assertRaises(UsageDenied):
                paid_call('generation', provider)
        provider.assert_called_once()
        self.assertEqual(len(self.rows()['ip_events']), 1)

    def test_provider_failure_never_refunds_ip_session_or_global(self):
        with self.assertRaises(TimeoutError):
            with admitted_identity(self.settings, self.scope_for(0), self.identity):
                paid_call('generation', Mock(side_effect=TimeoutError()))
        rows = self.rows()
        self.assertEqual((len(rows['ip_events']), len(rows['session_events']), len(rows['active'])), (1, 1, 0))
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_clock_rollback_fails_for_different_sessions_and_identities(self):
        self.admit_ip(0)
        scope = self.scope_for(1)
        self.now -= timedelta(seconds=1)
        # Keep the new session otherwise valid for this rollback probe.
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE sessions SET created_at=created_at-10')
        self.assert_rejected(TrustedIP('198.51.100.10'), scope=scope)

    def test_rollback_after_session_global_writes_before_ip_insert(self):
        scope = self.scope_for(0)
        before = self.rows()
        transaction = self.ledger._transaction
        from contextlib import contextmanager
        class Proxy:
            def __init__(self, db): self.db = db
            def execute(self, sql, *args):
                if sql.startswith('INSERT INTO ip_events'):
                    raise sqlite3.OperationalError('PRIVATE-STORAGE-FAILURE')
                return self.db.execute(sql, *args)
        @contextmanager
        def fault(**kwargs):
            with transaction(**kwargs) as db:
                yield Proxy(db)
        with patch.object(self.ledger, '_transaction', fault):
            with self.assertRaises(UsageDenied) as caught:
                with admitted_identity(self.settings, scope, self.identity):
                    self.fail('No provider work may start')
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        self.assertEqual(before, self.rows())

    def test_no_raw_ip_storage_logs_or_errors(self):
        with patch('src.reliability.logger.info') as info, patch('src.reliability.logger.error') as error:
            self.admit_ip()
            self.assert_rejected(None)
        stored = self.usage_path.read_bytes()
        self.assertNotIn(b'192.0.2.10', stored)
        self.assertNotIn('192.0.2.10', str(info.call_args_list) + str(error.call_args_list))
        row = self.rows()['ip_events'][0]
        self.assertEqual(row[1], self.identity.digest(self.key))
        self.assertEqual(len(row[1]), 32)
        self.assertNotIn(self.key_text, repr(self.settings))
        self.assertNotIn(self.key, stored)

    def test_missing_and_corrupt_database_never_recreated(self):
        from src.usage import UsageLedger
        for content in (None, b'invalid sqlite'):
            path = Path(self.temporary) / ('missing.db' if content is None else 'corrupt.db')
            if content: path.write_bytes(content)
            with patch('src.usage.UsageLedger.from_settings', return_value=UsageLedger(path)):
                with self.assertRaises(UsageDenied):
                    self.admit_ip()
            self.assertEqual(path.read_bytes() if path.exists() else None, content)

    def test_locked_database_fails_closed(self):
        scope = self.scope_for(0)
        self.ledger.busy_ms = 20
        with sqlite3.connect(self.usage_path) as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(UsageDenied):
                with admitted_identity(self.settings, scope, self.identity): pass
        self.assertEqual(self.rows()['ip_events'], [])

    def test_partial_identity_accounting_cannot_fall_back(self):
        for accounting in ({}, {'identity_digest': b'x' * 32},
                           {'identity_digest': None, 'identity_key_tag': None,
                            'identity_minute_limit': 10, 'identity_day_limit': 60}):
            with self.assertRaises(UsageDenied):
                with chat_usage(self.ledger, session_digest=self.digest, identity_accounting=accounting):
                    self.fail('Must not fall back')


class IPMigrationTests(IPFixture):
    def restore_v3(self):
        self.ledger.set_disabled(True)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE ip_events')
            db.execute('DROP TABLE ip_control')
            db.execute('PRAGMA user_version=3')

    def test_migration_preserves_every_existing_table_and_disabled_state(self):
        self.ledger.issue_session(b'x' * 32)
        self.ledger.reserve()
        self.restore_v3()
        with sqlite3.connect(self.usage_path) as db:
            tables = [row[0] for row in db.execute("SELECT name FROM sqlite_schema WHERE type='table'")]
            before = {name: db.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall() for name in tables}
        self.ledger.migrate_identity(self.tag, workers_stopped=True)
        after = self.rows()
        self.assertEqual(before, {name: after[name] for name in tables})
        self.assertTrue(self.ledger.status()['disabled'])

    def test_migration_requires_maintenance_and_rollback_is_complete(self):
        self.restore_v3()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate_identity(self.tag)
        validate = usage._validate_database
        def fail(db, version=None):
            validate(db, version)
            if version == 4: raise UsageDenied()
        before = self.usage_path.read_bytes()
        with patch('src.usage._validate_database', side_effect=fail):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate_identity(self.tag, workers_stopped=True)
        self.assertEqual(before, self.usage_path.read_bytes())
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied):
            self.ledger.migrate_identity(self.tag, workers_stopped=True)

    def test_v3_runtime_does_not_auto_migrate(self):
        self.restore_v3()
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied):
            self.admit_ip()
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 3)

    def test_missing_index_or_changed_constraints_are_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP INDEX ip_events_recent')
        with self.assertRaises(UsageDenied): self.admit_ip()

    def test_same_column_schema_without_checks_is_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE ip_control')
            db.execute('CREATE TABLE ip_control(id INTEGER PRIMARY KEY,key_tag BLOB NOT NULL,last_admitted_at INTEGER NOT NULL)')
            db.execute('INSERT INTO ip_control VALUES(1,?,0)', (self.tag,))
        before = self.usage_path.read_bytes()
        with self.assertRaises(UsageDenied): self.admit_ip()
        self.assertEqual(before, self.usage_path.read_bytes())

    def test_fresh_process_operator_migration_uses_environment_not_dotenv(self):
        self.restore_v3()
        code = '''
import sys
from contextlib import ExitStack
from unittest.mock import patch
with ExitStack() as guards:
 for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','dotenv.load_dotenv'):
  guards.enter_context(patch(target,side_effect=AssertionError('offline')))
 from src.usage_admin import main
 sys.exit(main(['--database',sys.argv[1],'migrate-v4','--confirm-workers-stopped']))
'''
        result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path)], capture_output=True,
                                text=True, timeout=10, env={'PATH': os.defpath, 'IP_RATE_HMAC_KEY': self.key_text})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.key_text, result.stdout + result.stderr)
        self.assertTrue(self.ledger.status()['disabled'])
        self.assertEqual(self.rows()['ip_control'][0][1], self.tag)

    def test_invalid_watermark_and_identity_records_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE ip_control SET last_admitted_at=1')
        with self.assertRaises(UsageDenied): self.admit_ip()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute("INSERT INTO ip_events VALUES(?,?,1)", ('0' * 32, b'short'))
        with self.assertRaises(UsageDenied): self.admit_ip()


class IPConcurrencyTests(IPFixture):
    def test_parallel_final_daily_slot(self):
        self.settings = replace(self.settings, ip_admission_day_limit=1)
        scopes = [self.scope_for(i) for i in range(8)]
        def admit(scope):
            try:
                with admitted_identity(self.settings, scope, self.identity): pass
                return True
            except UsageDenied: return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(admit, scopes)), 1)
        self.assertEqual(len(self.rows()['ip_events']), 1)

    def test_parallel_final_slot_across_sessions(self):
        for i in range(9): self.admit_ip(i)
        scopes = [self.scope_for(i + 9) for i in range(8)]
        def admit(scope):
            try:
                with admitted_identity(self.settings, scope, self.identity): pass
                return True
            except UsageDenied: return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(admit, scopes)), 1)
        self.assertEqual(len(self.rows()['ip_events']), 10)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 10)

    def test_fresh_process_final_slot_and_restart_persistence(self):
        for i in range(9): self.admit_ip(i)
        digests = [hashlib.sha256(dict(self.scope_for(i + 9)['headers'])[b'x-portfolio-session']).hexdigest() for i in range(8)]
        code = '''
import sys
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch
from datetime import datetime,timezone
with ExitStack() as guard:
 for target in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','dotenv.load_dotenv'):
  guard.enter_context(patch(target,side_effect=AssertionError('offline')))
 from src.usage import UsageLedger,UsageDenied
 l=UsageLedger(Path(sys.argv[1]),busy_ms=2000,clock=lambda:datetime(2026,11,9,12,tzinfo=timezone.utc))
 try:
  r=l.reserve_session(bytes.fromhex(sys.argv[2]),identity_digest=bytes.fromhex(sys.argv[3]),identity_key_tag=bytes.fromhex(sys.argv[4]))
  l.release(r)
  print('admitted')
 except UsageDenied as e: print(e.category)
'''
        def child(digest):
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path), digest,
                                     self.identity.digest(self.key).hex(), self.tag.hex()], capture_output=True,
                                    text=True, timeout=10, env={'PATH': os.defpath})
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(child, digests))
        self.assertEqual(results.count('admitted'), 1)
        self.assertEqual(results.count('usage_identity_budget'), 7)
        self.assertEqual(child(digests[-1]), 'usage_identity_budget')


class IPConfigurationTests(OfflineTestCase):
    def test_missing_configuration_disables_feature(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(Settings.from_env().ip_admission_enabled)

    def test_enabled_requires_key_session_and_bearer_authentication(self):
        with patch.dict(os.environ, {'IP_ADMISSION_ENABLED': 'true'}):
            with self.assertRaises(ValueError): Settings.from_env()
        with patch.dict(os.environ, {'IP_ADMISSION_ENABLED': 'true', 'SESSION_ADMISSION_ENABLED': 'true',
                                    'STAGING_AUTH_ENABLED': 'true', 'STAGING_AUTH_TOKEN': 's' * 43}):
            with self.assertRaises(ValueError): Settings.from_env()

    def test_invalid_configuration_never_echoes_secret(self):
        for key, value in (('IP_RATE_HMAC_KEY', 'PRIVATE-INVALID-KEY'), ('IP_ADMISSION_ENABLED', 'private'),
                           ('IP_ADMISSION_MINUTE_LIMIT', '0'), ('IP_ADMISSION_DAY_LIMIT', '10001')):
            with patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError) as caught: Settings.from_env()
                self.assertNotIn(value, str(caught.exception))

    def test_defaults(self):
        settings = Settings.from_env()
        self.assertEqual((settings.ip_admission_minute_limit, settings.ip_admission_day_limit), (10, 60))
