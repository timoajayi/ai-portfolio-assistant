"""Versioned storage tests: temporary databases, no tokens or provider calls."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from src import usage
from src.usage import UsageDenied, UsageLedger, chat_usage, paid_call
from src.usage_admin import main as admin
from tests.offline import OfflineTestCase


CHILD = '''
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch
with ExitStack() as guards:
 for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect',
              'socket.socket.connect_ex','dotenv.load_dotenv'):
  guards.enter_context(patch(name,side_effect=AssertionError('Offline isolation')))
 from src.usage import UsageLedger, UsageDenied
 ledger=UsageLedger(Path(sys.argv[1]))
 action=sys.argv[2]
 try:
  if action=='migrate': ledger.migrate(workers_stopped=True)
  elif action=='lookup':
   result=ledger.lookup_session(bytes.fromhex(sys.argv[3]))
   print(result['id'] if result else 'absent')
  elif action=='reserve':
   ledger.reserve()
  elif action=='create':
   print(ledger.create_session(bytes.fromhex(sys.argv[3]),int(sys.argv[4]),verified=True))
  print('ok')
 except UsageDenied as error:
  print(error.category)
'''


class SessionStorageTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
        self.ledger = UsageLedger(self.usage_path, clock=lambda: self.now)
        self.digest = hashlib.sha256(b'synthetic-test-input').digest()

    def version(self):
        with sqlite3.connect(self.usage_path) as db:
            return db.execute('PRAGMA user_version').fetchone()[0]

    def accounting(self):
        with sqlite3.connect(self.usage_path) as db:
            return {table: db.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall()
                    for table in ('control', 'periods', 'active')}

    def migrate(self):
        self.ledger.set_disabled(True)
        self.ledger.migrate(workers_stopped=True)

    def create(self, **kwargs):
        return self.ledger.create_session(self.digest, int(self.now.timestamp()) + 3600, **kwargs)

    def fresh(self, action, *args):
        result = subprocess.run([sys.executable, '-B', '-c', CHILD, str(self.usage_path), action, *args],
                                capture_output=True, text=True, timeout=10,
                                env={'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def assert_invalid(self):
        before = self.usage_path.read_bytes()
        provider = Mock()
        with self.assertRaises(UsageDenied):
            with chat_usage(self.ledger):
                paid_call('generation', provider)
        provider.assert_not_called()
        with self.assertRaises(UsageDenied):
            self.ledger.lookup_session(self.digest)
        self.assertEqual(self.usage_path.read_bytes(), before)

    def test_v1_initialization_validation_and_runtime_do_not_migrate(self):
        self.assertEqual(self.version(), 1)
        self.ledger.release(self.ledger.reserve())
        self.assertEqual(self.version(), 1)
        with self.assertRaises(UsageDenied):
            self.create()
        self.assertEqual(self.version(), 1)
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_schema WHERE name='sessions'").fetchone()[0], 0)

    def test_v1_invalid_constraints_cannot_be_migrated(self):
        self.ledger.set_disabled(True)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE periods')
            db.execute('CREATE TABLE periods(kind TEXT,period TEXT,admitted INTEGER,embedding_ops INTEGER,'
                       'generation_ops INTEGER,PRIMARY KEY(kind,period))')
        before = self.usage_path.read_bytes()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.version(), 1)
        self.assertEqual(before, self.usage_path.read_bytes())

    def test_v1_invalid_accounting_cannot_be_migrated(self):
        self.ledger.release(self.ledger.reserve())
        self.ledger.set_disabled(True)
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE periods SET admitted=2 WHERE kind='month'")
        with self.assertRaises(UsageDenied):
            self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.version(), 1)

    def test_migration_preserves_accounting_disabled_state_and_active_reservations(self):
        first = self.ledger.reserve()
        self.ledger.operation(first, 'embedding')
        self.now += timedelta(days=1)
        second = self.ledger.reserve()
        self.ledger.operation(second, 'generation')
        self.ledger.set_disabled(True)
        before = self.accounting()
        self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.version(), 2)
        self.assertEqual(self.accounting(), before)
        self.assertTrue(self.ledger.status()['disabled'])
        self.assertEqual(self.ledger.status()['active'], 2)
        with self.assertRaises(UsageDenied):
            self.ledger.reserve()

    def test_migration_requires_disable_and_exact_worker_confirmation(self):
        with self.assertRaises(UsageDenied):
            self.ledger.migrate(workers_stopped=True)
        self.ledger.set_disabled(True)
        for confirmation in (False, 1, 'yes'):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate(workers_stopped=confirmation)
        self.assertEqual(self.version(), 1)

    def test_failed_final_validation_rolls_back_every_schema_change(self):
        self.ledger.reserve()
        self.ledger.set_disabled(True)
        before = self.accounting()
        validate = usage._validate_database
        def fail_v2(db, version=None):
            validate(db, version)
            if version == 2:
                raise UsageDenied()
        with patch('src.usage._validate_database', side_effect=fail_v2):
            with self.assertRaises(UsageDenied):
                self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.version(), 1)
        self.assertEqual(self.accounting(), before)
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_schema WHERE name LIKE 'session%'").fetchone()[0], 0)
        self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.accounting(), before)

    def test_migration_sql_failure_rolls_back(self):
        self.ledger.set_disabled(True)
        with patch('src.usage.SESSION_SCHEMA', (*usage.SESSION_SCHEMA[:1], 'INVALID SQL')):
            with self.assertRaises(UsageDenied) as caught:
                self.ledger.migrate(workers_stopped=True)
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        self.assertEqual(self.version(), 1)
        self.assertTrue(self.ledger.status()['disabled'])

    def test_missing_or_corrupt_storage_is_not_recreated_by_migration(self):
        for content in (None, b'not-sqlite'):
            path = Path(self.temporary) / ('missing.sqlite3' if content is None else 'corrupt.sqlite3')
            if content is not None:
                path.write_bytes(content)
            with self.assertRaises(UsageDenied):
                UsageLedger(path).migrate(workers_stopped=True)
            self.assertEqual(path.read_bytes() if path.exists() else None, content)

    def test_fresh_process_migration_and_lookup_persistence(self):
        # Future expiry for a child using its real UTC clock; still synthetic.
        self.now = datetime.now(timezone.utc)
        self.ledger.reserve()
        self.ledger.set_disabled(True)
        before = self.accounting()
        self.assertEqual(self.fresh('migrate'), 'ok')
        identifier = self.create(verified=True)
        self.assertEqual(self.fresh('lookup', self.digest.hex()), identifier + '\nok')
        self.assertEqual(self.fresh('reserve'), 'usage_disabled')
        self.assertEqual(self.accounting(), before)

    def test_v2_migration_is_not_repeated_or_downgraded(self):
        self.migrate()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate(workers_stopped=True)
        self.assertEqual(self.version(), 2)

    def test_operator_cli_migration_requires_prerequisites_without_dotenv(self):
        args = ['--database', str(self.usage_path), 'migrate-v2']
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(admin(args), 1)
            self.ledger.set_disabled(True)
            self.assertEqual(admin([*args, '--confirm-workers-stopped']), 0)
        self.assertNotIn(str(self.usage_path), output.getvalue())
        self.dotenv.assert_not_called()
        self.client_factory.assert_not_called()

    def test_session_lookup_expiration_and_no_raw_digest_in_result(self):
        self.migrate()
        identifier = self.create()
        result = self.ledger.lookup_session(self.digest)
        self.assertEqual(result['id'], identifier)
        self.assertEqual(result['verified'], 0)
        self.assertNotIn('token_digest', result)
        self.assertIsNone(self.ledger.lookup_session(b'x' * 32))
        self.now += timedelta(hours=1)
        self.assertIsNone(self.ledger.lookup_session(self.digest))
        with self.assertRaises(UsageDenied):
            self.ledger.record_session_usage(identifier)

    def test_revoked_session_cannot_record_usage(self):
        self.migrate()
        identifier = self.create(verified=True)
        self.assertTrue(self.ledger.revoke_session(identifier))
        self.assertTrue(self.ledger.revoke_session(identifier))
        self.assertIsNone(self.ledger.lookup_session(self.digest))
        with self.assertRaises(UsageDenied):
            self.ledger.record_session_usage(identifier)

    def test_unverified_session_cannot_record_usage(self):
        self.migrate()
        with self.assertRaises(UsageDenied):
            self.ledger.record_session_usage(self.create())

    def test_duplicate_digest_rejected_safely(self):
        self.migrate()
        identifier = self.create()
        with self.assertRaises(UsageDenied) as caught:
            self.create()
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        self.assertEqual(self.ledger.lookup_session(self.digest)['id'], identifier)

    def test_session_inputs_validated(self):
        self.migrate()
        for digest in ('not-a-digest', b'short', bytearray(32), None):
            with self.assertRaises(UsageDenied):
                self.ledger.create_session(digest, 0)
        for expires in (-1, True, 1.5, 'tomorrow', 253402300800, int(self.now.timestamp())):
            with self.assertRaises(UsageDenied):
                self.ledger.create_session(self.digest, expires)
        with self.assertRaises(UsageDenied):
            self.create(verified='true')

    def test_events_recorded_transactionally_and_recent_query_bounded(self):
        self.migrate()
        before = self.accounting()
        identifier = self.create(verified=True)
        first = self.ledger.record_session_usage(identifier)
        self.now += timedelta(seconds=5)
        second = self.ledger.record_session_usage(identifier)
        since = int(self.now.timestamp())
        self.assertEqual(self.ledger.recent_session_usage(identifier, since), [(second, since)])
        self.assertEqual(len(self.ledger.recent_session_usage(identifier, 0, limit=1)), 1)
        self.assertNotEqual(first, second)
        self.assertEqual(self.accounting(), before)
        for limit in (0, 1001, True):
            with self.assertRaises(UsageDenied):
                self.ledger.recent_session_usage(identifier, 0, limit=limit)

    def test_concurrent_session_creation_and_event_storage(self):
        self.migrate()
        expires = int(self.now.timestamp()) + 3600
        def create(index):
            return self.ledger.create_session(hashlib.sha256(str(index).encode()).digest(), expires, verified=True)
        with ThreadPoolExecutor(max_workers=6) as pool:
            identifiers = list(pool.map(create, range(12)))
            events = list(pool.map(self.ledger.record_session_usage, [identifiers[0]] * 12))
        self.assertEqual(len(set(identifiers)), 12)
        self.assertEqual(len(set(events)), 12)
        self.assertEqual(len(self.ledger.recent_session_usage(identifiers[0], 0)), 12)

    def test_concurrent_duplicate_digest_allows_one_record(self):
        self.migrate()
        def create(_):
            try:
                return self.create()
            except UsageDenied:
                return None
        with ThreadPoolExecutor(max_workers=6) as pool:
            result = list(pool.map(create, range(12)))
        self.assertEqual(sum(value is not None for value in result), 1)

    def test_multiple_processes_store_sessions_in_one_database(self):
        self.migrate()
        expires = str(int(datetime.now(timezone.utc).timestamp()) + 3600)
        def create(number):
            return self.fresh('create', hashlib.sha256(str(number).encode()).hexdigest(), expires)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(create, range(8)))
        self.assertTrue(all(value.endswith('\nok') for value in results))
        self.assertEqual(len(set(results)), 8)
        self.assertTrue(self.ledger.status()['disabled'])

    def test_required_index_and_unsupported_version_rejected(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP INDEX session_events_recent')
        self.assert_invalid()

    def test_unsupported_schema_version_rejected(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=3')
        self.assert_invalid()

    def test_partial_migration_rejected(self):
        self.ledger.set_disabled(True)
        with sqlite3.connect(self.usage_path) as db:
            db.execute(usage.SESSION_SCHEMA[0])
        with self.assertRaises(UsageDenied):
            self.ledger.status()
        with self.assertRaises(UsageDenied):
            self.ledger.migrate(workers_stopped=True)

    def test_missing_session_constraints_rejected(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE session_events')
            db.execute(usage.SESSION_SCHEMA[1].replace(" CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*')", ''))
            db.execute(usage.SESSION_SCHEMA[3])
        self.assert_invalid()

    def test_invalid_session_record_rejected(self):
        self.migrate()
        self.create()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('UPDATE sessions SET expires_at=created_at')
        self.assert_invalid()

    def test_invalid_digest_and_verification_values_rejected(self):
        self.migrate()
        self.create()
        for statement in ("UPDATE sessions SET token_digest='not-a-digest'",
                          'UPDATE sessions SET verified=2', 'UPDATE sessions SET created_at=-1'):
            with self.subTest(statement=statement):
                with sqlite3.connect(self.usage_path) as db:
                    db.execute('PRAGMA ignore_check_constraints=ON')
                    db.execute(statement)
                self.assert_invalid()
                # Explicit test-only restoration, never performed by runtime.
                with sqlite3.connect(self.usage_path) as db:
                    db.execute('UPDATE sessions SET token_digest=?,verified=0,created_at=?',
                               (self.digest, int(self.now.timestamp())))

    def test_missing_foreign_key_rejected(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE session_events')
            db.execute(usage.SESSION_SCHEMA[1].replace(' REFERENCES sessions(id) ON DELETE CASCADE', ''))
            db.execute(usage.SESSION_SCHEMA[3])
        self.assert_invalid()

    def test_missing_unique_digest_constraint_rejected(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE session_events')
            db.execute('DROP TABLE sessions')
            db.execute(usage.SESSION_SCHEMA[0].replace('BLOB NOT NULL UNIQUE', 'BLOB NOT NULL'))
            for statement in usage.SESSION_SCHEMA[1:]:
                db.execute(statement)
        self.assert_invalid()

    def test_session_uuid_version_validated_beyond_sql_hex_check(self):
        self.migrate()
        self.create()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE sessions SET id=?', ('0' * 32,))
        self.assert_invalid()

    def test_orphan_events_fail_closed_even_if_inserted_with_foreign_keys_off(self):
        self.migrate()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('INSERT INTO session_events VALUES(?,?,?)', ('a' * 32, 'b' * 32, 1))
        self.assert_invalid()

    def test_event_outside_session_lifetime_rejected(self):
        self.migrate()
        identifier = self.create(verified=True)
        self.ledger.record_session_usage(identifier)
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE session_events SET admitted_at=0')
        self.assert_invalid()

    def test_cleanup_requires_disabled_stopped_workers_and_preserves_accounting(self):
        self.ledger.reserve()
        self.migrate()
        before = self.accounting()
        identifier = self.create(verified=True)
        self.ledger.record_session_usage(identifier)
        self.now += timedelta(days=2)
        with self.assertRaises(UsageDenied):
            self.ledger.cleanup_sessions()
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied):
            self.ledger.cleanup_sessions(workers_stopped=True)
        self.ledger.set_disabled(True)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True), 1)
        self.assertEqual(self.ledger.recent_session_usage(identifier, 0), [])
        self.assertEqual(self.accounting(), before)

    def test_cleanup_respects_retention_and_batch_limit(self):
        self.migrate()
        for number in range(3):
            self.ledger.create_session(bytes([number]) * 32, int(self.now.timestamp()) + 3600)
        self.now += timedelta(hours=2)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True), 0)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0, limit=2), 2)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0), 1)
        for arguments in ({'limit': 0}, {'retention_seconds': -1}, {'retention_seconds': 31_536_001}):
            with self.assertRaises(UsageDenied):
                self.ledger.cleanup_sessions(workers_stopped=True, **arguments)

    def test_cleanup_failure_rolls_back_session_and_event_deletions(self):
        self.migrate()
        identifier = self.create(verified=True)
        event = self.ledger.record_session_usage(identifier)
        self.now += timedelta(days=2)
        # Fail before COMMIT after the DELETE and FK cascade, preserving both rows.
        transaction = self.ledger._transaction
        from contextlib import contextmanager
        @contextmanager
        def fail_after_delete(**kwargs):
            with transaction(**kwargs) as db:
                yield db
                raise UsageDenied()
        with patch.object(self.ledger, '_transaction', fail_after_delete):
            with self.assertRaises(UsageDenied):
                self.ledger.cleanup_sessions(workers_stopped=True)
        self.assertEqual(self.ledger.recent_session_usage(identifier, 0)[0][0], event)
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)

    def test_v2_existing_budget_and_provider_guard_remain_active(self):
        self.migrate()
        provider = Mock()
        with self.assertRaises(UsageDenied):
            with chat_usage(self.ledger):
                paid_call('generation', provider)
        provider.assert_not_called()
        self.ledger.set_disabled(False)
        self.ledger.daily = 1
        with chat_usage(self.ledger):
            paid_call('generation', provider)
        with self.assertRaises(UsageDenied) as caught:
            self.ledger.reserve()
        self.assertEqual(caught.exception.category, 'usage_budget')
        self.assertEqual(self.ledger.status()['periods']['month']['generation_ops'], 1)
        provider.assert_called_once()

    def test_migration_has_no_http_route_or_startup_side_effect(self):
        api = self.load('src.api')
        before = self.accounting()
        with patch.object(UsageLedger, 'migrate', side_effect=AssertionError('No runtime migration')):
            with TestClient(api.app) as http:
                self.assertEqual(http.get('/health').status_code, 200)
                self.assertEqual(http.get('/ready').status_code, 200)
                self.assertEqual(http.post('/usage/migrate-v2').status_code, 404)
                self.assertEqual(self.version(), 1)
        self.assertEqual(self.accounting(), before)
        self.client_factory.assert_not_called()

    def test_v2_authenticated_chat_still_requires_bearer_and_usage_admission(self):
        from dataclasses import replace
        self.migrate()
        api = self.load('src.api')
        controls = api.app.state.chat_controls
        self.authorize_legacy_staging(api, token='s' * 43)
        with TestClient(api.app) as http, patch('src.reliability.logger.info') as logs:
            body = {'message': 'Show me all projects'}
            self.assertEqual(http.post('/chat', json=body).status_code, 401)
            headers = {'Authorization': 'Bearer ' + 's' * 43}
            self.assertEqual(http.post('/chat', json=body, headers=headers).status_code, 503)
            self.client_factory.assert_not_called()
            self.ledger.set_disabled(False)  # Temporary fixture only; bearer still mandatory.
            self.assertEqual(http.post('/chat', json=body, headers=headers).status_code, 200)
            self.assertNotIn('s' * 43, str(logs.call_args_list))
        self.assertEqual(self.ledger.status()['periods']['month']['generation_ops'], 1)

    def test_no_provider_clients_or_dotenv_used_by_session_storage(self):
        self.migrate()
        identifier = self.create(verified=True)
        self.ledger.record_session_usage(identifier)
        self.ledger.revoke_session(identifier)
        self.client_factory.assert_not_called()
        self.dotenv.assert_not_called()
