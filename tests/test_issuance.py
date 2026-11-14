"""Independent negative probes and HTTP issuance tests, entirely offline."""

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import AsyncMock, patch
from contextlib import redirect_stdout

from fastapi.testclient import TestClient

from src import usage
from src.config import Settings
from src.reliability import ChatControls, ChatProtectionMiddleware, RateLimiter
from src.usage import UsageDenied, UsageLedger
from src.usage_admin import main as admin
from tests.offline import OfflineTestCase


class IssuanceFixture(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
        self.ledger = UsageLedger(self.usage_path, clock=lambda: self.now, busy_ms=1000)
        self.ledger.set_disabled(True)
        self.ledger.migrate(workers_stopped=True)
        self.ledger.migrate_issuance(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.ledger.set_issuance_disabled(False)

    def issue(self, number=0, **kwargs):
        return self.ledger.issue_session(hashlib.sha256(str(number).encode()).digest(), **kwargs)

    def snapshot(self):
        with sqlite3.connect(self.usage_path) as db:
            return {name: db.execute(f'SELECT * FROM {name} ORDER BY 1').fetchall()
                    for name in ('control', 'periods', 'active', 'sessions', 'session_events')}


class IssuanceStorageTests(IssuanceFixture):
    def test_migration_preserves_all_existing_records_and_defaults_disabled(self):
        identifier = self.ledger.reserve()
        self.ledger.operation(identifier, 'embedding')
        self.ledger.create_session(b'x' * 32, int(self.now.timestamp()) + 1000, verified=True)
        self.ledger.set_disabled(True)
        before = self.snapshot()
        # Restore a complete v2 schema in this isolated test to rerun migration.
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE issuance_events')
            db.execute('DROP TABLE issuance_control')
            db.execute('PRAGMA user_version=2')
        self.ledger.migrate_issuance(workers_stopped=True)
        self.assertEqual(before, self.snapshot())
        self.assertTrue(self.ledger.issuance_status()['issuance_disabled'])
        self.assertTrue(self.ledger.status()['disabled'])

    def test_migration_requires_disabled_and_stopped_workers(self):
        path = Path(self.temporary) / 'other.sqlite3'
        ledger = UsageLedger(path)
        ledger.initialize()
        ledger.migrate(workers_stopped=True)
        with self.assertRaises(UsageDenied):
            ledger.migrate_issuance()
        ledger.set_disabled(False)
        with self.assertRaises(UsageDenied):
            ledger.migrate_issuance(workers_stopped=True)

    def test_migration_failure_rolls_back(self):
        path = Path(self.temporary) / 'rollback.sqlite3'
        ledger = UsageLedger(path)
        ledger.initialize()
        ledger.migrate(workers_stopped=True)
        validate = usage._validate_database
        def fail(db, version=None):
            validate(db, version)
            if version == 3:
                raise UsageDenied()
        with patch('src.usage._validate_database', side_effect=fail):
            with self.assertRaises(UsageDenied):
                ledger.migrate_issuance(workers_stopped=True)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_schema WHERE name LIKE 'issuance%'").fetchone()[0], 0)
        self.assertTrue(ledger.status()['disabled'])

    def test_rolling_minute_enforced_and_boundary_resets(self):
        self.issue(0, minute_limit=1)
        self.now += timedelta(seconds=59)
        with self.assertRaises(UsageDenied) as caught:
            self.issue(1, minute_limit=1)
        self.assertEqual(caught.exception.status, 429)
        self.now += timedelta(seconds=1)
        self.issue(1, minute_limit=1)

    def test_rolling_day_enforced_across_midnight(self):
        self.issue(0, day_limit=1)
        self.now += timedelta(hours=23, minutes=59)
        with self.assertRaises(UsageDenied):
            self.issue(1, day_limit=1)
        self.now += timedelta(minutes=1)
        self.issue(1, day_limit=1)

    def test_live_limit_includes_existing_sessions_and_expiration(self):
        self.ledger.create_session(b'x' * 32, int(self.now.timestamp()) + 10)
        with self.assertRaises(UsageDenied):
            self.issue(live_limit=1)
        self.now += timedelta(seconds=10)
        self.issue(live_limit=1)

    def test_revocation_frees_live_capacity_but_not_issuance_allowance(self):
        self.issue(0, minute_limit=1, live_limit=1)
        session = self.ledger.lookup_session(hashlib.sha256(b'0').digest())
        self.ledger.revoke_session(session['id'])
        with self.assertRaises(UsageDenied):
            self.issue(1, minute_limit=1, live_limit=1)

    def test_cleanup_cannot_reset_issuance_history(self):
        self.issue(0, lifetime=1, day_limit=1)
        self.now += timedelta(seconds=2)
        self.ledger.set_disabled(True)
        self.assertEqual(self.ledger.cleanup_sessions(workers_stopped=True, retention_seconds=0), 1)
        self.ledger.set_disabled(False)
        with self.assertRaises(UsageDenied) as caught:
            self.issue(1, day_limit=1)
        self.assertEqual(caught.exception.category, 'usage_issuance_budget')

    def test_concurrent_final_slot_is_atomic(self):
        def issue(number):
            try:
                self.issue(number, minute_limit=1)
                return True
            except UsageDenied:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(issue, range(16))), 1)

    def test_restart_and_multiple_processes_share_final_allowance(self):
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
  l.issue_session(bytes([int(sys.argv[2])])*32,minute_limit=1)
  print('issued')
 except UsageDenied as e: print(e.category)
'''
        def child(number):
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.usage_path), str(number)],
                                    capture_output=True, text=True, timeout=10, env={'PATH': os.defpath})
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(child, range(8)))
        self.assertEqual(results.count('issued'), 1)
        self.assertEqual(results.count('usage_issuance_budget'), 7)
        self.assertEqual(child(20), 'usage_issuance_budget')
        self.ledger.set_issuance_disabled(True)
        self.assertEqual(child(21), 'usage_issuance_disabled')

    def test_either_emergency_control_blocks_issuance(self):
        self.ledger.set_issuance_disabled(True)
        with self.assertRaises(UsageDenied):
            self.issue()
        self.assertFalse(self.ledger.status()['disabled'])
        self.ledger.set_issuance_disabled(False)
        self.ledger.set_disabled(True)
        with self.assertRaises(UsageDenied):
            self.issue()
        with self.assertRaises(UsageDenied):
            self.ledger.set_issuance_disabled(False)

    def test_clock_rollback_fails_closed(self):
        self.issue()
        self.now -= timedelta(seconds=1)
        with self.assertRaises(UsageDenied) as caught:
            self.issue(1)
        self.assertEqual(caught.exception.category, 'usage_clock')

    def test_failed_insertion_does_not_spend_issuance_allowance(self):
        self.issue(0)
        with self.assertRaises(UsageDenied):
            self.issue(0)
        self.issue(1, minute_limit=2)
        with self.assertRaises(UsageDenied):
            self.issue(2, minute_limit=2)

    def test_issuance_does_not_change_gemini_counters_or_active_reservations(self):
        self.ledger.reserve()
        before = {k: v for k, v in self.snapshot().items() if k != 'sessions'}
        self.issue()
        after = {k: v for k, v in self.snapshot().items() if k != 'sessions'}
        self.assertEqual(before, after)
        self.client_factory.assert_not_called()

    def test_unverified_session_cannot_record_paid_admission_event(self):
        self.issue()
        session = self.ledger.lookup_session(hashlib.sha256(b'0').digest())
        self.assertEqual(session['verified'], 0)
        with self.assertRaises(UsageDenied):
            self.ledger.record_session_usage(session['id'])

    def test_altered_schema_and_negative_state_fail_closed(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP INDEX issuance_recent')
        with self.assertRaises(UsageDenied):
            self.issue()

    def test_invalid_watermark_and_control_state_fail_closed(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE issuance_control SET last_issued_at=1')
        with self.assertRaises(UsageDenied):
            self.issue()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('UPDATE issuance_control SET last_issued_at=-1')
        with self.assertRaises(UsageDenied):
            self.issue()

    def test_same_column_control_without_required_checks_is_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE issuance_control')
            db.execute('CREATE TABLE issuance_control(id INTEGER PRIMARY KEY, disabled INTEGER NOT NULL, '
                       'last_issued_at INTEGER NOT NULL)')
            db.execute('INSERT INTO issuance_control VALUES(1,0,0)')
        before = self.usage_path.read_bytes()
        with self.assertRaises(UsageDenied):
            self.issue()
        self.assertEqual(self.usage_path.read_bytes(), before)

    def test_busy_storage_fails_closed_without_new_issuance(self):
        self.ledger.busy_ms = 20
        with sqlite3.connect(self.usage_path) as db:
            db.execute('BEGIN IMMEDIATE')
            with self.assertRaises(UsageDenied):
                self.issue()
        with sqlite3.connect(self.usage_path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM issuance_events').fetchone()[0], 0)

    def test_unsupported_schema_version_does_not_migrate(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=4')
        before = self.usage_path.read_bytes()
        with self.assertRaises(UsageDenied):
            self.issue()
        self.assertEqual(before, self.usage_path.read_bytes())

    def test_operator_shutdown_commands_need_no_credentials(self):
        with redirect_stdout(io.StringIO()) as output:
            prefix = ['--database', str(self.usage_path)]
            self.assertEqual(admin([*prefix, 'disable-issuance']), 0)
            self.assertEqual(admin([*prefix, 'issuance-status']), 0)
        self.assertIn('true', output.getvalue())
        self.dotenv.assert_not_called()
        self.client_factory.assert_not_called()


class IssuanceConfigurationTests(OfflineTestCase):
    def test_missing_flag_keeps_issuance_disabled(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(Settings.from_env().session_issuance_enabled)

    def test_enabled_requires_existing_authentication(self):
        with patch.dict(os.environ, {'SESSION_ISSUANCE_ENABLED': 'true'}):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_invalid_flag_and_lifetime_fail_closed_without_echo(self):
        for key, value in (('SESSION_ISSUANCE_ENABLED', 'private-invalid'),
                           ('SESSION_LIFETIME_SECONDS', '86401'), ('SESSION_LIFETIME_SECONDS', '0'),
                           ('SESSION_ISSUANCE_MINUTE_LIMIT', '-1'), ('SESSION_ISSUANCE_DAY_LIMIT', '10001'),
                           ('SESSION_MAX_LIVE', 'nan')):
            with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                with self.assertRaises(ValueError) as caught:
                    Settings.from_env()
                self.assertNotIn(value, str(caught.exception))

    def test_valid_enabled_configuration_and_defaults(self):
        with patch.dict(os.environ, {'SESSION_ISSUANCE_ENABLED': 'true', 'STAGING_AUTH_ENABLED': 'true',
                                    'STAGING_AUTH_TOKEN': 's' * 43}):
            settings = Settings.from_env()
        self.assertTrue(settings.session_issuance_enabled)
        self.assertEqual((settings.session_lifetime_seconds, settings.session_issuance_minute_limit,
                          settings.session_issuance_day_limit, settings.session_max_live), (14400, 10, 100, 500))


class IssuanceHTTPTests(IssuanceFixture):
    def setUp(self):
        super().setUp()
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.controls.settings = replace(self.controls.settings, staging_auth_enabled=True,
                                         staging_auth_token='s' * 43, session_issuance_enabled=True)
        self.controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.stack.enter_context(patch.object(UsageLedger, 'from_settings', return_value=self.ledger))
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.headers = {'Authorization': 'Bearer ' + 's' * 43}

    def post(self, **kwargs):
        kwargs.setdefault('headers', self.headers)
        kwargs.setdefault('json', {})
        return self.http.post('/internal/sessions', **kwargs)

    def assert_no_provider(self):
        self.client_factory.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_disabled_feature_and_disabled_auth_never_issue(self):
        for field in ('session_issuance_enabled', 'staging_auth_enabled'):
            original = self.controls.settings
            self.controls.settings = replace(original, **{field: False})
            self.assertEqual(self.post().status_code, 404)
            self.controls.settings = original
        self.assertEqual(self.snapshot()['sessions'], [])

    def test_missing_wrong_malformed_duplicate_and_query_credentials_rejected(self):
        for headers in ({}, {'Authorization': 'Bearer ' + 'w' * 43}, {'Authorization': 'Basic invalid'},
                        [('Authorization', self.headers['Authorization']), ('Authorization', self.headers['Authorization'])]):
            self.assertEqual(self.post(headers=headers).status_code, 401)
        self.assertEqual(self.http.post('/internal/sessions?token=invalid', json={}).status_code, 401)
        self.assertEqual(self.snapshot()['sessions'], [])
        self.assert_no_provider()

    def test_secure_one_time_token_digest_response_and_no_logs(self):
        with patch('src.api.secrets.token_urlsafe', wraps=__import__('secrets').token_urlsafe) as generate:
            response = self.post()
        self.assertEqual(response.status_code, 201)
        generate.assert_called_once_with(32)
        payload = response.json()
        self.assertEqual(set(payload), {'token', 'expires_at'})
        token = payload['token']
        self.assertEqual(len(base64.urlsafe_b64decode(token + '=')), 32)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertNotIn('set-cookie', response.headers)
        self.assertNotIn(token, str(response.headers) + str(self.logs.call_args_list))
        self.assertNotIn(token.encode(), self.usage_path.read_bytes())
        digest = hashlib.sha256(token.encode()).digest()
        self.assertIsNotNone(self.ledger.lookup_session(digest))
        self.assertEqual(self.snapshot()['sessions'][0][1], digest)
        second = self.post()
        self.assertNotEqual(second.json()['token'], token)
        self.assertNotIn(token, second.text)
        self.assert_no_provider()

    def test_get_head_and_other_methods_cannot_retrieve_token(self):
        for method in ('GET', 'HEAD', 'PUT', 'DELETE'):
            response = self.http.request(method, '/internal/sessions', headers=self.headers)
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(self.snapshot()['sessions'], [])

    def test_trailing_slash_alias_cannot_bypass_authentication(self):
        self.assertEqual(self.http.post('/internal/sessions/', json={}).status_code, 401)
        self.assertEqual(self.http.post('/internal/sessions/', json={}, headers=self.headers).status_code, 201)
        self.assertEqual(len(self.snapshot()['sessions']), 1)

    def test_body_fields_and_malformed_json_rejected_without_echo(self):
        marker = 'PRIVATE-INPUT-MARKER'
        for body in ({'verified': True}, {'expires_at': 99999999999}, {'token': marker},
                     {'session_id': marker}, {'client_ip': marker}, {'message': marker}, []):
            response = self.post(json=body)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn(marker, response.text)
        response = self.http.post('/internal/sessions', headers={**self.headers, 'Content-Type': 'application/json'},
                                  content='{"private":"PRIVATE-INPUT-MARKER"')
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text + str(self.logs.call_args_list))
        self.assertEqual(self.snapshot()['sessions'], [])

    def test_oversized_and_streamed_body_rejected(self):
        for body in (b' ' * 257, iter([b' ' * 150, b' ' * 150])):
            response = self.http.post('/internal/sessions', headers=self.headers, content=body)
            self.assertEqual(response.status_code, 413)
        self.assertEqual(self.snapshot()['sessions'], [])

    def test_browser_origin_and_query_fields_rejected(self):
        self.assertEqual(self.post(headers={**self.headers, 'Origin': 'http://localhost:3000'}).status_code, 403)
        self.assertEqual(self.http.post('/internal/sessions?verified=true', json={}, headers=self.headers).status_code, 400)
        self.assertEqual(self.snapshot()['sessions'], [])

    def test_expiry_is_absolute_and_revocation_is_effective(self):
        response = self.post()
        token = response.json()['token']
        digest = hashlib.sha256(token.encode()).digest()
        expires = response.json()['expires_at']
        self.now += timedelta(hours=3)
        self.assertEqual(self.ledger.lookup_session(digest)['expires_at'], expires)
        self.now += timedelta(hours=1)
        self.assertIsNone(self.ledger.lookup_session(digest))
        token = self.post().json()['token']
        digest = hashlib.sha256(token.encode()).digest()
        self.ledger.revoke_session(self.ledger.lookup_session(digest)['id'])
        self.assertIsNone(self.ledger.lookup_session(digest))

    def test_session_token_cannot_authenticate_chat(self):
        token = self.post().json()['token']
        response = self.http.post('/chat', json={'message': 'Docker?'}, headers={'Authorization': 'Bearer ' + token})
        self.assertEqual(response.status_code, 401)
        self.assert_no_provider()

    def test_limit_returns_sanitized_429_no_token_and_no_gemini_usage(self):
        self.controls.settings = replace(self.controls.settings, session_issuance_minute_limit=1)
        before = self.ledger.status()
        token = self.post().json()['token']
        response = self.post()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {'detail': 'Session issuance unavailable.'})
        self.assertIn('retry-after', response.headers)
        self.assertNotIn(token, response.text + str(self.logs.call_args_list))
        self.assertEqual(self.ledger.status(), before)
        self.assert_no_provider()

    def test_either_emergency_shutdown_returns_503(self):
        self.ledger.set_issuance_disabled(True)
        self.assertEqual(self.post().status_code, 503)
        self.ledger.set_issuance_disabled(False)
        self.ledger.set_disabled(True)
        self.assertEqual(self.post().status_code, 503)
        self.assertEqual(self.snapshot()['sessions'], [])
        self.assert_no_provider()

    def test_missing_and_corrupt_database_fail_closed_no_replacement(self):
        self.usage_path.unlink()
        self.assertEqual(self.post().status_code, 503)
        self.assertFalse(self.usage_path.exists())
        self.usage_path.write_bytes(b'corrupt')
        self.assertEqual(self.post().status_code, 503)
        self.assertEqual(self.usage_path.read_bytes(), b'corrupt')
        self.assert_no_provider()

    def test_unexpected_storage_errors_do_not_disclose_details(self):
        with patch.object(self.ledger, 'issue_session', side_effect=RuntimeError('PRIVATE-STORAGE-SECRET')):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('PRIVATE', response.text + str(self.logs.call_args_list))
        self.assert_no_provider()

    def test_version_two_requires_operator_migration_and_is_not_repaired(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE issuance_events')
            db.execute('DROP TABLE issuance_control')
            db.execute('PRAGMA user_version=2')
        before = self.usage_path.read_bytes()
        self.assertEqual(self.post().status_code, 503)
        self.assertEqual(self.usage_path.read_bytes(), before)
        self.assert_no_provider()

    def test_health_and_readiness_unchanged_without_authentication(self):
        self.assertEqual(self.http.get('/health').status_code, 200)
        self.assertEqual(self.http.get('/ready').status_code, 200)
        self.assert_no_provider()


class IssuanceASGINegativeTests(OfflineTestCase):
    """Exercise separate ASGI chunks without TestClient body buffering."""

    def run_request(self, chunks, headers=(), slow=False):
        config = Settings(staging_auth_enabled=True, staging_auth_token='s' * 43,
                          session_issuance_enabled=True)
        app = AsyncMock()
        middleware = ChatProtectionMiddleware(app, ChatControls(config))
        scope = {'type': 'http', 'method': 'POST', 'path': '/internal/sessions', 'query_string': b'',
                 'headers': [(b'authorization', ('Bearer ' + 's' * 43).encode()), *headers],
                 'client': ('127.0.0.1', 1)}
        parts = iter(chunks)
        messages = []
        async def receive():
            if slow:
                await asyncio.sleep(1)
            return next(parts)
        async def send(message):
            messages.append(message)
        with patch('src.reliability.logger.info'):
            asyncio.run(middleware(scope, receive, send))
        app.assert_not_called()
        return next(m['status'] for m in messages if m['type'] == 'http.response.start')

    def test_chunked_overflow_with_false_short_content_length(self):
        self.assertEqual(self.run_request([
            {'type': 'http.request', 'body': b' ' * 150, 'more_body': True},
            {'type': 'http.request', 'body': b' ' * 150, 'more_body': False},
        ], [(b'content-length', b'2')]), 413)

    def test_duplicate_and_malformed_content_length_rejected(self):
        for headers in ([(b'content-length', b'2'), (b'content-length', b'2')],
                        [(b'content-length', b'invalid')]):
            self.assertEqual(self.run_request([], headers), 400)
        self.assertEqual(self.run_request([], [(b'content-length', b'9' * 5000)]), 413)

    def test_slow_body_upload_is_bounded_without_entering_app(self):
        timeout = asyncio.timeout
        with patch('src.reliability.asyncio.timeout', side_effect=lambda _: timeout(0.01)):
            self.assertEqual(self.run_request([], slow=True), 408)
