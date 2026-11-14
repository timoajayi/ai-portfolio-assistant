"""Durable usage tests: temporary local databases and fully mocked providers."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import hashlib
import importlib
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import BoundedSemaphore, Event
import time
from uuid import uuid4
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from src.config import Settings
from src.usage import SCHEMA, UsageDenied, UsageLedger, chat_usage, paid_call
from src.usage_admin import main as admin
from tests.offline import OfflineTestCase
from tests import test_deadline


class LedgerTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.now = datetime(2026, 11, 9, 23, 59, tzinfo=timezone.utc)
        self.ledger = UsageLedger(self.usage_path, clock=lambda: self.now)

    def test_initialization_is_explicit_disabled_and_private(self):
        path = Path(self.temporary) / 'new.sqlite3'
        ledger = UsageLedger(path)
        ledger.initialize()
        self.assertTrue(ledger.status()['disabled'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(UsageDenied):
            ledger.reserve()
        before = hashlib.sha256(path.read_bytes()).digest()
        with self.assertRaises(UsageDenied):
            ledger.initialize()
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_daily_limit_and_final_available_reservation(self):
        self.ledger.daily = 2
        for _ in range(2):
            self.ledger.release(self.ledger.reserve())
        with self.assertRaises(UsageDenied) as caught:
            self.ledger.reserve()
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 2)

    def test_monthly_limit_rolls_back_partial_daily_increment(self):
        self.ledger.monthly = 1
        self.ledger.release(self.ledger.reserve())
        self.now += timedelta(days=1)
        with self.assertRaises(UsageDenied):
            self.ledger.reserve()
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 0)
        self.assertEqual(self.ledger.status()['periods']['month']['admitted'], 1)

    def test_simultaneous_reservations_cannot_overrun_final_allowance(self):
        ledger = UsageLedger(self.usage_path, daily=1, concurrent=20, busy_ms=1000)
        def reserve(_):
            try:
                return ledger.reserve()
            except UsageDenied:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            result = list(pool.map(reserve, range(16)))
        self.assertEqual(sum(x is not None for x in result), 1)
        self.assertEqual(ledger.status()['active'], 1)

    def test_multiple_processes_share_atomic_allowance(self):
        code = '''
import sys
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
with ExitStack() as guards:
 for name in ('socket.create_connection','socket.getaddrinfo','socket.socket.connect','socket.socket.connect_ex'):
  guards.enter_context(patch(name,side_effect=AssertionError('Network disabled')))
 from src.usage import UsageLedger,UsageDenied
 try:
  UsageLedger(Path(sys.argv[1]),daily=3,concurrent=10,busy_ms=1000).reserve()
  print('admitted')
 except UsageDenied as error:
  print(error.category)
'''
        children = []
        try:
            for _ in range(8):
                children.append(subprocess.Popen([sys.executable, '-B', '-c', code, str(self.usage_path)],
                                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            results = []
            for child in children:
                output, errors = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, errors)
                results.append(output.strip())
            self.assertEqual(results.count('admitted'), 3)
            self.assertEqual(results.count('usage_budget'), 5)
            self.assertEqual(self.ledger.status()['active'], 3)
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.communicate()

    def test_concurrency_is_durable_and_release_is_idempotent(self):
        ledger = UsageLedger(self.usage_path, concurrent=1)
        identifier = ledger.reserve()
        restarted = UsageLedger(self.usage_path, concurrent=1)
        with self.assertRaises(UsageDenied) as caught:
            restarted.reserve()
        self.assertEqual(caught.exception.category, 'usage_capacity')
        restarted.release(identifier)
        restarted.release(identifier)
        self.assertEqual(restarted.status()['periods']['day']['admitted'], 1)
        restarted.release(restarted.reserve())

    def test_restart_does_not_reset_exhausted_budget(self):
        ledger = UsageLedger(self.usage_path, daily=1)
        ledger.release(ledger.reserve())
        with self.assertRaises(UsageDenied):
            UsageLedger(self.usage_path, daily=1).reserve()

    def test_utc_day_boundary_preserves_month_total(self):
        self.ledger.daily = 1
        self.ledger.release(self.ledger.reserve())
        self.now += timedelta(minutes=2)
        self.ledger.release(self.ledger.reserve())
        status = self.ledger.status()['periods']
        self.assertEqual(status['day']['admitted'], 1)
        self.assertEqual(status['month']['admitted'], 2)

    def test_month_boundary_and_timezone_conversion(self):
        self.now = datetime(2026, 12, 1, 0, 30, tzinfo=timezone(timedelta(hours=1)))
        self.ledger.monthly = 1
        self.ledger.release(self.ledger.reserve())  # November in UTC.
        self.now += timedelta(hours=1)
        self.ledger.release(self.ledger.reserve())
        self.assertEqual(self.ledger.status()['periods']['month']['admitted'], 1)

    def test_backward_clock_and_naive_dates_fail_closed(self):
        self.ledger.release(self.ledger.reserve())
        self.now -= timedelta(days=1)
        with self.assertRaises(UsageDenied):
            self.ledger.reserve()
        self.now = datetime(2026, 11, 9)
        with self.assertRaises(UsageDenied):
            self.ledger.reserve()

    def test_busy_wait_is_bounded_and_does_not_reserve(self):
        with sqlite3.connect(self.usage_path) as writer:
            writer.execute('BEGIN IMMEDIATE')
            started = time.monotonic()
            with self.assertRaises(UsageDenied):
                UsageLedger(self.usage_path, busy_ms=30).reserve()
            self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_missing_database_is_not_created(self):
        path = Path(self.temporary) / 'missing.sqlite3'
        with self.assertRaises(UsageDenied):
            UsageLedger(path).reserve()
        self.assertFalse(path.exists())

    def test_corrupt_and_empty_databases_fail_closed(self):
        for content in (b'', b'not a sqlite database'):
            path = Path(self.temporary) / 'bad.sqlite3'
            path.write_bytes(content)
            with self.assertRaises(UsageDenied):
                UsageLedger(path).reserve()

    def test_wrong_schema_fails_closed(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=999')
        with self.assertRaises(UsageDenied):
            self.ledger.reserve()

    def test_permission_failures_are_sanitized(self):
        self.usage_path.chmod(0o400)
        try:
            with self.assertRaises(UsageDenied):
                self.ledger.reserve()
        finally:
            self.usage_path.chmod(0o600)
        with patch('src.usage.sqlite3.connect', side_effect=PermissionError('PRIVATE-STORAGE-DETAIL')):
            with self.assertRaises(UsageDenied) as caught:
                self.ledger.reserve()
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_emergency_state_survives_restart_and_release(self):
        identifier = self.ledger.reserve()
        self.ledger.set_disabled(True)
        self.ledger.release(identifier)
        restarted = UsageLedger(self.usage_path)
        self.assertTrue(restarted.status()['disabled'])
        with self.assertRaises(UsageDenied):
            restarted.reserve()

    def test_emergency_blocks_second_provider_operation(self):
        embedding, generation = Mock(), Mock()
        with chat_usage(self.ledger):
            paid_call('embedding', embedding)
            self.ledger.set_disabled(True)
            with self.assertRaises(UsageDenied):
                paid_call('generation', generation)
        embedding.assert_called_once()
        generation.assert_not_called()
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_transactions_are_not_held_during_provider_work(self):
        def provider():
            self.assertEqual(UsageLedger(self.usage_path, busy_ms=1).status()['active'], 1)
            self.ledger.set_disabled(True)
        with chat_usage(self.ledger):
            paid_call('embedding', provider)

    def test_operation_accounting_and_no_repeated_operation(self):
        with chat_usage(self.ledger):
            paid_call('embedding', lambda: None)
            paid_call('generation', lambda: None)
            with self.assertRaises(UsageDenied):
                paid_call('generation', lambda: self.fail('Repeated provider call'))
        expected = {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1}
        self.assertEqual(self.ledger.status()['periods']['day'], expected)

    def test_provider_failure_is_never_refunded(self):
        with self.assertRaises(RuntimeError):
            with chat_usage(self.ledger):
                paid_call('generation', Mock(side_effect=RuntimeError('uncertain failure')))
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)
        self.assertEqual(self.ledger.status()['periods']['day']['generation_ops'], 1)
        self.assertEqual(self.ledger.status()['active'], 0)

    def test_recovery_requires_disabled_state_and_operator_confirmation(self):
        self.ledger.reserve()
        with self.assertRaises(UsageDenied):
            self.ledger.recover(workers_stopped=True)
        self.ledger.set_disabled(True)
        with self.assertRaises(UsageDenied):
            self.ledger.recover()
        self.ledger.recover(workers_stopped=True)
        self.assertEqual(self.ledger.status()['active'], 0)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_admin_commands_do_not_import_provider_or_read_dotenv(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(admin(['--database', str(self.usage_path), 'disable']), 0)
            self.assertEqual(admin(['--database', str(self.usage_path), 'status']), 0)
            self.assertEqual(admin(['--database', str(self.usage_path), 'enable']), 0)
        self.assertNotIn(str(self.usage_path), output.getvalue())
        self.client_factory.assert_not_called()
        self.dotenv.assert_not_called()

    def test_database_and_limits_configuration_are_validated(self):
        for name, value in (('USAGE_DAILY_LIMIT', '0'), ('USAGE_MONTHLY_LIMIT', '-1'),
                            ('USAGE_MAX_CONCURRENT', '0'), ('USAGE_SQLITE_BUSY_MS', '2001'),
                            ('USAGE_LEDGER_PATH', 'relative.sqlite3'),
                            ('USAGE_LEDGER_PATH', str(Path.cwd() / 'bad.sqlite3')),
                            ('USAGE_LEDGER_PATH', str(self.index_path.parent / 'bad.sqlite3'))):
            with patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError):
                    Settings.from_env()


class LedgerValidationTests(OfflineTestCase):
    """Storage tampering must deny admission without repairing or spending."""

    def rewrite_schema(self, transform):
        self.usage_path.unlink()
        with sqlite3.connect(self.usage_path) as db:
            for statement in SCHEMA:
                db.execute(transform(statement))
            db.execute("INSERT INTO control VALUES(1,0,'0001-01-01')")
            db.execute('PRAGMA user_version=1')

    def assert_storage_denied(self):
        before = self.usage_path.read_bytes()
        provider = Mock()
        with self.assertRaises(UsageDenied) as caught:
            with chat_usage(UsageLedger(self.usage_path)):
                paid_call('generation', provider)
        self.assertEqual(caught.exception.category, 'usage_storage')
        self.assertEqual(str(caught.exception), 'Paid operation unavailable.')
        provider.assert_not_called()
        self.assertEqual(self.usage_path.read_bytes(), before)
        # A fresh ledger object must not repair storage on restart.
        with self.assertRaises(UsageDenied):
            UsageLedger(self.usage_path).status()
        with self.assertRaises(UsageDenied):
            UsageLedger(self.usage_path).initialize()
        self.assertEqual(self.usage_path.read_bytes(), before)

    def test_supported_schema_and_formatting_remain_accepted(self):
        self.rewrite_schema(lambda sql: sql.replace('CREATE TABLE', 'create /* format */ table')
                            .replace('periods (', '"periods" (').replace(',', ',\n  '))
        ledger = UsageLedger(self.usage_path)
        with chat_usage(ledger):
            paid_call('generation', Mock())
        self.assertEqual(ledger.status()['periods']['day']['generation_ops'], 1)

    def test_missing_check_constraints_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace(' CHECK(admitted>=0)', ''))
        self.assert_storage_denied()

    def test_wrong_column_type_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace('admitted INTEGER', 'admitted REAL'))
        self.assert_storage_denied()

    def test_missing_not_null_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace('period TEXT NOT NULL', 'period TEXT'))
        self.assert_storage_denied()

    def test_missing_required_primary_key_index_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace(',\n        PRIMARY KEY(kind,period)', ''))
        self.assert_storage_denied()

    def test_unsupported_unique_constraint_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace('last_day TEXT NOT NULL', 'last_day TEXT NOT NULL UNIQUE'))
        self.assert_storage_denied()

    def test_unsupported_foreign_key_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace('last_day TEXT NOT NULL',
                                                    'last_day TEXT NOT NULL REFERENCES periods(period)'))
        self.assert_storage_denied()

    def test_wrong_default_rejected(self):
        self.rewrite_schema(lambda sql: sql.replace('DEFAULT 0', 'DEFAULT 1'))
        self.assert_storage_denied()

    def test_extra_trigger_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('CREATE TRIGGER tamper AFTER INSERT ON active BEGIN DELETE FROM active; END')
        self.assert_storage_denied()

    def test_wrong_schema_version_rejected_without_repair(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA user_version=2')
        self.assert_storage_denied()

    def mutate_period(self, column, value):
        ledger = UsageLedger(self.usage_path)
        ledger.release(ledger.reserve())
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute(f'UPDATE periods SET {column}=?', (value,))

    def test_negative_admission_counters_rejected(self):
        self.mutate_period('admitted', -10)
        self.assert_storage_denied()

    def test_negative_embedding_counters_rejected(self):
        self.mutate_period('embedding_ops', -1)
        self.assert_storage_denied()

    def test_negative_generation_counters_rejected(self):
        self.mutate_period('generation_ops', -1)
        self.assert_storage_denied()

    def test_nonintegral_counter_rejected(self):
        self.mutate_period('admitted', 1.5)
        self.assert_storage_denied()

    def test_provider_counter_exceeding_admissions_rejected(self):
        self.mutate_period('embedding_ops', 2)
        self.assert_storage_denied()

    def test_invalid_day_identifier_rejected(self):
        self.mutate_period('period', '2026-02-30')
        self.assert_storage_denied()

    def test_invalid_month_identifier_rejected(self):
        ledger = UsageLedger(self.usage_path)
        ledger.release(ledger.reserve())
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE periods SET period='2026-13' WHERE kind='month'")
        self.assert_storage_denied()

    def test_inconsistent_daily_monthly_totals_rejected(self):
        ledger = UsageLedger(self.usage_path)
        ledger.release(ledger.reserve())
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE periods SET admitted=2 WHERE kind='month'")
        self.assert_storage_denied()

    def test_missing_monthly_accounting_rejected(self):
        ledger = UsageLedger(self.usage_path)
        ledger.release(ledger.reserve())
        with sqlite3.connect(self.usage_path) as db:
            db.execute("DELETE FROM periods WHERE kind='month'")
        self.assert_storage_denied()

    def test_invalid_clock_watermark_rejected(self):
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE control SET last_day='2026-11-09'")
        self.assert_storage_denied()

    def test_invalid_reservation_identifier_rejected(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE active SET id='not-a-reservation'")
        self.assert_storage_denied()

    def test_invalid_active_flag_rejected(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('PRAGMA ignore_check_constraints=ON')
            db.execute('UPDATE active SET generation_ops=-1')
        self.assert_storage_denied()

    def test_reservation_month_must_match_its_day(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute("UPDATE active SET month='2026-01'")
        self.assert_storage_denied()

    def test_orphan_reservation_rejected(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DELETE FROM periods')
            db.execute("UPDATE control SET last_day='0001-01-01'")
        self.assert_storage_denied()

    def test_active_count_exceeding_admissions_rejected(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('INSERT INTO active SELECT ?,day,month,0,0 FROM active', (uuid4().hex,))
        self.assert_storage_denied()

    def test_active_operations_exceeding_counters_rejected(self):
        UsageLedger(self.usage_path).reserve()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('UPDATE active SET embedding_ops=1')
        self.assert_storage_denied()

    def test_lowered_limits_do_not_invalidate_existing_state(self):
        ledger = UsageLedger(self.usage_path)
        first, second = ledger.reserve(), ledger.reserve()
        lowered = UsageLedger(self.usage_path, daily=1, monthly=1, concurrent=1)
        self.assertEqual(lowered.status()['active'], 2)
        with self.assertRaises(UsageDenied) as caught:
            lowered.reserve()
        self.assertEqual(caught.exception.category, 'usage_capacity')
        ledger.release(first)
        ledger.release(second)
        with self.assertRaises(UsageDenied) as caught:
            lowered.reserve()
        self.assertEqual(caught.exception.category, 'usage_budget')

    def test_large_valid_history_and_bounded_validation_work(self):
        start = date(2025, 1, 1)
        totals = {}
        with sqlite3.connect(self.usage_path) as db:
            for offset in range(200):
                day = (start + timedelta(days=offset)).isoformat()
                totals[day[:7]] = totals.get(day[:7], 0) + 1
                db.execute("INSERT INTO periods VALUES('day',?,1,1,1)", (day,))
            for month, count in totals.items():
                db.execute("INSERT INTO periods VALUES('month',?,?,?,?)", (month, count, count, count))
            db.execute('UPDATE control SET last_day=?', (day,))
        self.assertFalse(UsageLedger(self.usage_path).status()['disabled'])
        with patch('src.usage.VALIDATION_MAX_STEPS', 1000):
            self.assert_storage_denied()


class UsageAPITests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.legacy_headers = self.authorize_legacy_staging(self.api)
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))

    def post(self, **kwargs):
        kwargs.setdefault('headers', self.legacy_headers)
        return self.http.post('/chat', json={'message': 'Docker?'}, **kwargs)

    def assert_no_provider_work(self):
        self.client_factory.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.models.embed_content.assert_not_called()

    def test_disabled_chat_never_initializes_provider(self):
        self.usage_ledger.set_disabled(True)
        response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'detail': 'The AI assistant could not generate a response.'})
        self.assert_no_provider_work()

    def test_budget_exhaustion_never_initializes_provider(self):
        ledger = UsageLedger(self.usage_path)
        for _ in range(100):
            ledger.release(ledger.reserve())
        self.assertEqual(self.post().status_code, 429)
        self.assert_no_provider_work()

    def test_missing_ledger_returns_safe_error_without_recreation(self):
        self.usage_path.unlink()
        self.assertEqual(self.post().status_code, 503)
        self.assertFalse(self.usage_path.exists())
        self.assert_no_provider_work()

    def test_authenticated_chat_rejects_original_malformed_storage(self):
        self.controls.settings = replace(self.controls.settings, staging_auth_enabled=True,
                                         staging_auth_token='x' * 43)
        day = datetime.now(timezone.utc).date().isoformat()
        with sqlite3.connect(self.usage_path) as db:
            db.execute('DROP TABLE periods')
            db.execute('CREATE TABLE periods (kind TEXT, period TEXT, admitted INTEGER, '
                       'embedding_ops INTEGER, generation_ops INTEGER, PRIMARY KEY(kind,period))')
            db.executemany('INSERT INTO periods VALUES(?,?,-10,0,0)',
                           [('day', day), ('month', day[:7])])
        before = self.usage_path.read_bytes()
        response = self.post(headers={'Authorization': 'Bearer ' + 'x' * 43})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'detail': 'The AI assistant could not generate a response.'})
        self.assert_no_provider_work()
        self.assertEqual(self.usage_path.read_bytes(), before)
        self.assertNotIn('xxxx', str(self.logs.call_args_list))

    def test_unrelated_rate_and_body_failures_do_not_spend_allowance(self):
        self.controls.settings = replace(self.controls.settings, max_body_bytes=1)
        self.assertEqual(self.post().status_code, 413)
        self.assertEqual(self.usage_ledger.status()['periods']['day']['admitted'], 0)
        self.assert_no_provider_work()

    def test_staging_authentication_precedes_usage_admission(self):
        self.controls.settings = replace(
            self.controls.settings, staging_auth_enabled=True, staging_auth_token='x' * 43)
        self.assertEqual(self.post().status_code, 401)
        self.assertEqual(self.usage_ledger.status()['periods']['day']['admitted'], 0)
        self.assert_no_provider_work()

    def test_global_concurrency_rejects_before_provider(self):
        for _ in range(2):
            self.usage_ledger.reserve()
        self.assertEqual(self.post().status_code, 503)
        self.assert_no_provider_work()

    def test_provider_timeout_keeps_spent_counters(self):
        self.models.generate_content.side_effect = TimeoutError('PRIVATE-ERROR')
        self.assertEqual(self.post().status_code, 504)
        status = self.usage_ledger.status()
        self.assertEqual(status['periods']['day'], {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1})
        self.assertEqual(status['active'], 0)
        self.assertNotIn('PRIVATE-ERROR', str(self.logs.call_args_list))

    def test_success_accounts_both_operations_once(self):
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1})

    def test_collection_query_accounts_only_actual_generation_attempt(self):
        self.assertEqual(self.http.post('/chat', json={'message': 'Show me all projects'}, headers=self.legacy_headers).status_code, 200)
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 0, 'generation_ops': 1})

    def test_alternate_embedding_and_cli_paths_cannot_bypass_disabled_ledger(self):
        self.usage_ledger.set_disabled(True)
        embeddings = self.load('src.embeddings')
        cli = importlib.import_module('src.main')
        with self.assertRaises(UsageDenied):
            embeddings.create_embedding('Synthetic document')
        with self.assertRaises(UsageDenied):
            cli.generate_answer('Synthetic CLI message')
        self.assert_no_provider_work()

    def test_standalone_query_embedding_is_accounted(self):
        embeddings = self.load('src.embeddings')
        embeddings.create_embedding('Synthetic question', task_type='RETRIEVAL_QUERY')
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 0})

    def test_direct_retrieval_and_document_helper_cannot_bypass_disable(self):
        self.usage_ledger.set_disabled(True)
        retrieval = self.load('src.retrieval')
        with self.assertRaises(UsageDenied):
            retrieval.retrieve_relevant_chunks('Docker?', index=self.api.app.state.rag_index)
        with self.assertRaises(UsageDenied):
            retrieval.build_portfolio_index(['Synthetic document'])
        self.assert_no_provider_work()

    def test_cli_generation_is_accounted_and_not_retried(self):
        cli = importlib.import_module('src.main')
        cli.generate_answer('Synthetic CLI question')
        self.models.generate_content.assert_called_once()
        self.assertEqual(self.client_factory.call_args.kwargs['http_options'].retry_options.attempts, 1)
        self.assertFalse(self.models.generate_content.call_args.kwargs['config']['automatic_continuation'])
        self.assertEqual(self.usage_ledger.status()['periods']['day'],
                         {'admitted': 1, 'embedding_ops': 0, 'generation_ops': 1})

    def test_failed_release_retains_reservation_without_refund(self):
        with patch.object(UsageLedger, 'release', side_effect=UsageDenied()):
            self.assertEqual(self.post().status_code, 503)
        status = self.usage_ledger.status()
        self.assertEqual(status['active'], 1)
        self.assertEqual(status['periods']['day']['admitted'], 1)
        self.assertTrue(self.controls.capacity.acquire(blocking=False))
        self.controls.capacity.release()

    def test_ledger_never_stores_request_or_provider_content(self):
        marker = 'PRIVATE-VISITOR-CONTENT-6B3'
        self.http.post('/chat', json={'message': marker}, headers=self.legacy_headers)
        stored = self.usage_path.read_bytes()
        for value in (marker, 'Offline test answer.', 'offline-test-key-not-a-secret'):
            self.assertNotIn(value.encode(), stored)
            self.assertNotIn(value, str(self.logs.call_args_list))

    def test_emergency_disable_between_embedding_and_generation(self):
        def embedding(**kwargs):
            self.usage_ledger.set_disabled(True)
            return self.models.embed_content.return_value
        self.models.embed_content.side_effect = embedding
        self.assertEqual(self.post().status_code, 503)
        self.models.generate_content.assert_not_called()

    def test_no_transaction_or_client_content_in_storage_failure(self):
        with patch('src.usage.sqlite3.connect', side_effect=sqlite3.OperationalError('PRIVATE-SQL-KEY')):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('PRIVATE', response.text + str(self.logs.call_args_list))
        self.assert_no_provider_work()

    available = test_deadline.DeadlineTests.available
    wait_until = test_deadline.DeadlineTests.wait_until

    def test_http_deadline_does_not_release_durable_slot_before_worker(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)
        def embedding(**kwargs):
            self.assertEqual(self.usage_ledger.status()['active'], 1)
            self.assertTrue(finish.wait(3))
            return self.models.embed_content.return_value
        finish = Event()
        self.models.embed_content.side_effect = embedding
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.post)
            try:
                response = future.result(timeout=1)
                self.assertEqual(response.status_code, 504)
                self.assertEqual(self.usage_ledger.status()['active'], 1)
                self.assertEqual(self.usage_ledger.status()['periods']['day']['admitted'], 1)
                self.assertFalse(self.available())
            finally:
                finish.set()
        self.wait_until(self.available)
        self.assertEqual(self.usage_ledger.status()['active'], 0)
        self.models.generate_content.assert_not_called()

    def test_ledger_lock_wait_does_not_postpone_http_deadline(self):
        self.controls.settings = replace(self.controls.settings, chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)
        with sqlite3.connect(self.usage_path) as writer:
            writer.execute('BEGIN IMMEDIATE')
            with ThreadPoolExecutor(max_workers=1) as pool:
                response = pool.submit(self.post).result(timeout=0.8)
                self.assertEqual(response.status_code, 504)
                self.assertFalse(self.available())
                self.wait_until(self.available)  # Finite SQLite busy wait, while writer still owns the lock.
        self.assert_no_provider_work()
        self.assertEqual(self.usage_ledger.status()['active'], 0)
