"""Internal session chat only: no HTTP route or trusted ingress is simulated."""

import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
from threading import Event, BoundedSemaphore
from unittest.mock import patch

import anyio
from fastapi.testclient import TestClient

from src.config import Settings
from src.identity import TrustedIP
from src.reliability import RateLimiter
from src.session_chat import SessionChatService
from tests.offline import OfflineTestCase
from tests.test_ip_admission import IPFixture


class InternalChatTests(IPFixture):
    def setUp(self):
        super().setUp()
        self.ledger.set_disabled(True)
        self.ledger.migrate_verification(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.settings = replace(self.settings, session_chat_enabled=True)
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.controls.settings = self.settings
        self.controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.controls.rate_limiter = RateLimiter(1000, 60, 1)
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))
        self.service = SessionChatService(self.settings, self.controls, self.api.app, self.api.ChatRequest, self.api._chat_worker)
        self.gateway = {**self.scope, 'path': '/internal/session-chat', 'http_version': '1.1',
                        'headers': [*self.scope['headers'], (b'content-type', b'application/json')]}

    async def stream(self, value):
        yield json.dumps(value).encode()

    def run_chat(self, *, scope=None, value=None, identity=None):
        return asyncio.run(self.service.run(self.gateway if scope is None else scope,
                           self.stream({'message': 'What is BundesHost?'} if value is None else value),
                           identity=self.identity if identity is None else identity))

    def no_provider(self):
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()

    def reset_providers(self):
        self.client_factory.reset_mock()
        self.models.reset_mock(side_effect=True)

    def configure(self, **changes):
        self.settings = replace(self.settings, **changes)
        self.controls.settings = self.settings
        self.service.settings = self.settings

    def test_http_route_absent_even_when_internal_feature_enabled(self):
        self.assertNotIn('/internal/session-chat', {route.path for route in self.api.app.routes})
        headers = {'Authorization': 'Bearer ' + 's' * 43, 'X-Portfolio-Session': self.raw,
                   'X-Forwarded-For': '192.0.2.10'}
        self.assertEqual(self.http.post('/internal/session-chat', json={'message': 'Docker?'}, headers=headers).status_code, 404)
        self.no_provider()

    def test_disabled_by_default_and_other_feature_guards(self):
        self.assertFalse(Settings().session_chat_enabled)
        original = self.settings
        for name in ('session_chat_enabled', 'staging_auth_enabled', 'session_admission_enabled', 'ip_admission_enabled'):
            self.configure(**{name: False})
            self.assertEqual(self.run_chat().status, 503)
            self.configure(**{name: getattr(original, name)})
        self.no_provider()

    def test_missing_invalid_or_duplicate_bearer(self):
        for headers in (self.gateway['headers'][1:], [(b'authorization', b'Bearer ' + b'w' * 43), *self.gateway['headers'][1:]],
                        [self.gateway['headers'][0], *self.gateway['headers']]):
            result = self.run_chat(scope={**self.gateway, 'headers': headers})
            self.assertEqual(result.status, 401)
        self.no_provider()

    def test_missing_invalid_duplicate_or_malformed_session(self):
        auth, session, content = self.gateway['headers']
        for headers in ([auth, content], [auth, (b'x-portfolio-session', b'invalid'), content],
                        [auth, session, session, content], [auth, (b'x-portfolio-session', b'x' * 43), content]):
            self.assertEqual(self.run_chat(scope={**self.gateway, 'headers': headers}).status, 401)
        self.no_provider()

    def test_unknown_session_rejected(self):
        import base64
        token = base64.urlsafe_b64encode(b'x' * 32).rstrip(b'=')
        scope = {**self.gateway, 'headers': [self.gateway['headers'][0], (b'x-portfolio-session', token), self.gateway['headers'][2]]}
        self.assertEqual(self.run_chat(scope=scope).status, 401)
        self.no_provider()

    def test_expired_revoked_and_unverified_sessions(self):
        self.now += timedelta(hours=4)
        self.assertEqual(self.run_chat().status, 401)
        self.now -= timedelta(hours=4)
        import sqlite3
        with sqlite3.connect(self.usage_path) as db: db.execute('UPDATE sessions SET verified=0')
        self.assertEqual(self.run_chat().status, 401)
        with sqlite3.connect(self.usage_path) as db: db.execute('UPDATE sessions SET verified=1')
        self.ledger.revoke_session(self.session)
        self.assertEqual(self.run_chat().status, 401)
        self.no_provider()

    def test_no_identity_from_peer_or_forwarded_headers(self):
        async def run():
            scope = {**self.gateway, 'client': ('192.0.2.10', 123), 'headers': [*self.gateway['headers'],
                     (b'x-forwarded-for', b'192.0.2.10'), (b'x-real-ip', b'192.0.2.10'),
                     (b'cf-connecting-ip', b'192.0.2.10'), (b'x-identity-digest', b'x' * 64)]}
            for supplied in (None, '192.0.2.10', {'ip': '192.0.2.10'}, b'x' * 32):
                result = await self.service.run(scope, self.stream({'message': 'Docker?'}), identity=supplied)
                self.assertEqual(result.status, 401)
        asyncio.run(run())
        self.no_provider()

    def test_strict_request_contract_and_no_echo(self):
        for value in ({'message': ''}, {'message': ' '}, {'message': 123}, {'message': 'x' * 1001},
                      {'message': 'PRIVATE-CONTENT', 'verified': True}, {'message': 'Docker?', 'ip': '192.0.2.10'}):
            result = self.run_chat(value=value)
            self.assertEqual(result.status, 422)
            self.assertNotIn('PRIVATE-CONTENT', str(result.body))
        for changes, status in (({'method': 'GET'}, 405), ({'query_string': b'ip=192.0.2.10'}, 403),
                                ({'headers': [*self.gateway['headers'], (b'origin', b'https://example.test')]}, 403),
                                ({'headers': self.gateway['headers'][:2]}, 415)):
            self.assertEqual(self.run_chat(scope={**self.gateway, **changes}).status, status)
        self.no_provider()

    def test_stream_body_limit_malformed_json_and_duplicate_fields(self):
        async def run():
            async def chunks():
                yield b'x' * 4096
                yield b'x' * 4097
            result = await self.service.run(self.gateway, chunks(), identity=self.identity)
            self.assertEqual(result.status, 413)
            for body in (b'not-json', b'{"message":"one","message":"two"}'):
                async def data(): yield body
                self.assertEqual((await self.service.run(self.gateway, data(), identity=self.identity)).status, 422)
        asyncio.run(run())
        self.no_provider()

    def test_success_reuses_rag_and_counts_both_provider_attempts(self):
        result = self.run_chat()
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(result.body, {'answer': 'Offline test answer.'})
        self.assertEqual(result.headers['cache-control'], 'no-store')
        self.models.embed_content.assert_called_once()
        self.models.generate_content.assert_called_once()
        self.assertEqual(self.ledger.status()['periods']['day'], {'admitted': 1, 'embedding_ops': 1, 'generation_ops': 1})
        rows = self.rows()
        self.assertEqual(len(rows['ip_events']), 1)
        self.assertEqual(len(rows['session_events']), 1)
        self.assertEqual(len(rows['active']), 0)

    def test_project_collection_keeps_existing_retrieval_behavior(self):
        result = self.run_chat(value={'message': 'Show me all projects'})
        self.assertEqual(result.status, 200)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_called_once()

    def test_session_and_ip_limits_reject_without_more_provider_work(self):
        for _ in range(3): self.assertEqual(self.run_chat().status, 200)
        self.reset_providers()
        self.assertEqual(self.run_chat().status, 429)
        self.no_provider()
        self.configure(ip_admission_minute_limit=1)
        scope = self.scope_for(99)
        scope = {**self.gateway, 'headers': [*scope['headers'], (b'content-type', b'application/json')]}
        self.assertEqual(self.run_chat(scope=scope).status, 429)
        self.no_provider()

    def test_global_budgets_concurrency_and_emergency_preserved(self):
        self.ledger.daily = 1
        self.assertEqual(self.run_chat().status, 200)
        self.reset_providers()
        self.assertEqual(self.run_chat().status, 429)
        self.ledger.daily, self.ledger.monthly = 100, 1
        self.assertEqual(self.run_chat().status, 429)
        self.ledger.monthly = 1000
        self.ledger.reserve(); self.ledger.reserve()
        self.assertEqual(self.run_chat().status, 503)
        self.ledger.set_disabled(True)
        self.assertEqual(self.run_chat().status, 503)
        self.no_provider()

    def test_database_missing_corrupt_or_locked_fails_before_provider(self):
        import sqlite3
        self.ledger.busy_ms = 20
        with sqlite3.connect(self.usage_path) as db:
            db.execute('BEGIN IMMEDIATE')
            self.assertEqual(self.run_chat().status, 503)
        self.usage_path.unlink()
        self.assertEqual(self.run_chat().status, 503)
        self.assertFalse(self.usage_path.exists())
        self.usage_path.write_bytes(b'not-sqlite')
        self.assertEqual(self.run_chat().status, 503)
        self.no_provider()

    def test_provider_timeout_and_failure_remain_sanitized_without_refund(self):
        self.models.generate_content.side_effect = TimeoutError('PRIVATE-PROVIDER-CONTENT')
        result = self.run_chat()
        self.assertEqual(result.status, 504)
        self.assertEqual(result.body, {'detail': self.api.ERROR_DETAIL})
        self.assertNotIn('PRIVATE', str(result.body) + str(self.logs.call_args_list))
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_output_bound_and_generation_config_preserved(self):
        self.models.generate_content.return_value.text = 'x' * 65537
        result = self.run_chat()
        self.assertEqual(result.status, 502)
        self.assertNotIn('x' * 100, str(result.body))
        config = self.models.generate_content.call_args.kwargs['config']
        self.assertFalse(config['automatic_continuation'])
        self.assertEqual(config['max_output_tokens'], self.api.settings.max_output_tokens)
        self.assertEqual(config['thinking_config']['thinking_level'], self.api.settings.thinking_level)

    def test_overall_deadline_returns_before_worker_and_preserves_both_slots(self):
        self.configure(chat_deadline_seconds=0.05)
        self.controls.capacity = BoundedSemaphore(1)
        started, finish, exited = Event(), Event(), Event()
        vector = self.models.embed_content.return_value
        def embedding(**kwargs):
            started.set()
            try: self.assertTrue(finish.wait(3))
            finally: exited.set()
            return vector
        self.models.embed_content.side_effect = embedding
        async def run():
            try:
                result = await self.service.run(self.gateway, self.stream({'message': 'Docker?'}), identity=self.identity)
                self.assertEqual(result.status, 504)
                self.assertTrue(started.is_set())
                self.assertFalse(exited.is_set())
                self.assertEqual(self.ledger.status()['active'], 1)
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally: finish.set()
            for _ in range(100):
                if self.ledger.status()['active'] == 0 and not self.controls.tasks: break
                await asyncio.sleep(0.01)
            self.assertEqual(self.ledger.status()['active'], 0)
            self.assertTrue(self.controls.capacity.acquire(blocking=False))
            self.controls.capacity.release()
        asyncio.run(run())
        self.models.generate_content.assert_not_called()

    def test_cancellation_holds_capacity_until_actual_worker_exit(self):
        started, finish = Event(), Event()
        self.controls.capacity = BoundedSemaphore(1)
        vector = self.models.embed_content.return_value
        def embedding(**kwargs):
            started.set()
            self.assertTrue(finish.wait(3))
            return vector
        self.models.embed_content.side_effect = embedding
        async def run():
            task = asyncio.create_task(self.service.run(self.gateway, self.stream({'message': 'Docker?'}), identity=self.identity))
            try:
                for _ in range(100):
                    if started.is_set(): break
                    await asyncio.sleep(0.01)
                self.assertTrue(started.is_set())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError): await task
                self.assertEqual(self.ledger.status()['active'], 1)
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally: finish.set()
            for _ in range(100):
                if not self.controls.tasks and self.ledger.status()['active'] == 0: break
                await asyncio.sleep(0.01)
            self.assertEqual(self.ledger.status()['active'], 0)
        asyncio.run(run())
        self.models.generate_content.assert_not_called()

    def test_slow_upload_is_supervised_before_admission(self):
        self.configure(chat_deadline_seconds=0.02)
        async def chunks():
            await asyncio.sleep(1)
            yield b'{}'
        result = asyncio.run(self.service.run(self.gateway, chunks(), identity=self.identity))
        self.assertEqual(result.status, 504)
        self.assertEqual(self.rows()['ip_events'], [])
        self.no_provider()

    def test_worker_pool_delay_cannot_start_paid_work_after_deadline(self):
        self.configure(chat_deadline_seconds=0.02)
        entered, finish = Event(), Event()
        def occupy():
            entered.set()
            self.assertTrue(finish.wait(3))
        async def run():
            limiter = anyio.to_thread.current_default_thread_limiter()
            old = limiter.total_tokens
            limiter.total_tokens = 1
            blocker = asyncio.create_task(anyio.to_thread.run_sync(occupy))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(0.01)
                self.assertTrue(entered.is_set())
                result = await self.service.run(self.gateway, self.stream({'message': 'Docker?'}), identity=self.identity)
                self.assertEqual(result.status, 504)
            finally:
                finish.set()
                await blocker
                limiter.total_tokens = old
            for _ in range(100):
                if not self.controls.tasks: break
                await asyncio.sleep(0.01)
        asyncio.run(run())
        self.assertEqual(self.rows()['ip_events'], [])
        self.no_provider()

    def test_existing_process_rate_and_capacity_controls_still_reject(self):
        self.controls.capacity = BoundedSemaphore(1)
        self.controls.capacity.acquire()
        self.assertEqual(self.run_chat().status, 503)
        self.controls.capacity.release()
        self.no_provider()
        self.controls.rate_limiter = RateLimiter(1, 60, 1)
        self.assertEqual(self.run_chat().status, 200)
        self.reset_providers()
        self.assertEqual(self.run_chat().status, 429)
        self.no_provider()

    def test_distinct_sessions_compete_for_one_ip_allowance(self):
        self.configure(ip_admission_minute_limit=1)
        scopes = [{**self.gateway, 'headers': [*self.scope_for(i + 100)['headers'],
                  (b'content-type', b'application/json')]} for i in range(8)]
        async def run():
            return await asyncio.gather(*(self.service.run(scope, self.stream({'message': 'Docker?'}),
                                         identity=self.identity) for scope in scopes))
        results = asyncio.run(run())
        self.assertEqual(sum(r.status == 200 for r in results), 1)
        self.assertEqual(len(self.rows()['ip_events']), 1)
        self.assertEqual(self.models.generate_content.call_count, 1)

    def test_parallel_final_session_slot_and_distinct_sessions(self):
        for _ in range(2): self.assertEqual(self.run_chat().status, 200)
        async def run():
            return await asyncio.gather(*(self.service.run(self.gateway, self.stream({'message': 'Docker?'}),
                                         identity=self.identity) for _ in range(8)))
        results = asyncio.run(run())
        self.assertEqual(sum(result.status == 200 for result in results), 1)
        self.assertEqual(len(self.rows()['ip_events']), 3)

    def test_no_tokens_credentials_or_messages_in_logs(self):
        result = self.run_chat(value={'message': 'PRIVATE-VISITOR-MESSAGE'})
        self.assertEqual(result.status, 200)
        for value in (self.raw, 's' * 43, self.key_text, 'PRIVATE-VISITOR-MESSAGE'):
            self.assertNotIn(value, str(self.logs.call_args_list) + str(result.body) + str(result.headers))

    def test_legacy_chat_still_uses_only_original_global_admission(self):
        headers = self.authorize_legacy_staging(self.api, token='s' * 43)
        response = self.http.post('/chat', json={'message': 'Show me all projects'}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'answer': 'Offline test answer.'})
        self.assertEqual(self.rows()['ip_events'], [])
        self.assertEqual(self.rows()['session_events'], [])


class SessionChatConfigurationTests(OfflineTestCase):
    def test_missing_flag_is_disabled_and_only_exact_true_accepted(self):
        with patch.dict(os.environ, {}, clear=True): self.assertFalse(Settings.from_env().session_chat_enabled)
        for value in ('TRUE', ' true', '1', 'private-invalid'):
            with patch.dict(os.environ, {'SESSION_CHAT_ENABLED': value}):
                with self.assertRaises(ValueError) as caught: Settings.from_env()
                self.assertNotIn(value, str(caught.exception))

    def test_enabling_without_authenticated_session_ip_policy_fails_closed(self):
        with patch.dict(os.environ, {'SESSION_CHAT_ENABLED': 'true'}):
            with self.assertRaises(ValueError): Settings.from_env()
