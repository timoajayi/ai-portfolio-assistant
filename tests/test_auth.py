"""Capability isolation tests use synthetic credentials and temporary ledgers."""

import asyncio
from dataclasses import replace
import hashlib
import os
from uuid import uuid4
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.auth import (AuthenticatedPrincipal, AuthorizationError, Capability, Mechanism,
                      ROUTE_CAPABILITIES, authenticate, validate_configuration)
from src.config import Settings
from src.reliability import RateLimiter
from src.session_chat import SessionChatService
from tests.offline import OfflineTestCase
from tests.test_bot_verification import BotFixture


def configuration(settings):
    return replace(settings, capability_auth_enabled=True, staging_auth_enabled=True,
                   staging_auth_token='s' * 43, verified_session_auth_token='i' * 43,
                   session_chat_auth_token='c' * 43)


def scope(path='/internal/verified-sessions', token='i' * 43, method='POST'):
    return {'type': 'http', 'method': method, 'path': path, 'raw_path': path.encode(),
            'query_string': b'', 'headers': [(b'authorization', ('Bearer ' + token).encode())],
            'state': {'request_id': uuid4().hex}}


class CapabilityUnitTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.settings = configuration(Settings.from_env())

    def test_correct_capabilities_for_exact_route_matrix(self):
        tokens = {Capability.VERIFIED_SESSION_ISSUANCE: 'i' * 43, Capability.SESSION_CHAT: 'c' * 43,
                  Capability.LEGACY_STAGING: 's' * 43}
        for (method, path), capability in ROUTE_CAPABILITIES.items():
            with self.subTest(method=method, path=path):
                principal = authenticate(self.settings, scope(path, tokens[capability], method))
                self.assertIs(principal.capability, capability)
                self.assertIs(principal.mechanism, Mechanism.BEARER)

    def test_wrong_capabilities_and_no_legacy_fallback(self):
        paths = ('/internal/verified-sessions', '/internal/session-chat', '/chat', '/internal/sessions')
        for path in paths:
            correct = 'i' if path == paths[0] else 'c' if path == paths[1] else 's'
            for token in ('i', 'c', 's'):
                if token != correct:
                    with self.assertRaises(AuthorizationError): authenticate(self.settings, scope(path, token * 43))

    def test_missing_malformed_duplicate_and_combined_authorization(self):
        for headers in ([], [(b'authorization', b'Basic invalid')], [(b'authorization', b'Bearer short')],
                        [(b'authorization', b'Bearer ' + b'i' * 43 + b', Bearer ' + b'i' * 43)],
                        [(b'authorization', b'Bearer ' + b'i' * 43), (b'Authorization', b'Bearer ' + b'i' * 43)],
                        [(b'authorization', b'Bearer  ' + b'i' * 43)], [(b'authorization', b'Bearer ' + b'i' * 43 + b' ')],
                        [(b'authorization', b'Bearer ' + b'\xff' * 43)]):
            request = scope()
            request['headers'] = headers
            with self.assertRaises(AuthorizationError) as caught: authenticate(self.settings, request)
            self.assertEqual(str(caught.exception), 'Unauthorized.')

    def test_no_method_path_query_or_encoded_alias_authorization(self):
        for changes in ({'method': 'GET'}, {'method': 'HEAD'}, {'method': 'OPTIONS'},
                        {'path': '/internal/verified-sessions/'}, {'path': '//internal/verified-sessions'},
                        {'path': '/internal/./verified-sessions'}, {'query_string': b'x=1'},
                        {'raw_path': b'/internal/%76erified-sessions'}, {'root_path': '/prefix'},
                        {'path': '/internal\\verified-sessions'}, {'path': '/admin'},
                        {'path': '/internal/usage/enable'}):
            request = {**scope(), **changes}
            with self.assertRaises(AuthorizationError): authenticate(self.settings, request)

    def test_no_wildcard_for_unknown_routes_or_administration(self):
        for path in ('/', '/future-paid-route', '/admin', '/usage_admin', '/internal/migrate-v5', '/internal/sessions/disable'):
            for token in ('i', 'c', 's'):
                with self.assertRaises(AuthorizationError): authenticate(self.settings, scope(path, token * 43))

    def test_capability_selection_headers_are_ignored(self):
        request = scope('/internal/session-chat', 's' * 43)
        request['headers'] += [(b'x-capability', b'session_chat'), (b'x-credential-id', b'session-chat-v1'),
                               (b'x-principal', b'authenticated')]
        with self.assertRaises(AuthorizationError): authenticate(self.settings, request)
        with self.assertRaises(AuthorizationError): authenticate(self.settings, scope(), required='verified_session_issuance')

    def test_principal_has_no_raw_credential_and_binds_context(self):
        request = scope()
        principal = authenticate(self.settings, request)
        self.assertIs(authenticate(self.settings, request, principal=principal), principal)
        for token in ('i' * 43, 's' * 43, 'c' * 43):
            self.assertNotIn(token, repr(principal))
            self.assertNotIn(token, repr(vars(principal)))
        self.assertEqual(principal.request_id, request['state']['request_id'])
        with self.assertRaises(AuthorizationError): authenticate(self.settings, scope(), principal=principal)
        request['state']['request_id'] = uuid4().hex
        with self.assertRaises(AuthorizationError): authenticate(self.settings, request, principal=principal)

    def test_principal_cannot_be_constructed_from_client_values(self):
        with self.assertRaises(TypeError): AuthenticatedPrincipal(capability=Capability.SESSION_CHAT)
        request = scope()
        for forged in ({'capability': 'verified_session_issuance'}, AuthenticatedPrincipal()):
            with self.assertRaises(AuthorizationError): authenticate(self.settings, request, principal=forged)

    def test_credential_rotation_rejects_old_credentials_and_principals(self):
        request = scope()
        principal = authenticate(self.settings, request)
        rotated = replace(self.settings, verified_session_auth_token='n' * 43, verified_session_credential_id='verified-session-v2')
        with self.assertRaises(AuthorizationError): authenticate(rotated, request)
        request['headers'] = [(b'authorization', b'Bearer ' + b'n' * 43)]
        with self.assertRaises(AuthorizationError): authenticate(rotated, request, principal=principal)
        self.assertEqual(authenticate(rotated, request).credential_id, 'verified-session-v2')

    def test_constant_time_comparison_is_used(self):
        import secrets
        with patch('src.auth.secrets.compare_digest', wraps=secrets.compare_digest) as compare:
            authenticate(self.settings, scope())
        self.assertTrue(any(call.args == (b'i' * 43, b'i' * 43) for call in compare.call_args_list))

    def test_missing_invalid_equal_or_injected_config_fails_closed(self):
        for changes in ({'verified_session_auth_token': ''}, {'session_chat_auth_token': ''},
                        {'session_chat_auth_token': 'short'}, {'verified_session_auth_token': 's' * 43},
                        {'session_chat_auth_token': 'i' * 43}, {'staging_auth_enabled': False},
                        {'capability_auth_enabled': 'true'}, {'session_chat_credential_id': 'verified-session-v1'}):
            with self.assertRaises(AuthorizationError) as caught:
                authenticate(replace(self.settings, **changes), scope())
            self.assertEqual(str(caught.exception), 'Unauthorized.')


class CapabilityConfigurationTests(OfflineTestCase):
    def test_disabled_default_preserves_staging_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(Settings.from_env().capability_auth_enabled)
        self.assertFalse(Settings.from_env().capability_auth_enabled)

    def test_exact_flag_and_required_independent_credentials(self):
        for value in ('true', 'TRUE', ' true', '1'):
            with patch.dict(os.environ, {'CAPABILITY_AUTH_ENABLED': value}):
                with self.assertRaises(ValueError): Settings.from_env()
        values = {'CAPABILITY_AUTH_ENABLED': 'true', 'STAGING_AUTH_ENABLED': 'true', 'STAGING_AUTH_TOKEN': 's' * 43,
                  'VERIFIED_SESSION_AUTH_TOKEN': 'i' * 43, 'SESSION_CHAT_AUTH_TOKEN': 'c' * 43}
        with patch.dict(os.environ, values):
            settings = Settings.from_env()
            self.assertTrue(settings.capability_auth_enabled)
            for token in ('s' * 43, 'i' * 43, 'c' * 43): self.assertNotIn(token, repr(settings))
            for changes in ({'SESSION_CHAT_AUTH_TOKEN': 'i' * 43}, {'VERIFIED_SESSION_AUTH_TOKEN': 's' * 43},
                            {'SESSION_CHAT_AUTH_TOKEN': 'PRIVATE-INVALID'}, {'VERIFIED_SESSION_CREDENTIAL_ID': 'legacy-staging'}):
                with patch.dict(os.environ, changes):
                    with self.assertRaises(ValueError) as caught: Settings.from_env()
                    self.assertNotIn('PRIVATE-INVALID', str(caught.exception))


class ScopedFixture(BotFixture):
    def setUp(self):
        super().setUp()
        self.settings = replace(configuration(self.settings), backend_deployment_policy='staging', legacy_chat_enabled=True)
        self.adapter.settings = self.settings
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.controls.settings = self.settings
        self.controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.api.app.state.verification_service = self.service
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))


class ScopedHTTPTests(ScopedFixture):
    def test_issuance_requires_own_credential_and_preserves_provider_guards(self):
        for token in ('s', 'c'):
            response = self.http.post('/internal/verified-sessions', json={'proof': self.proof},
                                      headers={'Authorization': 'Bearer ' + token * 43})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.calls, [])
        response = self.http.post('/internal/verified-sessions', json={'proof': self.proof},
                                  headers={'Authorization': 'Bearer ' + 'i' * 43})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.claims()[0][4], 'issued')
        self.client_factory.assert_not_called()

    def test_new_credentials_cannot_access_legacy_chat_or_unverified_issuance(self):
        for path, body in (('/chat', {'message': 'Docker?'}), ('/internal/sessions', {})):
            for token in ('i', 'c'):
                response = self.http.post(path, json=body, headers={'Authorization': 'Bearer ' + token * 43})
                self.assertEqual(response.status_code, 401)
        self.client_factory.assert_not_called()
        self.models.generate_content.assert_not_called()

    def test_legacy_credential_still_serves_legacy_workflows(self):
        headers = {'Authorization': 'Bearer ' + 's' * 43}
        self.assertEqual(self.http.post('/internal/sessions', json={}, headers=headers).status_code, 201)
        result = self.http.post('/chat', json={'message': 'Show me all projects'}, headers=headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {'answer': 'Offline test answer.'})

    def test_future_session_chat_route_stays_unregistered(self):
        self.assertNotIn('/internal/session-chat', {r.path for r in self.api.app.routes})
        for token, status in (('i', 401), ('s', 401), ('c', 404)):
            result = self.http.post('/internal/session-chat', json={'message': 'Docker?'},
                                    headers={'Authorization': 'Bearer ' + token * 43})
            self.assertEqual(result.status_code, status)
        self.client_factory.assert_not_called()

    def test_methods_aliases_queries_and_encoded_paths_are_not_authorized(self):
        headers = {'Authorization': 'Bearer ' + 'i' * 43}
        for path in ('/internal/verified-sessions/', '/internal/verified-sessions?x=1', '/internal/%76erified-sessions'):
            self.assertEqual(self.http.post(path, json={'proof': self.proof}, headers=headers).status_code, 401)
        for method in ('GET', 'HEAD', 'PUT', 'OPTIONS'):
            self.assertEqual(self.http.request(method, '/internal/verified-sessions', headers=headers).status_code, 401)
        self.assertEqual(self.calls, [])

    def test_missing_duplicate_ambiguous_credentials_no_principal_headers(self):
        for headers in ({}, {'Authorization': 'Basic invalid'},
                        [('Authorization', 'Bearer ' + 'i' * 43), ('Authorization', 'Bearer ' + 'i' * 43)],
                        {'Authorization': 'Bearer ' + 's' * 43, 'X-Capability': 'verified_session_issuance'}):
            result = self.http.post('/internal/verified-sessions', json={'proof': self.proof}, headers=headers)
            self.assertEqual(result.status_code, 401)
        self.assertEqual(self.calls, [])

    def test_health_public_no_http_admin_and_safe_errors_logs(self):
        self.assertEqual(self.http.get('/health').status_code, 200)
        self.assertEqual(self.http.get('/ready').status_code, 200)
        for token in ('i', 'c', 's'):
            result = self.http.post('/internal/admin/enable', headers={'Authorization': 'Bearer ' + token * 43})
            self.assertEqual(result.status_code, 401)
            for secret in ('i' * 43, 'c' * 43, 's' * 43):
                self.assertNotIn(secret, result.text + str(self.logs.call_args_list))

    def test_internal_issuance_rejects_wrong_principal_and_request_id(self):
        from src.bot_verification import VerificationError
        request = scope()
        chat_principal = authenticate(self.settings, scope('/internal/session-chat', 'c' * 43))
        with self.assertRaises(VerificationError):
            asyncio.run(self.service.issue(self.settings, request, self.proof, request['state']['request_id'], principal=chat_principal))
        issuance = authenticate(self.settings, request)
        with self.assertRaises(VerificationError):
            asyncio.run(self.service.issue(self.settings, request, self.proof, uuid4().hex, principal=issuance))
        self.assertEqual(self.calls, [])


class ScopedSessionChatTests(ScopedFixture):
    def setUp(self):
        super().setUp()
        self.settings = replace(self.settings, session_chat_enabled=True)
        self.controls.settings = self.settings
        self.controls.rate_limiter = RateLimiter(1000, 60, 1)
        self.service_chat = SessionChatService(self.settings, self.controls, self.api.app,
                                               self.api.ChatRequest, self.api._chat_worker)
        self.chat_scope = {**scope('/internal/session-chat', 'c' * 43), 'headers': [
            (b'authorization', b'Bearer ' + b'c' * 43), (b'x-portfolio-session', self.raw.encode()),
            (b'content-type', b'application/json')]}

    def run_chat(self, request=None, principal=None, identity=None):
        async def chunks(): yield b'{"message":"What is BundesHost?"}'
        return asyncio.run(self.service_chat.run(self.chat_scope if request is None else request, chunks(),
                           principal=principal, identity=self.identity if identity is None else identity))

    def test_chat_requires_chat_credential_not_issuance_or_legacy(self):
        for token in ('i', 's'):
            request = {**self.chat_scope, 'headers': [(b'authorization', ('Bearer ' + token * 43).encode()),
                                                     *self.chat_scope['headers'][1:]]}
            self.assertEqual(self.run_chat(request).status, 401)
        self.client_factory.assert_not_called()
        result = self.run_chat()
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(result.body, {'answer': 'Offline test answer.'})
        self.assertEqual(len(self.rows()['ip_events']), 1)
        self.assertEqual(self.ledger.status()['periods']['day']['generation_ops'], 1)

    def test_pre_authenticated_principal_is_preserved_through_supervisor(self):
        principal = authenticate(self.settings, self.chat_scope, required=Capability.SESSION_CHAT)
        result = self.run_chat(principal=principal)
        self.assertEqual(result.status, 200)
        self.assertEqual(principal.path, '/internal/session-chat')
        self.assertEqual(principal.capability, Capability.SESSION_CHAT)

    def test_issuance_legacy_or_forged_principal_rejected(self):
        issuance = authenticate(self.settings, scope())
        legacy = authenticate(self.settings, scope('/chat', 's' * 43))
        for principal in (issuance, legacy, {'capability': 'session_chat'}, AuthenticatedPrincipal()):
            self.assertEqual(self.run_chat(principal=principal).status, 401)
        self.client_factory.assert_not_called()

    def test_scoped_principal_does_not_replace_trusted_identity(self):
        async def run():
            async def chunks(): yield b'{"message":"Docker?"}'
            principal = authenticate(self.settings, self.chat_scope)
            return await self.service_chat.run(self.chat_scope, chunks(), principal=principal, identity=None)
        self.assertEqual(asyncio.run(run()).status, 401)
        self.client_factory.assert_not_called()

    def test_session_state_and_global_emergency_still_enforced(self):
        self.ledger.revoke_session(self.session)
        self.assertEqual(self.run_chat().status, 401)
        self.ledger.set_disabled(True)
        self.assertEqual(self.run_chat().status, 503)
        self.client_factory.assert_not_called()

    def test_missing_scoped_settings_never_falls_back(self):
        self.settings = replace(self.settings, session_chat_auth_token='')
        self.controls.settings = self.settings
        self.service_chat.settings = self.settings
        self.assertEqual(self.run_chat().status, 503)
        self.client_factory.assert_not_called()

    def test_scoped_chat_deadline_preserves_worker_owned_capacity(self):
        from threading import Event, BoundedSemaphore
        entered, finish = Event(), Event()
        self.settings = replace(self.settings, chat_deadline_seconds=0.05)
        self.controls.settings = self.settings
        self.service_chat.settings = self.settings
        self.controls.capacity = BoundedSemaphore(1)
        vector = self.models.embed_content.return_value
        def embedding(**kwargs):
            entered.set()
            self.assertTrue(finish.wait(3))
            return vector
        self.models.embed_content.side_effect = embedding
        async def run():
            async def chunks(): yield b'{"message":"Docker?"}'
            try:
                result = await self.service_chat.run(self.chat_scope, chunks(), identity=self.identity)
                self.assertEqual(result.status, 504)
                self.assertTrue(entered.is_set())
                self.assertEqual(self.ledger.status()['active'], 1)
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally:
                finish.set()
            for _ in range(100):
                if self.ledger.status()['active'] == 0 and not self.controls.tasks: break
                await asyncio.sleep(0.01)
            self.assertEqual(self.ledger.status()['active'], 0)
            self.assertTrue(self.controls.capacity.acquire(blocking=False))
            self.controls.capacity.release()
        asyncio.run(run())
        self.models.generate_content.assert_not_called()
