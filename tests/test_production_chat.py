"""Production composition with synthetic credentials, temporary SQLite and mocks."""
import asyncio
from unittest.mock import patch

from src.production_chat import compose_production_chat, POLICY, VercelGatewayIdentity
from tests.test_authenticated_session_chat import KEY
from tests.test_session_chat_http import HTTPFixture


class ProductionCompositionTests(HTTPFixture):
    def environment(self):
        import base64
        return {'RENDER': 'true', 'GATEWAY_INGRESS_POLICY': POLICY,
                'GATEWAY_ASSERTION_KEY': base64.urlsafe_b64encode(KEY).rstrip(b'=').decode(),
                'GATEWAY_ASSERTION_KEY_ID': 'gateway-key-1',
                'GATEWAY_ASSERTION_KEY_NOT_BEFORE': '0', 'GATEWAY_ASSERTION_KEY_NOT_AFTER': '253402300799',
                'GATEWAY_ASSERTION_ISSUER': 'portfolio-gateway', 'GATEWAY_ASSERTION_AUDIENCE': 'portfolio-backend'}

    def compose(self, environment=None):
        return compose_production_chat(self.api.app, self.controls, self.api.ChatRequest,
                                       self.api._chat_worker, self.environment() if environment is None else environment)

    def install(self):
        self.api.app.state.session_chat_pipeline = self.compose()

    def test_real_composition_session_chat_and_durable_replay(self):
        self.install()
        self.assertIsInstance(self.api.app.state.session_chat_pipeline._resolver, VercelGatewayIdentity)
        proof = self.proof(ip_source=POLICY)
        self.assertEqual(self.post(proof=proof).status_code, 200)
        self.assertEqual(self.models.generate_content.call_count, 1)
        self.assertEqual(self.post(proof=proof).status_code, 403)
        self.assertEqual(self.models.generate_content.call_count, 1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 1)

    def test_missing_invalid_configuration_never_sets_pipeline_or_invokes_provider(self):
        for name in self.environment():
            environment = self.environment(); del environment[name]
            with self.subTest(missing=name), self.assertRaisesRegex(RuntimeError, '^Production chat configuration unavailable.$'):
                self.compose(environment)
        for changes in ({'RENDER': 'false'}, {'GATEWAY_INGRESS_POLICY': 'local-loopback-development-v1'},
                        {'GATEWAY_ASSERTION_KEY': 'invalid'}, {'GATEWAY_ASSERTION_KEY_NOT_BEFORE': '-1'},
                        {'GATEWAY_ASSERTION_KEY_NOT_AFTER': '1'}, {'GATEWAY_ASSERTION_KEY_ID': 'BAD KID'},
                        {'GATEWAY_ASSERTION_KEY': self.settings.session_chat_auth_token}):
            with self.subTest(fields=list(changes)), self.assertRaises(RuntimeError):
                self.compose({**self.environment(), **changes})
        self.no_provider()

    def test_invalid_assertion_scope_session_and_ingress_cannot_invoke_provider(self):
        self.install()
        for changes in ({'ip_source': 'unapproved'}, {'iss': 'other-gateway'}, {'aud': 'other-backend'},
                        {'iat': 0, 'exp': 30}):
            self.reject_http(403, proof=self.proof(ip_source=POLICY, **{k:v for k,v in changes.items() if k != 'ip_source'})
                             if 'ip_source' not in changes else self.proof(**changes))
        self.reject_http(401, headers=self.headers(self.proof(ip_source=POLICY), token='i'*43))
        self.reject_http(401, headers=self.headers(self.proof(ip_source=POLICY), session='invalid'))
        self.reject_http(403, body=self.body+b' ', proof=self.proof(ip_source=POLICY))

    def test_actual_lifespan_composes_only_when_enabled_and_uncomposed(self):
        self.api.app.state.session_chat_pipeline = None
        async def startup():
            with patch.dict('os.environ', self.environment()):
                async with self.api.lifespan(self.api.app):
                    self.assertIsInstance(self.api.app.state.session_chat_pipeline._resolver, VercelGatewayIdentity)
        asyncio.run(startup())
        self.no_provider()

    def test_existing_limits_and_emergency_controls_are_preserved(self):
        self.install()
        for _ in range(3):
            self.assertEqual(self.post(proof=self.proof(ip_source=POLICY)).status_code, 200)
        self.assertEqual(self.post(proof=self.proof(ip_source=POLICY)).status_code, 429)
        self.assertEqual(self.models.generate_content.call_count, 3)
        self.ledger.set_disabled(True)
        self.assertNotEqual(self.post(proof=self.proof(ip_source=POLICY)).status_code, 200)
        self.assertEqual(self.models.generate_content.call_count, 3)

    def test_render_forwarding_is_discarded_not_used_as_identity(self):
        import sqlite3
        from src.identity import TrustedIP
        self.install()
        # Even a conflicting transport header never replaces the signed visitor.
        headers = self.headers(self.proof(ip_source=POLICY))
        headers.append(('X-Forwarded-For', '198.51.100.99, 198.51.100.100'))
        self.assertEqual(self.post(headers=headers).status_code, 200)
        with sqlite3.connect(self.usage_path) as db:
            rows = db.execute('SELECT identity FROM ip_events').fetchall()
        self.assertEqual(rows, [(TrustedIP('192.0.2.10').digest(self.key),)])
        # The ignored field cannot authorize requests or fix an invalid MAC.
        headers = self.headers('invalid') + [('X-Forwarded-For', '192.0.2.10')]
        self.assertEqual(self.post(headers=headers).status_code, 403)
        self.assertEqual(self.models.generate_content.call_count, 1)
