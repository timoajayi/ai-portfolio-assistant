"""Production-deny legacy policy and trusted-identity boundaries, fully offline."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import re
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.config import Settings
from src.legacy_policy import legacy_execution_allowed, validate_legacy_configuration
from tests.offline import OfflineTestCase


class ProductionPolicyTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))

    def no_work(self):
        self.client_factory.assert_not_called()
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.assertEqual(self.usage_ledger.status()['active'], 0)
        self.assertEqual(self.usage_ledger.status()['periods']['day']['admitted'], 0)

    def test_default_configuration_and_http_deny_anonymous_legacy(self):
        self.assertEqual(Settings().backend_deployment_policy, 'production')
        self.assertFalse(Settings().legacy_chat_enabled)
        self.assertFalse(legacy_execution_allowed(Settings()))
        for field in ('session_chat_http_enabled', 'session_chat_enabled', 'session_issuance_enabled',
                      'session_admission_enabled', 'ip_admission_enabled', 'bot_verification_enabled'):
            self.assertFalse(getattr(Settings(), field))
        response = self.http.post('/chat', json={'message':'Docker?'})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.json(), {'detail':'The AI assistant could not generate a response.'})
        self.no_work()

    def test_browser_headers_body_mode_queries_and_node_env_cannot_authorize(self):
        for headers in ({'X-Deployment-Policy':'staging','X-Legacy-Chat-Enabled':'true'},
                        {'X-Forwarded-For':'127.0.0.1','Host':'localhost'},
                        {'Authorization':'Bearer '+'s'*43}, {'NODE_ENV':'development'}):
            response = self.http.post('/chat', json={'message':'Docker?','mode':'staging'}, headers=headers)
            self.assertEqual(response.status_code,404)
        with patch.dict(os.environ, {'NODE_ENV':'development','ENVIRONMENT':'staging'}):
            self.assertEqual(Settings.from_env().backend_deployment_policy,'production')
        self.no_work()

    def test_production_never_accepts_legacy_execution_even_with_flag(self):
        for overrides in ({'legacy_chat_enabled':True}, {'legacy_chat_enabled':True,'staging_auth_enabled':True,
                          'staging_auth_token':'s'*43}):
            settings=replace(self.controls.settings,**overrides)
            self.assertFalse(legacy_execution_allowed(settings))
            with self.assertRaises(ValueError):validate_legacy_configuration(settings)
            self.controls.settings=settings
            response=self.http.post('/chat',json={'message':'Docker?'},headers={'Authorization':'Bearer '+'s'*43})
            self.assertEqual(response.status_code,404)
        self.no_work()

    def test_exact_configuration_is_required_and_errors_are_sanitized(self):
        for variable,values in [('BACKEND_DEPLOYMENT_POLICY',('development','PRODUCTION','production ','PRIVATE')),
                                ('LEGACY_CHAT_ENABLED',('TRUE','1',' true','false\n','PRIVATE'))]:
            for value in values:
                with patch.dict(os.environ,{variable:value}):
                    with self.assertRaises(ValueError) as error:Settings.from_env()
                    self.assertNotIn(value,str(error.exception))
        with patch.dict(os.environ,{'LEGACY_CHAT_ENABLED':'true'}):
            with self.assertRaises(ValueError):Settings.from_env()
        self.no_work()

    def test_staging_mode_alone_is_not_an_opt_in(self):
        self.controls.settings=replace(self.controls.settings,backend_deployment_policy='staging')
        self.assertEqual(self.http.post('/chat',json={'message':'Docker?'}).status_code,404)
        self.no_work()

    def test_enabled_staging_without_bearer_auth_configuration_fails_closed(self):
        settings=replace(self.controls.settings,backend_deployment_policy='staging',legacy_chat_enabled=True)
        self.controls.settings=settings
        self.assertFalse(legacy_execution_allowed(settings))
        self.assertEqual(self.http.post('/chat',json={'message':'Docker?'}).status_code,404)
        with patch.dict(os.environ,{'BACKEND_DEPLOYMENT_POLICY':'staging','LEGACY_CHAT_ENABLED':'true'}):
            with self.assertRaises(ValueError):Settings.from_env()
        self.no_work()

    def test_deliberate_staging_requires_auth_and_preserves_success_contract(self):
        headers=self.authorize_legacy_staging(self.api)
        self.assertEqual(self.http.post('/chat',json={'message':'Docker?'}).status_code,401)
        self.no_work()
        response=self.http.post('/chat',json={'message':'Docker?'},headers=headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json(),{'answer':'Offline test answer.'})
        self.assertEqual(self.usage_ledger.status()['periods']['day']['admitted'],1)

    def test_scoped_credentials_do_not_fall_back_to_legacy(self):
        headers=self.authorize_legacy_staging(self.api,token='s'*43)
        self.controls.settings=replace(self.controls.settings,capability_auth_enabled=True,
                                      verified_session_auth_token='i'*43,session_chat_auth_token='c'*43)
        for token in ('i','c'):
            response=self.http.post('/chat',json={'message':'Docker?'},headers={'Authorization':'Bearer '+token*43})
            self.assertEqual(response.status_code,401)
        self.no_work()
        self.assertEqual(self.http.post('/chat',json={'message':'Docker?'},headers=headers).status_code,200)

    def test_legacy_staging_and_secure_http_cannot_be_enabled_together(self):
        self.authorize_legacy_staging(self.api)
        settings=replace(self.controls.settings,session_chat_http_enabled=True)
        self.assertFalse(legacy_execution_allowed(settings))
        with self.assertRaises(ValueError):validate_legacy_configuration(settings)
        self.no_work()

    def test_alias_methods_and_queries_do_not_redirect_or_execute(self):
        headers=self.authorize_legacy_staging(self.api)
        for path in ('/chat/','/chat//','/%63hat','/chat?mode=staging'):
            response=self.http.post(path,json={'message':'Docker?'},headers=headers,follow_redirects=False)
            self.assertEqual(response.status_code,404)
            self.assertNotIn('location',response.headers)
        for method in ('GET','HEAD','PUT','OPTIONS','DELETE'):
            response=self.http.request(method,'/chat',headers=headers,follow_redirects=False)
            self.assertEqual(response.status_code,404)
            self.assertNotIn('location',response.headers)
        self.no_work()

    def test_untrusted_internal_state_does_not_select_private_supervisor(self):
        async def run():
            scope={'type':'http','method':'POST','path':'/chat','raw_path':b'/chat','query_string':b'',
                   'headers':[(b'x-internal-session-chat',b'true')],
                   'state':{'_internal_session_chat':True,'authenticated_principal':'forged'},
                   'app':self.api.app}
            sent=[]
            async def receive():self.fail('Denied legacy request body must never be read')
            async def send(message):sent.append(message)
            await self.api.app(scope,receive,send)
            self.assertEqual(sent[0]['status'],404)
        asyncio.run(run())
        self.no_work()

    def test_direct_handler_defense_denies_before_worker(self):
        request=Request({'type':'http','method':'POST','path':'/chat','headers':[],'app':self.api.app})
        with patch.object(self.api,'_chat_worker') as worker:
            with self.assertRaises(HTTPException) as error:
                self.api.chat(self.api.ChatRequest(message='Docker?'),request)
            self.assertEqual(error.exception.status_code,404)
            worker.assert_not_called()
        self.no_work()

    def test_health_readiness_and_no_http_admin_access(self):
        self.assertEqual(self.http.get('/health').status_code,200)
        self.assertEqual(self.http.get('/ready').status_code,200)
        self.assertFalse(any('admin' in route.path for route in self.api.app.routes))
        self.no_work()

    def test_no_sensitive_error_or_log_values(self):
        marker='PRIVATE-VISITOR-MESSAGE'
        response=self.http.post('/chat',json={'message':marker},headers={'Authorization':'Bearer '+'c'*43})
        self.assertEqual(response.status_code,404)
        for value in (marker,'c'*43,'Bearer'):
            self.assertNotIn(value,response.text)
            self.assertNotIn(value,str(self.logs.call_args_list))
        self.no_work()

    def test_docker_defaults_and_explicit_source_copy_cover_release_manifest(self):
        from scripts.prepare_docker_context import RUNTIME_FILES
        docker=Path('Dockerfile').read_text()
        self.assertIn('BACKEND_DEPLOYMENT_POLICY=production',docker)
        self.assertIn('LEGACY_CHAT_ENABLED=false',docker)
        self.assertIn('--no-proxy-headers',docker)
        self.assertIn('USER 10001:10001',docker)
        copied=set(re.findall(r'src/[a-z_]+\.py',docker))
        self.assertEqual(copied,set(RUNTIME_FILES))
        # Every required module must also survive the deny-by-default context filter.
        rules = Path('.dockerignore').read_text().splitlines()
        exceptions = {line[1:] for line in rules if line.startswith('!src/')}
        self.assertEqual(exceptions, set(RUNTIME_FILES) | {'src/'})
        self.assertNotIn('!src/local_development.py', rules)
        self.no_work()

    def test_invalid_policy_fails_lifespan_before_index_or_provider_work(self):
        self.controls.settings = replace(self.controls.settings, legacy_chat_enabled=True)
        with patch.object(self.api, 'load_portfolio_index') as index:
            async def startup():
                with self.assertRaises(ValueError):
                    async with self.api.lifespan(self.api.app):
                        self.fail('Invalid configuration must never start')
            asyncio.run(startup())
            index.assert_not_called()
        self.no_work()
