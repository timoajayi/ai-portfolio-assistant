"""Dedicated disposable local state, real gateway/SQLite/admission, mocked providers."""
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from src import local_development as local
from src.bot_verification import TurnstileAdapter, VerifiedSessionService
from tests.offline import OfflineTestCase

FRONTEND = Path('/Users/timothyajayi/PycharmProjects/ai-engineer-portfolio')


class LocalDevelopmentTests(OfflineTestCase):
    def setUp(self):
        super().setUp()
        self.directory = Path(self.temporary) / 'local-private'
        self.ledger = local.initialize(self.directory)
        self.profile = local.read_profile(self.directory)
        self.stack.enter_context(patch.dict(os.environ, {'BOT_PROVIDER_SECRET': 'offline-bot-secret',
            'NODE_ENV': 'development'}, clear=False))

    def application(self, *, enable=True, bot_success=True, session_only=False):
        if enable:
            self.ledger.set_disabled(False)
            self.ledger.set_issuance_disabled(False)
        app = local.create_app(self.directory, session_only=session_only)
        self.api = sys.modules['src.api']
        self.bot_requests = []
        self.wire_requests = []
        def bot(request):
            self.bot_requests.append(request)
            return httpx.Response(200, json={
                'success': bot_success, 'hostname': 'localhost', 'action': 'portfolio_session',
                'challenge_ts': datetime.now(timezone.utc).isoformat(), 'error-codes': []})
        self.api.app.state.verification_service = VerifiedSessionService(TurnstileAdapter(
            self.api.settings, transport=httpx.MockTransport(bot)))
        return self.stack.enter_context(TestClient(app, client=('127.0.0.1', 40000)))

    def workflow(self, http):
        if not (FRONTEND / 'node_modules/typescript').is_dir():
            self.fail('Installed frontend compiler required for cross-repository verification')
        guard = Path('/tmp/portfolio-assertion-guards/offline-node.cjs')
        args = ['node']
        if guard.exists():args.append('--require=' + str(guard))
        args.append('tests/local_frontend_workflow.mjs')
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env={**os.environ, 'NODE_ENV': 'development'})
        try:
            process.stdin.write(json.dumps({'frontend': str(FRONTEND), 'profile': self.profile}) + '\n')
            process.stdin.flush()
            done = None
            for line in process.stdout:
                message = json.loads(line)
                if message.get('done'):
                    done = message
                    break
                request = message['request']
                self.wire_requests.append(request)
                self.assertEqual(request['method'], 'POST')
                path = request['url'].removeprefix('http://127.0.0.1:8001')
                self.assertIn(path, ('/internal/verified-sessions', '/internal/session-chat'))
                response = http.post(path, content=request['body'], headers=request['headers'])
                process.stdin.write(json.dumps({'status': response.status_code, 'body': response.json()}) + '\n')
                process.stdin.flush()
            process.stdin.close()
            self.assertEqual(process.wait(timeout=10), 0, 'Offline Node bridge failed')
            self.assertIsNotNone(done)
            self.assertNotIn('error', done)
            return done
        finally:
            if process.poll() is None:
                process.kill();process.wait()
            process.stdout.close();process.stderr.close()

    def test_profile_and_init_are_private_distinct_and_disabled(self):
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.directory/'profile.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(len({self.profile[k] for k in ('staging','chat','issuance','signing','ip_key')}),5)
        self.assertTrue(self.ledger.status()['disabled'])
        with self.assertRaises(FileExistsError):local.initialize(self.directory)
        self.client_factory.assert_not_called()

    def test_complete_node_session_cookie_assertion_backend_rag_flow(self):
        http = self.application()
        result = self.workflow(http)
        self.assertEqual(result['sessionStatus'],201)
        self.assertEqual(result['chatStatus'],200)
        self.assertTrue(result['secureCookie'])
        self.assertEqual(result['body'],{'answer':'Offline test answer.'})
        self.assertEqual(len(self.bot_requests),1)
        self.models.embed_content.assert_called_once()
        self.models.generate_content.assert_called_once()
        self.assertEqual(self.ledger.status()['periods']['day'],{'admitted':1,'embedding_ops':1,'generation_ops':1})

    def test_session_only_normal_gateway_flow_issues_session_but_never_calls_gemini(self):
        with patch('src.reliability.logger.info') as logs:
            http = self.application(session_only=True)
        events = [json.loads(call.args[0]) for call in logs.call_args_list]
        self.assertIn({'event': 'local_session_diagnostic', 'gemini_execution': 'blocked',
                       'verified_session_issuance': 'enabled', 'verification_diagnostics': 'enabled'}, events)
        result = self.workflow(http)
        self.assertEqual(result['sessionStatus'], 201)
        self.assertNotEqual(result['chatStatus'], 200)
        self.assertEqual(len(self.bot_requests), 1)
        self.assertFalse(self.api.settings.session_chat_enabled)
        self.assertFalse(self.api.settings.session_chat_http_enabled)
        self.assertFalse(self.api.settings.legacy_chat_enabled)
        self.assertTrue(self.api.settings.bot_verification_enabled)
        self.assertTrue(self.api.settings.session_issuance_enabled)
        self.assertFalse(self.ledger.status()['disabled'])
        self.assertFalse(self.ledger.issuance_status()['issuance_disabled'])
        self.assertEqual(self.ledger.status()['periods']['day'],
                         {'admitted': 0, 'embedding_ops': 0, 'generation_ops': 0})
        for path in ('/chat', '/chat/', '/internal/session-chat', '/internal/session-chat/'):
            for token in (self.profile['staging'], self.profile['chat'], self.profile['issuance']):
                self.assertNotEqual(http.post(path, json={'message': 'Docker?'},
                    headers={'Authorization': 'Bearer ' + token}, follow_redirects=False).status_code, 200)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.client_factory.assert_not_called()

    def test_session_only_preserves_verification_failure_diagnostics(self):
        http = self.application(session_only=True)
        def unavailable(request):
            raise httpx.ConnectError('private diagnostic marker')
        self.api.app.state.verification_service.adapter.transport = httpx.MockTransport(unavailable)
        with patch('src.reliability.logger.warning') as logs:
            response = http.post('/internal/verified-sessions', json={'proof': 'offline-fresh-proof'},
                headers={'Authorization': 'Bearer ' + self.profile['issuance']})
        self.assertEqual(response.status_code, 503)
        events = [json.loads(call.args[0]) for call in logs.call_args_list]
        event = next(item for item in events if item['event'] == 'verified_session_failure')
        self.assertEqual((event['stage'], event['category'], event['exception_class'], event['status']),
                         ('cloudflare_transport', 'network', 'ConnectError', 503))
        self.assertNotIn('private diagnostic marker', str(events))
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'], 0)
        self.client_factory.assert_not_called()

    def test_session_only_cli_passes_mode_without_enabling_or_resetting_storage(self):
        before = (self.directory / 'usage.sqlite3').read_bytes()
        with patch.object(local, 'create_app', return_value=object()) as factory, patch('uvicorn.run') as run:
            self.assertEqual(local.main(['serve', '--state', str(self.directory),
                '--allow-live-providers', '--session-only']), 0)
        factory.assert_called_once_with(self.directory.resolve(), session_only=True)
        run.assert_called_once()
        self.assertEqual(local.main(['enable', '--state', str(self.directory),
            '--allow-live-providers', '--session-only']), 1)
        self.assertEqual((self.directory / 'usage.sqlite3').read_bytes(), before)

    def test_bot_failure_creates_no_session_or_paid_work(self):
        result = self.workflow(self.application(bot_success=False))
        self.assertNotEqual(result['sessionStatus'],201)
        self.assertEqual(result['calls'],1)
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],0)

    def test_disabled_ledger_does_not_call_bot_or_gemini(self):
        result = self.workflow(self.application(enable=False))
        self.assertNotEqual(result['sessionStatus'],201)
        self.assertEqual(self.bot_requests,[])
        self.client_factory.assert_not_called()

    def test_startup_does_not_enable_or_migrate_and_legacy_stays_denied(self):
        http=self.application(enable=False)
        self.assertEqual(http.get('/health').status_code,200)
        self.assertEqual(http.post('/chat',json={'message':'Docker?'}).status_code,401)
        self.assertTrue(self.ledger.status()['disabled'])
        self.assertFalse(self.api.settings.legacy_chat_enabled)
        self.client_factory.assert_not_called()

    def test_non_loopback_peer_denied_before_application(self):
        async def run():
            called=[]; sent=[]
            async def forbidden(*args):called.append(True)
            async def receive():raise AssertionError('No body reads allowed')
            async def send(message):sent.append(message)
            for address in ('192.0.2.1','::1','127.0.0.2'):
                await local.LoopbackOnly(forbidden)({'type':'http','client':(address,1)},receive,send)
                self.assertEqual(sent[-2]['status'],403)
            self.assertEqual(called,[])
        asyncio.run(run())

    def test_hosted_and_production_environments_rejected(self):
        for overrides in ({'NODE_ENV':'production'},{'VERCEL':'1'},{'RAILWAY_ENVIRONMENT_ID':'test'}):
            with patch.dict(os.environ,overrides):
                with self.assertRaises(ValueError):local.local_only()

    def test_missing_and_permissive_profile_fail_closed(self):
        with self.assertRaises(FileNotFoundError):local.read_profile(Path(self.temporary)/'absent')
        (self.directory/'profile.json').chmod(0o644)
        with self.assertRaises(ValueError):local.read_profile(self.directory)

    def test_serve_and_enable_require_explicit_live_authorization(self):
        self.assertEqual(local.main(['enable','--state',str(self.directory)]),1)
        self.assertTrue(self.ledger.status()['disabled'])
        self.assertEqual(local.main(['serve','--state',str(self.directory)]),1)
        self.client_factory.assert_not_called()

    def test_replay_and_quota_rejections_keep_all_guards(self):
        self.stack.enter_context(patch.dict(os.environ, {'USAGE_DAILY_LIMIT':'1'}))
        http=self.application()
        self.assertEqual(self.workflow(http)['chatStatus'],200)
        chat=self.wire_requests[-1]
        replay=http.post('/internal/session-chat',content=chat['body'],headers=chat['headers'])
        self.assertEqual(replay.status_code,403)
        self.assertEqual(self.models.generate_content.call_count,1)
        # Distinct assertions/sessions still share the same durable global budget.
        renewed=self.renew_assertion(chat['headers'])
        self.assertEqual(http.post('/internal/session-chat',content=chat['body'],headers=renewed).status_code,429)
        self.assertEqual(self.models.generate_content.call_count,1)

    def test_loopback_local_policy_cannot_authorize_arbitrary_identity(self):
        http=self.application()
        self.assertEqual(self.workflow(http)['chatStatus'],200)
        chat=self.wire_requests[-1]
        headers=self.renew_assertion(chat['headers'], visitor_ip='192.0.2.10')
        denied=http.post('/internal/session-chat',content=chat['body'],headers=headers)
        self.assertEqual(denied.status_code,403)
        self.assertEqual(self.models.generate_content.call_count,1)

    def renew_assertion(self, headers, **changes):
        import base64,hmac,secrets
        compact=headers['x-portfolio-gateway-assertion']
        header,payload,_=compact.split('.')
        value=json.loads(base64.urlsafe_b64decode(payload+'='*((-len(payload))%4)))
        value.update(changes)
        value['jti']=secrets.token_urlsafe(32)
        payload=base64.urlsafe_b64encode(json.dumps(value,separators=(',',':')).encode()).rstrip(b'=').decode()
        signing=(header+'.'+payload).encode()
        key=base64.urlsafe_b64decode(self.profile['signing']+'=')
        signature=base64.urlsafe_b64encode(hmac.digest(key,signing,'sha256')).rstrip(b'=').decode()
        return {**headers,'x-portfolio-gateway-assertion':signing.decode()+'.'+signature}
