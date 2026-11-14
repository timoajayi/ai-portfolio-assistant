"""HTTP boundary tests: temporary schema 6 ledgers, fixture ingress, mocked SDK."""
import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
import os
import sqlite3
from threading import Event
import time
from unittest.mock import patch

from src.config import Settings
from src.session_chat_http import SessionChatHTTPAdapter, validate_http_configuration
from src.diagnostics import ChatDiagnostics
from src.auth import AuthenticatedPrincipal
from tests.test_authenticated_session_chat import IntegrationFixture, FixtureResolver, b64, KEY

PATH='/internal/session-chat'


class HTTPFixture(IntegrationFixture):
    def setUp(self):
        super().setUp()
        self.configure(session_chat_http_enabled=True)
        self.api.app.state.session_chat_pipeline=self.pipeline

    def headers(self,proof=None,session=None,token=None):
        return [('Authorization','Bearer '+('c'*43 if token is None else token)),
                ('X-Portfolio-Session',self.raw if session is None else session),
                ('X-Portfolio-Gateway-Assertion',self.proof() if proof is None else proof),
                ('Content-Type','application/json')]

    def post(self,*,body=None,headers=None,proof=None,path=PATH):
        return self.http.post(path,content=self.body if body is None else body,
                              headers=self.headers(proof) if headers is None else headers,follow_redirects=False)

    def reject_http(self,status=None,**kwargs):
        result=self.post(**kwargs)
        self.assertNotEqual(result.status_code,200)
        if status is not None:self.assertEqual(result.status_code,status)
        self.assertEqual(result.headers.get('cache-control'),'no-store')
        self.assertEqual(result.headers.get('content-type'),'application/json')
        self.assertNotIn('location',result.headers)
        self.assertNotIn('access-control-allow-origin',result.headers)
        for secret in ('c'*43,'i'*43,'s'*43,self.raw,'192.0.2.10',KEY.hex(),'PRIVATE'):
            self.assertNotIn(secret,result.text)
        self.no_provider()
        return result

    async def asgi_request(self,*,parts=None,headers=None,path=PATH,method='POST',query=b'',raw_path=None):
        headers=self.headers() if headers is None else headers
        scope={'type':'http','method':method,'path':path,'raw_path':path.encode() if raw_path is None else raw_path,
            'query_string':query,'http_version':'1.1','headers':[(k.lower().encode(),v.encode()) for k,v in headers],
            'state':{}}
        parts=parts or [{'type':'http.request','body':self.body,'more_body':False}]
        items=iter(parts)
        async def receive():
            item=next(items)
            if isinstance(item,tuple):
                await asyncio.sleep(item[0]);return item[1]
            return item
        output=[]
        async def send(message):output.append(message)
        async def forbidden(*args):self.fail('Reserved path fell through to application routing')
        adapter=SessionChatHTTPAdapter(forbidden,application=self.api.app,controls=self.controls,upload_timeout_seconds=.03)
        await adapter(scope,receive,send)
        return output,adapter

    @staticmethod
    def status(messages):
        return next(m['status'] for m in messages if m['type']=='http.response.start')


class SessionChatHTTPSecurityTests(HTTPFixture):
    def test_success_exact_schema_and_cache_controls(self):
        result=self.post()
        self.assertEqual(result.status_code,200)
        self.assertEqual(result.json(),{'answer':'Offline test answer.'})
        self.assertEqual(result.headers['cache-control'],'no-store')
        self.assertNotIn('location',result.headers)
        self.assertNotIn('set-cookie',result.headers)
        self.assertEqual(self.claims(),1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_disabled_default_no_api_route_or_provider(self):
        self.assertFalse(Settings().session_chat_http_enabled)
        self.configure(session_chat_http_enabled=False)
        self.reject_http(404)
        self.assertNotIn(PATH,{route.path for route in self.api.app.routes})
        self.assertEqual(self.claims(),0)

    def test_exact_feature_flag_parsing_missing_and_invalid_config(self):
        for flag in (None,'false'):
            environment={} if flag is None else {'SESSION_CHAT_HTTP_ENABLED':flag}
            with patch.dict(os.environ,environment):
                self.assertFalse(Settings.from_env().session_chat_http_enabled)
        for flag in ('TRUE','True',' true','true ','1','', 'FALSE'):
            with patch.dict(os.environ,{'SESSION_CHAT_HTTP_ENABLED':flag}):
                with self.assertRaises(ValueError):Settings.from_env()
        # Exact true cannot bypass the required scoped configuration.
        with patch.dict(os.environ,{'SESSION_CHAT_HTTP_ENABLED':'true'}):
            with self.assertRaises(ValueError):Settings.from_env()
        self.no_provider()

    def test_missing_capability_configuration_or_pipeline_fails_closed(self):
        self.api.app.state.session_chat_pipeline=None
        self.reject_http(503)
        self.api.app.state.session_chat_pipeline=self.pipeline
        self.configure(capability_auth_enabled=False)
        self.api.app.state.session_chat_pipeline=self.pipeline
        self.reject_http(503)
        self.assertEqual(self.claims(),0)

    def test_enabled_startup_refuses_missing_pipeline_and_resolver(self):
        self.api.app.state.session_chat_pipeline=None
        with self.assertRaises(RuntimeError):validate_http_configuration(self.api.app,self.controls)
        async def startup():
            async with self.api.lifespan(self.api.app):self.fail('Startup must fail without trusted composition')
        with self.assertRaises(RuntimeError):asyncio.run(startup())
        self.api.app.state.session_chat_pipeline=self.pipeline
        self.no_provider()

    def test_exact_true_configuration_requires_scoped_credentials_and_has_no_resolver_selector(self):
        environment={'SESSION_CHAT_HTTP_ENABLED':'true','SESSION_CHAT_ENABLED':'true',
            'CAPABILITY_AUTH_ENABLED':'true','STAGING_AUTH_ENABLED':'true','STAGING_AUTH_TOKEN':'s'*43,
            'SESSION_CHAT_AUTH_TOKEN':'c'*43,'VERIFIED_SESSION_AUTH_TOKEN':'i'*43,
            'SESSION_ADMISSION_ENABLED':'true','IP_ADMISSION_ENABLED':'true','IP_RATE_HMAC_KEY':self.key_text}
        with patch.dict(os.environ,environment):
            self.assertTrue(Settings.from_env().session_chat_http_enabled)
            for name in ('SESSION_CHAT_AUTH_TOKEN','VERIFIED_SESSION_AUTH_TOKEN','STAGING_AUTH_TOKEN'):
                with patch.dict(os.environ,{name:''}):
                    with self.assertRaises(ValueError):Settings.from_env()
        self.assertFalse(any('resolver' in name for name in Settings.__dataclass_fields__))
        self.assertIs(validate_http_configuration(self.api.app,self.controls),self.pipeline)
        self.no_provider()

    def test_health_and_readiness_remain_public(self):
        self.assertEqual(self.http.get('/health').status_code,200)
        self.assertEqual(self.http.get('/ready').status_code,200)
        self.no_provider()

    def test_global_and_ip_limits_do_not_allow_http_bypass(self):
        reservation=self.ledger.reserve_session(self.digest,identity_digest=self.identity.digest(self.key),identity_key_tag=self.tag)
        self.ledger.release(reservation)
        self.configure(ip_admission_minute_limit=1)
        self.api.app.state.session_chat_pipeline=self.pipeline
        self.reject_http(429)
        self.configure(ip_admission_minute_limit=10)
        self.api.app.state.session_chat_pipeline=self.pipeline
        for field in ('daily','monthly'):
            original=getattr(self.ledger,field)
            setattr(self.ledger,field,1)
            self.reject_http(429)
            setattr(self.ledger,field,original)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_wrong_or_missing_scoped_credentials(self):
        for token in ('w'*43,'s'*43,'i'*43,'short'):
            self.reject_http(401,headers=self.headers(token=token))
        self.reject_http(401,headers=[h for h in self.headers() if h[0]!='Authorization'])
        self.assertEqual(self.claims(),0)

    def test_duplicate_malformed_authorization_and_principal_headers(self):
        valid=self.headers()
        for headers in ([valid[0],*valid], [('Authorization','Basic invalid'),*valid[1:]],
                        [('Authorization','Bearer '+ 'c'*43+', Bearer '+'c'*43),*valid[1:]]):
            self.reject_http(401,headers=headers)
        self.reject_http(401,headers=[*self.headers(token='s'*43),('X-Capability','session_chat'),('X-Principal','authenticated')])
        self.assertEqual(self.claims(),0)

    def test_missing_duplicate_or_malformed_assertion(self):
        valid=self.headers()
        for headers in ([h for h in valid if h[0]!='X-Portfolio-Gateway-Assertion'], [*valid,valid[2]],
                        self.headers(proof='invalid'),self.headers(proof='X'*2049)):
            self.reject_http(403,headers=headers)
        self.assertEqual(self.claims(),0)

    def test_invalid_signature_and_body_or_session_bindings(self):
        proof=self.proof()
        h,p,s=proof.split('.')
        self.reject_http(403,proof=h+'.'+p+'.'+b64(b'X'*32))
        self.reject_http(403,proof=proof,body=self.body+b' ')
        self.reject_http(403,headers=self.headers(proof=proof,session=b64(b'X'*32)))
        self.assertEqual(self.claims(),0)

    def test_missing_duplicate_and_noncanonical_session_header(self):
        valid=self.headers()
        for headers in ([h for h in valid if h[0]!='X-Portfolio-Session'],[*valid,valid[1]],
                        self.headers(session='x'*43),self.headers(session=self.raw+'=')):
            self.reject_http(401,headers=headers)
        self.assertEqual(self.claims(),0)

    def test_unknown_unverified_expired_revoked_sessions(self):
        unknown=b64(b'X'*32)
        self.reject_http(401,headers=self.headers(session=unknown,proof=self.proof(session=unknown)))
        for column in ('verified','revoked'):
            original=1 if column=='verified' else 0
            with sqlite3.connect(self.usage_path) as db:db.execute(f'UPDATE sessions SET {column}=?',(1-original,))
            self.reject_http(401)
            with sqlite3.connect(self.usage_path) as db:db.execute(f'UPDATE sessions SET {column}=?',(original,))
        self.now+=timedelta(hours=4)
        self.reject_http(401)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],0)

    def test_wrong_policy_or_identity_and_resolver_failure_consumes_replay(self):
        self.reject_http(403,proof=self.proof(ip_source='unapproved'))
        self.assertEqual(self.claims(),0)
        self.resolver.address='192.0.2.77'
        self.reject_http(403)
        self.assertEqual(self.claims(),1)
        with self.assertRaises(ValueError):self.make_pipeline(resolver=FixtureResolver(policy='unapproved'))

    def test_browser_origins_and_forwarded_identity_headers_rejected(self):
        for name in ('Origin','X-Forwarded-For','X-Real-IP','CF-Connecting-IP','Forwarded','X-Identity-Digest'):
            self.reject_http(403,headers=[*self.headers(),(name,'192.0.2.10')])
        self.assertEqual(self.claims(),0)

    def test_methods_paths_queries_and_encoded_aliases_never_redirect(self):
        for method in ('GET','HEAD','PUT','PATCH','DELETE','OPTIONS'):
            result=self.http.request(method,PATH,headers=self.headers(),follow_redirects=False)
            self.assertEqual(result.status_code,405)
            self.assertNotIn('location',result.headers)
            self.assertEqual(result.headers['cache-control'],'no-store')
        for path in (PATH+'/',PATH+'?message=PRIVATE','/internal/%73ession-chat',PATH+'//'):
            result=self.post(path=path)
            self.assertIn(result.status_code,(400,404))
            self.assertNotIn('location',result.headers)
        messages,_=asyncio.run(self.asgi_request(path='/internal/./session-chat'))
        self.assertEqual(self.status(messages),400)
        self.no_provider()

    def test_oversized_fixed_and_streamed_body(self):
        self.reject_http(413,body=b'X'*8193)
        parts=[{'type':'http.request','body':b'X'*4096,'more_body':True},
               {'type':'http.request','body':b'X'*4097,'more_body':False}]
        messages,_=asyncio.run(self.asgi_request(parts=parts))
        self.assertEqual(self.status(messages),413)
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_json_unicode_schema_and_message_validation_before_replay(self):
        for body in (b'{',b'[]',b'null',b'{"message":""}',b'{"message":"   "}',
                     b'{"message":123}', b'{"message":"PRIVATE","extra":true}',
                     b'{"message":"a","message":"PRIVATE"}', b'{"message":"a","\\u006dessage":"PRIVATE"}',
                     b'{"message":"\\ud800"}',b'{"message":"\xff"}', b'\xef\xbb\xbf'+self.body,
                     b'{"message":"a"} trailing',b'{"message":"'+b'A'*1001+b'"}'):
            self.reject_http(422,body=body,proof=self.proof(body=body))
        self.assertEqual(self.claims(),0)

    def test_content_type_and_compression(self):
        for content in ('text/plain','application/json; charset=utf-8','APPLICATION/JSON'):
            self.reject_http(415,headers=[(k,content if k=='Content-Type' else v) for k,v in self.headers()])
        for value in ('gzip','br','identity, gzip'):
            self.reject_http(415,headers=[*self.headers(),('Content-Encoding',value)])
        self.reject_http(415,headers=[*self.headers(),('Content-Type','application/json')])
        self.assertEqual(self.claims(),0)

    def test_ambiguous_content_length_and_transfer_encoding(self):
        for extra in ([('Content-Length','1'),('Content-Length','2')], [('Content-Length','+1')],
                      [('Content-Length','01')], [('Content-Length','1, 2')],
                      [('Transfer-Encoding','gzip')], [('Transfer-Encoding','chunked'),('Content-Length','1')],
                      [('Transfer-Encoding','chunked'),('Transfer-Encoding','chunked')], [('Trailer','X-Private')]):
            messages,_=asyncio.run(self.asgi_request(headers=[*self.headers(),*extra]))
            self.assertEqual(self.status(messages),400)
        for declared in (0,len(self.body)-1,len(self.body)+1):
            messages,_=asyncio.run(self.asgi_request(headers=[*self.headers(),('Content-Length',str(declared))]))
            self.assertEqual(self.status(messages),400)
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_exact_utf8_bytes_and_thousand_codepoints_supported(self):
        body=json.dumps({'message':'😀'*1000},ensure_ascii=False).encode()
        result=self.post(body=body,proof=self.proof(body=body))
        self.assertEqual(result.status_code,200)
        self.assertEqual(self.claims(),1)

    def test_chunked_asgi_stream_uses_exact_decoded_bytes(self):
        proof=self.proof()
        parts=[{'type':'http.request','body':self.body[:10],'more_body':True},
               {'type':'http.request','body':self.body[10:],'more_body':False}]
        messages,_=asyncio.run(self.asgi_request(headers=[*self.headers(proof),('Transfer-Encoding','chunked')],parts=parts))
        self.assertEqual(self.status(messages),200)
        self.assertEqual(self.claims(),1)

    def test_duplicate_replay_and_concurrent_http_requests(self):
        proof=self.proof()
        async def race():
            return await asyncio.gather(*(self.asgi_request(headers=self.headers(proof)) for _ in range(4)))
        results=asyncio.run(race())
        self.assertEqual(sum(self.status(m)==200 for m,_ in results),1)
        self.assertEqual(self.models.generate_content.call_count,1)
        self.models.reset_mock();self.client_factory.reset_mock()
        self.reject_http(403,proof=proof)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_quotas_emergency_and_replay_database_failure(self):
        self.ledger.set_disabled(True)
        self.reject_http(503)
        self.ledger.set_disabled(False)
        identifier=self.ledger.reserve_session(self.digest)
        self.configure(session_admission_minute_limit=1)
        self.api.app.state.session_chat_pipeline=self.pipeline
        self.reject_http(429)
        self.ledger.release(identifier)
        self.usage_path.unlink()
        self.reject_http(503)
        self.assertFalse(self.usage_path.exists())

    def test_provider_failure_is_sanitized_and_not_retried(self):
        self.models.generate_content.side_effect=RuntimeError('PRIVATE PROVIDER CONTENT')
        proof=self.proof()
        result=self.post(proof=proof)
        self.assertEqual(result.status_code,500)
        self.assertNotIn('PRIVATE',result.text)
        self.assertEqual(self.models.generate_content.call_count,1)
        self.models.reset_mock();self.client_factory.reset_mock()
        self.reject_http(403,proof=proof)

    def test_legacy_route_credentials_remain_separate_and_unknown_routes_denied(self):
        for token in ('c'*43,'i'*43):
            result=self.http.post('/chat',json={'message':'Docker?'},headers={'Authorization':'Bearer '+token})
            self.assertEqual(result.status_code,401)
        for route in ('/internal/admin','/internal/usage/enable','/unknown-route'):
            self.assertEqual(self.http.post(route,headers={'Authorization':'Bearer '+'c'*43}).status_code,401)
        self.no_provider()

    def test_no_legacy_handler_and_no_sensitive_logs_or_response_metadata(self):
        proof=self.proof()
        with patch.object(self.api,'chat',side_effect=RuntimeError('Forbidden legacy dispatch')):
            result=self.post(proof=proof)
        self.assertEqual(result.status_code,200)
        for secret in ('c'*43,self.raw,proof,'192.0.2.10',self.body.decode(),KEY.hex()):
            self.assertNotIn(secret,result.text)
            self.assertNotIn(secret,str(self.logs.call_args_list))
        self.assertEqual(set(result.json()),{'answer'})


class SessionChatHTTPLifecycleTests(HTTPFixture):
    async def drain(self):
        for _ in range(200):
            if not self.pipeline.tasks and not self.controls.tasks and self.ledger.status()['active']==0:return
            await asyncio.sleep(.01)
        self.fail('Temporary test workers did not drain')

    def test_unauthenticated_request_body_is_never_read(self):
        async def run():
            async def forbidden(*args):self.fail('Request reached fallback')
            adapter=SessionChatHTTPAdapter(forbidden,application=self.api.app,controls=self.controls)
            scope={'type':'http','method':'POST','path':PATH,'raw_path':PATH.encode(),'http_version':'1.1',
                   'query_string':b'','headers':[(k.lower().encode(),v.encode()) for k,v in self.headers(token='s'*43)]}
            async def read():self.fail('Unauthenticated body read')
            output=[]
            async def send(message):output.append(message)
            await adapter(scope,read,send)
            self.assertEqual(self.status(output),401)
        asyncio.run(run())
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_slow_upload_has_independent_bounded_timeout(self):
        parts=[(.2,{'type':'http.request','body':self.body,'more_body':False})]
        start=time.monotonic()
        messages,_=asyncio.run(self.asgi_request(parts=parts))
        self.assertEqual(self.status(messages),408)
        self.assertLess(time.monotonic()-start,.15)
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_upload_consumes_overall_deadline_and_no_new_budget(self):
        self.configure(chat_deadline_seconds=.025)
        self.api.app.state.session_chat_pipeline=self.pipeline
        parts=[(.2,{'type':'http.request','body':self.body,'more_body':False})]
        messages,_=asyncio.run(self.asgi_request(parts=parts))
        self.assertEqual(self.status(messages),504)
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_upload_time_is_inherited_through_real_provider_worker(self):
        self.configure(chat_deadline_seconds=.2)
        self.api.app.state.session_chat_pipeline=self.pipeline
        entered,finish=Event(),Event()
        vector=self.models.embed_content.return_value
        remaining=[]
        def embed(**kwargs):
            from src.diagnostics import current_diagnostics
            diagnostics=current_diagnostics.get()
            remaining.append(diagnostics.deadline-time.monotonic())
            entered.set()
            self.assertTrue(finish.wait(3))
            return vector
        self.models.embed_content.side_effect=embed
        async def run():
            # Use a larger upload bound here; .06s is still counted in the same
            # .2s overall deadline seen by the worker.
            proof=self.proof()
            headers=[(k.lower().encode(),v.encode()) for k,v in self.headers(proof)]
            scope={'type':'http','method':'POST','path':PATH,'raw_path':PATH.encode(),'query_string':b'',
                   'http_version':'1.1','headers':headers,'state':{}}
            async def fallback(*args):self.fail('Fallback')
            adapter=SessionChatHTTPAdapter(fallback,application=self.api.app,controls=self.controls,upload_timeout_seconds=1)
            async def read():
                await asyncio.sleep(.06)
                return {'type':'http.request','body':self.body,'more_body':False}
            output=[]
            async def send(message):output.append(message)
            try:
                await adapter(scope,read,send)
                self.assertEqual(self.status(output),504)
                self.assertTrue(entered.is_set())
                self.assertLess(remaining[0],.16)
                self.assertEqual(self.ledger.status()['active'],1)
            finally:finish.set()
            await self.drain()
        asyncio.run(run())
        self.assertEqual(self.claims(),1)
        self.models.generate_content.assert_not_called()

    def test_cancellation_after_claim_preserves_replay_and_worker_cleanup(self):
        entered,finish=Event(),Event()
        vector=self.models.embed_content.return_value
        def embed(**kwargs):
            entered.set()
            self.assertTrue(finish.wait(3))
            return vector
        self.models.embed_content.side_effect=embed
        proof=self.proof()
        async def run():
            task=asyncio.create_task(self.asgi_request(headers=self.headers(proof)))
            try:
                for _ in range(100):
                    if entered.is_set():break
                    await asyncio.sleep(.005)
                self.assertTrue(entered.is_set())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertEqual(self.claims(),1)
                self.assertEqual(self.ledger.status()['active'],1)
            finally:finish.set()
            await self.drain()
        asyncio.run(run())
        self.models.generate_content.assert_not_called()
        self.models.reset_mock();self.client_factory.reset_mock()
        self.reject_http(403,proof=proof)

    def test_disconnect_during_upload_does_not_admit(self):
        messages,_=asyncio.run(self.asgi_request(parts=[{'type':'http.disconnect'}]))
        self.assertEqual(messages,[])
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_http_capacity_is_nonblocking_and_bounded_during_upload(self):
        async def run():
            entered,finish=asyncio.Event(),asyncio.Event()
            async def fallback(*args):self.fail('Fallback')
            adapter=SessionChatHTTPAdapter(fallback,application=self.api.app,controls=self.controls)
            from threading import BoundedSemaphore
            adapter.capacity=BoundedSemaphore(1)
            headers=[(k.lower().encode(),v.encode()) for k,v in self.headers()]
            scope={'type':'http','method':'POST','path':PATH,'raw_path':PATH.encode(),'query_string':b'',
                   'http_version':'1.1','headers':headers,'state':{}}
            async def read():
                entered.set();await finish.wait()
                return {'type':'http.disconnect'}
            output=[]
            async def send(message):output.append(message)
            first=asyncio.create_task(adapter(scope,read,send))
            try:
                await entered.wait()
                await adapter(scope,read,send)
                self.assertEqual(self.status(output),503)
            finally:
                finish.set();await first
            self.assertTrue(adapter.capacity.acquire(blocking=False))
            adapter.capacity.release()
        asyncio.run(run())
        self.no_provider()

    def test_pipeline_inherited_deadline_cannot_be_extended(self):
        extended=ChatDiagnostics(time.monotonic(),self.settings.chat_deadline_seconds+1)
        result=asyncio.run(self.pipeline.run(self.scope,self.body,self.proof(),diagnostics=extended))
        self.assertEqual(result.status,503)
        self.assertEqual(self.claims(),0)
        self.no_provider()
