"""Offline internal orchestration: real guards/SQLite, mocked Gemini, fixture ingress."""
import asyncio
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
from threading import BoundedSemaphore, Event
import time
from unittest.mock import patch
from uuid import uuid4

from src.auth import AuthenticatedPrincipal, Capability, authenticate
from src.authenticated_session_chat import (AuthenticatedSessionChatService, GatewayAuthority,
                                          TrustedIdentityResolver)
from src.diagnostics import ChatDiagnostics
from src.gateway_assertions import GatewayAssertionVerifier, VerificationKey
from src.gateway_replay import GatewayReplayService
from src.identity import TrustedIP
from src.reliability import RateLimiter
from src.session_chat import SessionChatService
from tests.test_auth import configuration
from tests.test_ip_admission import IPFixture

KEY = bytes(range(1, 33))  # public test-only data
POLICY = 'offline-fixture-ingress'


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class FixtureResolver(TrustedIdentityResolver):
    """Explicit test evidence. This does NOT model production ingress trust."""
    def __init__(self, address='192.0.2.10', policy=POLICY):
        super().__init__(policy)
        self.address = address
        self.calls = []
        self.result = True
        self.wait = None

    def _authorize(self, context):
        self.calls.append(context)
        if self.wait is not None:
            self.wait()
        return (self.result if context.assertion.visitor_ip == self.address
                and context.assertion.ip_source == self._policy_id
                and context.principal.credential_id == 'session-chat-v1'
                and context.authority.issuer == 'portfolio-gateway' else False)


class IntegrationFixture(IPFixture):
    def setUp(self):
        super().setUp()
        self.ledger.set_disabled(True)
        self.ledger.migrate_verification(workers_stopped=True)
        self.ledger.migrate_gateway_replay(workers_stopped=True)
        self.ledger.set_disabled(False)
        self.settings = replace(configuration(self.settings), session_chat_enabled=True)
        self.api = self.load('src.api')
        self.controls = self.api.app.state.chat_controls
        self.controls.settings = self.settings
        self.controls.authenticated_budget = RateLimiter(1000, 60, 1)
        self.controls.rate_limiter = RateLimiter(1000, 60, 1)
        # Existing lifespan loads the offline synthetic index without provider calls.
        from fastapi.testclient import TestClient
        self.http = self.stack.enter_context(TestClient(self.api.app))
        self.chat = SessionChatService(self.settings, self.controls, self.api.app, self.api.ChatRequest, self.api._chat_worker)
        self.verifier = GatewayAssertionVerifier(issuer='portfolio-gateway', audience='portfolio-backend', ip_source=POLICY,
            current_key=VerificationKey('gateway-key-1', KEY, 0, 253402300799))
        self.replay = GatewayReplayService(self.ledger, self.verifier)
        self.authority = GatewayAuthority('session-chat-v1', 'portfolio-gateway', 'portfolio-backend',
                                          frozenset({'gateway-key-1'}), POLICY)
        self.resolver = FixtureResolver()
        self.pipeline = self.make_pipeline()
        self.logs = self.stack.enter_context(patch('src.reliability.logger.info'))
        self.scope = {'type': 'http', 'method': 'POST', 'path': '/internal/session-chat',
                      'raw_path': b'/internal/session-chat', 'query_string': b'', 'http_version': '1.1',
                      'headers': [(b'authorization', b'Bearer '+b'c'*43), (b'x-portfolio-session', self.raw.encode()),
                                  (b'content-type', b'application/json')], 'state': {}}
        self.body = b'{"message":"What is BundesHost?"}'

    def make_pipeline(self, **kwargs):
        return AuthenticatedSessionChatService(self.chat, self.replay, authority=kwargs.get('authority', self.authority),
                                               identity_resolver=kwargs.get('resolver', self.resolver))

    def proof(self, *, body=None, session=None, **changes):
        header = {'typ': 'portfolio-gateway-assertion-v1', 'alg': 'HS256', 'kid': 'gateway-key-1'}
        timestamp = int(self.now.timestamp())
        payload = {'v': 1, 'iss': 'portfolio-gateway', 'aud': 'portfolio-backend', 'scope': 'session:chat',
                   'method': 'POST', 'path': '/internal/session-chat', 'iat': timestamp, 'exp': timestamp+30,
                   'jti': b64(hashlib.sha256(uuid4().bytes).digest()),
                   'session_sha256': hashlib.sha256((self.raw if session is None else session).encode()).hexdigest(),
                   'body_sha256': hashlib.sha256(self.body if body is None else body).hexdigest(),
                   'visitor_ip': '192.0.2.10', 'ip_source': POLICY}
        payload.update(changes)
        parts = '.'.join(b64(json.dumps(v, separators=(',', ':')).encode()) for v in (header, payload))
        return parts + '.' + b64(hmac.digest(KEY, parts.encode(), 'sha256'))

    def claims(self):
        with sqlite3.connect(self.usage_path) as db:
            return db.execute('SELECT count(*) FROM gateway_replay_claims').fetchone()[0]

    def invoke(self, *, scope=None, body=None, proof=None, principal=None):
        return asyncio.run(self.pipeline.run(self.scope if scope is None else scope,
            self.body if body is None else body, self.proof() if proof is None else proof, principal=principal))

    def no_provider(self):
        self.models.embed_content.assert_not_called()
        self.models.generate_content.assert_not_called()
        self.client_factory.assert_not_called()

    def configure(self, **changes):
        self.settings = replace(self.settings, **changes)
        self.chat.settings = self.settings
        self.controls.settings = self.settings
        self.pipeline = self.make_pipeline()

    def reject(self, status=None, **kwargs):
        result = self.invoke(**kwargs)
        self.assertNotEqual(result.status, 200)
        if status is not None:
            self.assertEqual(result.status, status)
        self.assertIn('detail', result.body)
        self.assertEqual(result.headers['cache-control'], 'no-store')
        for secret in ('c'*43, 'i'*43, 's'*43, self.raw, '192.0.2.10', KEY.hex()):
            self.assertNotIn(secret, str(result))
        self.no_provider()
        return result


class AuthenticatedChatSecurityTests(IntegrationFixture):
    def test_valid_complete_request_counts_each_admission_once(self):
        result = self.invoke()
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, {'answer':'Offline test answer.'})
        self.assertEqual(self.claims(), 1)
        self.assertEqual(self.ledger.status()['periods']['day'], {'admitted':1,'embedding_ops':1,'generation_ops':1})
        self.assertEqual(self.ledger.status()['active'], 0)
        self.assertEqual(len(self.rows()['session_events']), 1)
        self.assertEqual(len(self.rows()['ip_events']), 1)
        self.assertEqual(len(self.resolver.calls), 1)

    def test_feature_flags_still_disabled_by_default_and_mandatory(self):
        from src.config import Settings
        self.assertFalse(Settings().session_chat_enabled)
        original = self.settings
        for flag in ('capability_auth_enabled', 'session_chat_enabled', 'staging_auth_enabled',
                     'session_admission_enabled', 'ip_admission_enabled'):
            self.configure(**{flag:False})
            self.reject(503)
            self.configure(**{flag:getattr(original, flag)})
        self.assertEqual(self.claims(), 0)

    def test_wrong_credentials_and_wrong_capabilities(self):
        for value in (b'w'*43, b'i'*43, b's'*43, b'', b'Basic invalid'):
            headers = [(b'authorization', b'Bearer '+value), *self.scope['headers'][1:]]
            self.reject(401, scope={**self.scope,'headers':headers})
        self.assertEqual(self.claims(), 0)

    def test_missing_malformed_duplicate_bearers(self):
        for headers in (self.scope['headers'][1:], [self.scope['headers'][0], *self.scope['headers']],
                        [(b'authorization',b'Bearer '+b'c'*43+b', Bearer '+b'c'*43),*self.scope['headers'][1:]]):
            self.reject(401, scope={**self.scope, 'headers':headers})
        self.assertEqual(self.claims(), 0)

    def test_forged_modified_and_wrong_request_principals(self):
        for principal in ({'capability':'session_chat'}, AuthenticatedPrincipal()):
            self.reject(401, principal=principal)
        principal = authenticate(self.settings, self.scope, required=Capability.SESSION_CHAT)
        for field, value in (('capability', Capability.LEGACY_STAGING), ('capability', Capability.VERIFIED_SESSION_ISSUANCE),
                             ('credential_id','unrelated-gateway'),('method','GET'),('path','/chat'),
                             ('_fingerprint',b'x'*32),('request_id',uuid4().hex)):
            changed = copy.copy(principal)
            object.__setattr__(changed, field, value)
            self.reject(401, principal=changed)
        fresh = {**self.scope,'state':{}}
        other = authenticate(self.settings, fresh, required=Capability.SESSION_CHAT)
        self.reject(401, principal=other)
        self.assertEqual(self.claims(), 0)

    def test_valid_pre_authenticated_principal_is_revalidated(self):
        principal = authenticate(self.settings, self.scope, required=Capability.SESSION_CHAT)
        self.assertEqual(self.invoke(principal=principal).status, 200)

    def test_authority_configuration_cannot_combine_unrelated_gateway_or_key(self):
        for changes in ({'credential_id':'other-gateway'}, {'issuer':'other-issuer'}, {'audience':'other-audience'},
                        {'signing_key_ids':frozenset({'other-key'})}, {'ingress_policy':'other-ingress'}):
            with self.assertRaises(ValueError) as error:
                self.make_pipeline(authority=replace(self.authority, **changes))
            self.assertEqual(str(error.exception),'Internal chat configuration unavailable.')
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_wrong_issuer_audience_policy_and_scope(self):
        for changes in ({'iss':'other-gateway'}, {'aud':'other-backend'}, {'ip_source':'other-ingress'}, {'scope':'legacy_staging'}):
            self.reject(403, proof=self.proof(**changes))
        self.assertEqual(self.claims(),0)

    def test_bad_signature_body_session_and_exact_http_binding(self):
        proof = self.proof()
        h,p,signature=proof.split('.')
        self.reject(403, proof=h+'.'+p+'.'+b64(b'X'*32))
        header=json.loads(base64.urlsafe_b64decode(h+'='*(-len(h)%4)))
        unknown=b64(json.dumps({**header,'kid':'unrelated-key'}).encode())+'.'+p
        self.reject(403, proof=unknown+'.'+b64(hmac.digest(KEY,unknown.encode(),'sha256')))
        self.reject(403, proof=proof, body=self.body+b' ')
        self.reject(403, proof=self.proof(session=b64(b'X'*32)))
        for changes in ({'method':'GET'}, {'path':'/chat'}, {'path':'/internal/session-chat/'},
                        {'query_string':b'x=1'}, {'raw_path':b'/internal/%73ession-chat'}):
            self.reject(401, scope={**self.scope, **changes})
        for changes in ({'method':'GET'}, {'path':'/chat'}):
            self.reject(403, proof=self.proof(**changes))
        self.assertEqual(self.claims(),0)

    def test_expired_and_future_assertions(self):
        now = int(self.now.timestamp())
        self.reject(403, proof=self.proof(iat=now-30, exp=now))
        self.reject(403, proof=self.proof(iat=now+6, exp=now+30))
        self.assertEqual(self.claims(),0)

    def test_duplicate_assertion_rejected_without_duplicate_admission(self):
        proof = self.proof()
        self.assertEqual(self.invoke(proof=proof).status, 200)
        self.models.reset_mock()
        self.client_factory.reset_mock()
        self.reject(403, proof=proof)
        self.assertEqual(self.claims(),1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_concurrent_replay_exactly_one_execution(self):
        proof = self.proof()
        async def run():
            return await asyncio.gather(*(self.pipeline.run(self.scope,self.body,proof) for _ in range(4)))
        results=asyncio.run(run())
        self.assertEqual(sum(r.status==200 for r in results),1)
        self.assertEqual(self.models.generate_content.call_count,1)
        self.assertEqual(self.claims(),1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_replay_survives_service_reconstruction(self):
        proof=self.proof()
        self.assertEqual(self.invoke(proof=proof).status,200)
        self.models.reset_mock(); self.client_factory.reset_mock()
        self.pipeline=self.make_pipeline()
        self.reject(403,proof=proof)

    def test_missing_and_wrong_schema_replay_storage(self):
        original=self.usage_path.read_bytes()
        self.usage_path.unlink()
        self.reject(503)
        self.assertFalse(self.usage_path.exists())
        self.usage_path.write_bytes(original)
        with sqlite3.connect(self.usage_path) as db: db.execute('PRAGMA user_version=5')
        self.reject(503)

    def test_missing_untrusted_or_wrong_policy_resolver_refused(self):
        for resolver in (None, lambda context:True, TrustedIP('192.0.2.10'), FixtureResolver(policy='other-ingress')):
            with self.assertRaises(ValueError): self.make_pipeline(resolver=resolver)
        class Override(FixtureResolver):
            def resolve(self,context): return TrustedIP('192.0.2.10')
        with self.assertRaises(ValueError): self.make_pipeline(resolver=Override())
        self.no_provider()

    def test_resolver_policy_ip_and_verification_failures_consume_claim(self):
        for result in (False, None, '192.0.2.10', TrustedIP('192.0.2.10'), {'verified':True}):
            self.resolver.result=result
            self.reject(403)
        self.resolver.result=True
        self.resolver.address='192.0.2.99'
        self.reject(403)
        self.assertEqual(self.claims(),6)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],0)

    def test_no_trusted_ip_constructed_before_resolver_authorization(self):
        self.resolver.result=False
        with patch('src.authenticated_session_chat.TrustedIP') as mint:
            self.reject(403)
        mint.assert_not_called()

    def test_forwarded_headers_do_not_resolve_identity_or_select_authority(self):
        self.resolver.result=False
        headers=[*self.scope['headers'], (b'x-forwarded-for',b'192.0.2.10'), (b'x-real-ip',b'192.0.2.10'),
                 (b'cf-connecting-ip',b'192.0.2.10'),(b'x-credential-id',b'session-chat-v1')]
        self.reject(403,scope={**self.scope,'headers':headers})

    def test_missing_malformed_duplicate_session_headers(self):
        auth,session,content=self.scope['headers']
        for headers in ([auth,content],[auth,session,session,content], [auth,(b'x-portfolio-session',b'short'),content],
                        [auth,(b'x-portfolio-session',b'\xff'*43),content]):
            self.reject(scope={**self.scope,'headers':headers})
        self.assertEqual(self.claims(),0)

    def test_unknown_unverified_expired_revoked_sessions(self):
        for field,value in (('verified',0),('revoked',1)):
            with sqlite3.connect(self.usage_path) as db: db.execute(f'UPDATE sessions SET {field}=?',(value,))
            self.reject(401)
            with sqlite3.connect(self.usage_path) as db: db.execute(f'UPDATE sessions SET {field}=?',(1-value,))
        old=self.now
        self.now+=timedelta(hours=4)
        self.reject(401)
        self.now=old
        # Clock floor from the expired-session attempt remains forward; use a
        # separate unknown token under the current trusted accounting time.
        self.now+=timedelta(hours=4)
        unknown=b64(b'Z'*32)
        scope={**self.scope,'headers':[(k, unknown.encode() if k==b'x-portfolio-session' else v) for k,v in self.scope['headers']]}
        self.reject(401,scope=scope,proof=self.proof(session=unknown))

    def test_session_ip_global_limits_and_concurrency_still_enforced(self):
        self.ledger.reserve_session(self.digest,identity_digest=self.identity.digest(self.key),identity_key_tag=self.tag)
        # Existing abandoned slot is intentional; no recovery/refund here.
        self.configure(session_admission_minute_limit=1)
        self.reject(429)
        self.configure(session_admission_minute_limit=3,ip_admission_minute_limit=1)
        self.reject(429)
        self.configure(ip_admission_minute_limit=10)
        self.ledger.daily=1
        self.reject(429)
        self.ledger.daily=100
        self.ledger.monthly=1
        self.reject(429)
        self.ledger.monthly=1000
        self.ledger.concurrent=1
        self.reject(503)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_emergency_shutdown_blocks_before_replay_and_execution(self):
        self.ledger.set_disabled(True)
        self.reject(503)
        self.assertEqual(self.claims(),0)

    def test_request_schema_content_type_origin_and_body_limits_preserved(self):
        for body in (b'{', b'{"message":""}', b'{"message":"PRIVATE","extra":true}',
                     b'{"message":"PRIVATE","message":"other"}'):
            self.reject(body=body,proof=self.proof(body=body))
        for headers in ([*self.scope['headers'],(b'origin',b'https://browser.test')],
                        [(k,b'text/plain' if k==b'content-type' else v) for k,v in self.scope['headers']]):
            self.reject(scope={**self.scope,'headers':headers})
        self.reject(413,body=b'X'*8193)

    def test_ipv6_fixture_identity_uses_existing_pseudonymous_admission(self):
        self.resolver.address='2001:db8::10'
        result=self.invoke(proof=self.proof(visitor_ip='2001:db8::10'))
        self.assertEqual(result.status,200)
        with sqlite3.connect(self.usage_path) as db:
            rows=db.execute('SELECT identity FROM ip_events').fetchall()
            dump='\n'.join(db.iterdump())
        self.assertEqual(rows,[(TrustedIP('2001:db8::10').digest(self.key),)])
        self.assertNotIn('2001:db8::10',dump)

    def test_resolver_failure_after_claim_is_sanitized_and_consumed(self):
        def fail():raise RuntimeError('PRIVATE RESOLVER CONTENT')
        self.resolver.wait=fail
        proof=self.proof()
        self.reject(500,proof=proof)
        self.resolver.wait=None
        self.reject(403,proof=proof)
        self.assertEqual(self.claims(),1)

    def test_resolver_runs_after_replay_transaction_has_closed(self):
        def prove_unlocked():
            with sqlite3.connect(self.usage_path,isolation_level=None,timeout=.01) as db:
                db.execute('BEGIN IMMEDIATE')
                self.assertEqual(db.execute('SELECT count(*) FROM gateway_replay_claims').fetchone()[0],1)
                db.execute('COMMIT')
        self.resolver.wait=prove_unlocked
        self.assertEqual(self.invoke().status,200)

    def test_forged_resolved_identity_does_not_match_authenticated_context(self):
        original=TrustedIdentityResolver.resolve
        def corrupt(resolver,context):
            resolution=original(resolver,context)
            object.__setattr__(resolution._identity,'_packed',bytes([192,0,2,99]))
            return resolution
        with patch.object(TrustedIdentityResolver,'resolve',corrupt):
            self.reject(403)
        self.assertEqual(self.claims(),1)

    def test_caller_state_cannot_supply_authorization_or_extend_deadline(self):
        scope={**self.scope,'state':{'authenticated_principal':AuthenticatedPrincipal(),
            'chat_diagnostics':ChatDiagnostics(time.monotonic(),99999),'request_id':'caller-selected'}}
        self.assertEqual(self.invoke(scope=scope).status,200)
        self.assertNotEqual(self.resolver.calls[0].principal.request_id,'caller-selected')
        self.assertLessEqual(self.resolver.calls[0]._diagnostics.deadline,
                            self.resolver.calls[0]._diagnostics.started+self.settings.chat_deadline_seconds)

    def test_no_new_http_route_no_legacy_dispatch_and_no_secret_logging(self):
        with patch.object(self.api,'chat',side_effect=RuntimeError('Legacy dispatch forbidden')):
            self.assertEqual(self.invoke().status,200)
        self.assertNotIn('/internal/session-chat',{r.path for r in self.api.app.routes})
        logs=' '.join(str(c) for c in self.logs.call_args_list)
        for secret in ('c'*43,self.raw,'192.0.2.10',self.body.decode(),KEY.hex()): self.assertNotIn(secret,logs)
        with sqlite3.connect(self.usage_path) as db: dump='\n'.join(db.iterdump())
        self.assertNotIn('192.0.2.10',dump)


class AuthenticatedChatLifecycleTests(IntegrationFixture):
    async def drain(self):
        for _ in range(200):
            if not self.pipeline.tasks and not self.controls.tasks and self.ledger.status()['active']==0:
                return
            await asyncio.sleep(.01)
        self.fail('Temporary internal tasks did not drain')

    def test_deadline_covers_slow_verification_before_claim(self):
        self.configure(chat_deadline_seconds=.06)
        entered,finish,exited=Event(),Event(),Event()
        original=self.verifier.verify
        def slow(*args,**kwargs):
            entered.set()
            try:
                self.assertTrue(finish.wait(3))
                return original(*args,**kwargs)
            finally: exited.set()
        async def run():
            with patch.object(self.verifier,'verify',slow):
                try:
                    result=await self.pipeline.run(self.scope,self.body,self.proof())
                    self.assertEqual(result.status,504)
                    self.assertTrue(entered.is_set())
                    self.assertFalse(exited.is_set())
                    self.assertEqual(self.claims(),0)
                finally: finish.set()
                for _ in range(100):
                    if exited.is_set(): break
                    await asyncio.sleep(.01)
                await self.drain()
        asyncio.run(run())
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_slow_replay_keeps_claim_but_cannot_start_provider_after_deadline(self):
        self.configure(chat_deadline_seconds=.06)
        entered,finish,exited=Event(),Event(),Event()
        original=self.replay.claim
        def slow(value):
            original(value)
            entered.set()
            try: self.assertTrue(finish.wait(3))
            finally: exited.set()
        proof=self.proof()
        async def run():
            with patch.object(self.replay,'claim',slow):
                try:
                    result=await self.pipeline.run(self.scope,self.body,proof)
                    self.assertEqual(result.status,504)
                    self.assertTrue(entered.is_set())
                    self.assertEqual(self.claims(),1)
                    self.assertFalse(exited.is_set())
                finally: finish.set()
                for _ in range(100):
                    if exited.is_set(): break
                    await asyncio.sleep(.01)
                await self.drain()
        asyncio.run(run())
        self.reject(403,proof=proof)

    def test_slow_resolver_holds_preprocessing_capacity_without_unbounded_workers(self):
        self.configure(chat_deadline_seconds=.06)
        self.pipeline._capacity=BoundedSemaphore(1)
        entered,finish,exited=Event(),Event(),Event()
        def wait():
            entered.set()
            try: self.assertTrue(finish.wait(3))
            finally: exited.set()
        self.resolver.wait=wait
        async def run():
            first=asyncio.create_task(self.pipeline.run(self.scope,self.body,self.proof()))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(.002)
                self.assertTrue(entered.is_set())
                for _ in range(10):
                    self.assertEqual((await self.pipeline.run(self.scope,self.body,self.proof())).status,503)
                self.assertEqual((await first).status,504)
                self.assertFalse(exited.is_set())
                self.assertFalse(self.pipeline._capacity.acquire(blocking=False))
                self.assertEqual(len(self.resolver.calls),1)
            finally: finish.set()
            for _ in range(100):
                if self.pipeline._capacity.acquire(blocking=False):
                    self.pipeline._capacity.release()
                    break
                await asyncio.sleep(.01)
            else: self.fail('Preprocessing capacity leaked')
            await self.drain()
        asyncio.run(run())
        self.no_provider()
        self.assertEqual(self.claims(),1)

    def test_worker_inherits_original_deadline_and_preserves_active_capacity(self):
        self.configure(chat_deadline_seconds=.3)
        self.resolver.wait=lambda:time.sleep(.09)
        entered,finish,exited=Event(),Event(),Event()
        vector=self.models.embed_content.return_value
        remaining=[]
        def slow(**kwargs):
            from src.diagnostics import current_diagnostics
            current=current_diagnostics.get()
            self.assertIs(current,self.resolver.calls[0]._diagnostics)
            remaining.append(current.deadline-time.monotonic())
            entered.set()
            try: self.assertTrue(finish.wait(3))
            finally: exited.set()
            return vector
        self.models.embed_content.side_effect=slow
        self.controls.capacity=BoundedSemaphore(1)
        async def run():
            before=time.monotonic()
            try:
                result=await self.pipeline.run(self.scope,self.body,self.proof())
                self.assertEqual(result.status,504)
                self.assertLess(time.monotonic()-before,.9)
                self.assertTrue(entered.is_set())
                self.assertLess(remaining[0],.24)
                self.assertFalse(exited.is_set())
                self.assertEqual(self.ledger.status()['active'],1)
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally: finish.set()
            await self.drain()
            self.assertTrue(self.controls.capacity.acquire(blocking=False))
            self.controls.capacity.release()
        asyncio.run(run())
        self.models.generate_content.assert_not_called()
        self.assertEqual(self.claims(),1)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)
        # No late success response/log can be emitted by the abandoned worker.
        for call in self.logs.call_args_list:
            self.assertNotEqual(json.loads(call.args[0])['status'],200)

    def test_slow_session_admission_consumes_deadline_without_provider_execution(self):
        self.configure(chat_deadline_seconds=.06)
        entered,finish=Event(),Event()
        original=self.ledger.reserve_session
        def slow(*args,**kwargs):
            entered.set()
            self.assertTrue(finish.wait(3))
            return original(*args,**kwargs)
        async def run():
            with patch.object(self.ledger,'reserve_session',slow):
                try:
                    result=await self.pipeline.run(self.scope,self.body,self.proof())
                    self.assertEqual(result.status,504)
                    self.assertTrue(entered.is_set())
                finally: finish.set()
                await self.drain()
        asyncio.run(run())
        self.no_provider()
        self.assertEqual(self.claims(),1)

    def test_worker_pool_delay_counts_toward_single_deadline(self):
        self.configure(chat_deadline_seconds=.06)
        entered,finish=Event(),Event()
        def occupy():
            entered.set()
            self.assertTrue(finish.wait(3))
        async def run():
            import anyio
            limiter=anyio.to_thread.current_default_thread_limiter()
            old=limiter.total_tokens
            limiter.total_tokens=1
            blocker=asyncio.create_task(anyio.to_thread.run_sync(occupy))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(.002)
                result=await self.pipeline.run(self.scope,self.body,self.proof())
                self.assertEqual(result.status,504)
            finally:
                finish.set()
                await blocker
                limiter.total_tokens=old
            await self.drain()
        asyncio.run(run())
        self.assertEqual(self.claims(),0)
        self.no_provider()

    def test_provider_failure_after_claim_never_refunds_or_retries(self):
        self.models.generate_content.side_effect=TimeoutError('PRIVATE PROVIDER CONTENT')
        proof=self.proof()
        result=self.invoke(proof=proof)
        self.assertEqual(result.status,504)
        self.assertNotIn('PRIVATE',str(result))
        self.assertEqual(self.claims(),1)
        self.assertEqual(self.models.generate_content.call_count,1)
        self.assertEqual(self.ledger.status()['periods']['day']['generation_ops'],1)
        self.models.reset_mock(); self.client_factory.reset_mock()
        self.reject(403,proof=proof)
        self.assertEqual(self.ledger.status()['periods']['day']['admitted'],1)

    def test_cancellation_after_claim_preserves_claim_and_worker_owned_cleanup(self):
        entered,finish=Event(),Event()
        vector=self.models.embed_content.return_value
        def slow(**kwargs):
            entered.set()
            self.assertTrue(finish.wait(3))
            return vector
        self.models.embed_content.side_effect=slow
        self.controls.capacity=BoundedSemaphore(1)
        proof=self.proof()
        async def run():
            task=asyncio.create_task(self.pipeline.run(self.scope,self.body,proof))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(.005)
                self.assertTrue(entered.is_set())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertEqual(self.claims(),1)
                self.assertEqual(self.ledger.status()['active'],1)
                self.assertFalse(self.controls.capacity.acquire(blocking=False))
            finally: finish.set()
            await self.drain()
        asyncio.run(run())
        self.models.generate_content.assert_not_called()
        self.models.reset_mock();self.client_factory.reset_mock()
        self.reject(403,proof=proof)

    def test_cancellation_during_resolver_does_not_mint_or_execute(self):
        entered,finish,exited=Event(),Event(),Event()
        def slow():
            entered.set()
            try:self.assertTrue(finish.wait(3))
            finally:exited.set()
        self.resolver.wait=slow
        async def run():
            task=asyncio.create_task(self.pipeline.run(self.scope,self.body,self.proof()))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(.005)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):await task
                self.assertEqual(self.claims(),1)
            finally:finish.set()
            for _ in range(100):
                if exited.is_set(): break
                await asyncio.sleep(.005)
            await self.drain()
        asyncio.run(run())
        self.no_provider()

    def test_inherited_deadline_cannot_be_extended_by_session_service(self):
        principal=authenticate(self.settings,self.scope,required=Capability.SESSION_CHAT)
        async def chunks():yield self.body
        diagnostics=ChatDiagnostics(time.monotonic()-.1,self.settings.chat_deadline_seconds+.2)
        result=asyncio.run(self.chat.run(self.scope,chunks(),identity=self.identity,principal=principal,diagnostics=diagnostics))
        self.assertEqual(result.status,503)
        diagnostics=ChatDiagnostics(time.monotonic()-2,1)
        result=asyncio.run(self.chat.run(self.scope,chunks(),identity=self.identity,principal=principal,diagnostics=diagnostics))
        self.assertEqual(result.status,504)
        self.no_provider()
