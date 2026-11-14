"""Internal orchestration only; no routes, environment loading or ingress defaults.

Composition must supply trusted authority configuration and a resolver that
independently authorizes visitor identity. A gateway signature alone is not it.
"""
from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
import ipaddress
import math
import re
from threading import BoundedSemaphore
import time
from uuid import uuid4

import anyio

from src.auth import authenticate, AuthenticatedPrincipal, AuthorizationError, Capability
from src.diagnostics import ChatDiagnostics, ChatDeadlineExceeded
from src.gateway_assertions import AssertionError as InvalidAssertion, VerifiedGatewayAssertion
from src.gateway_replay import GatewayReplayService
from src.identity import TrustedIP
from src.provider import ERROR_DETAIL
from src.reliability import CapacityLease
from src.session_chat import SessionChatResult, SessionChatService


class IdentityResolutionError(Exception):
    def __init__(self):
        super().__init__('Request identity unavailable.')


def _configuration(condition):
    if not condition:
        raise ValueError('Internal chat configuration unavailable.')


@dataclass(frozen=True, slots=True)
class GatewayAuthority:
    """Explicit SERVER configuration, never derived from request headers."""
    credential_id: str
    issuer: str
    audience: str
    signing_key_ids: frozenset[str]
    ingress_policy: str
    capability: Capability = field(default=Capability.SESSION_CHAT, init=False)

    def __post_init__(self):
        _configuration(type(self.credential_id) is str and
                       re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', self.credential_id) is not None)
        _configuration(all(type(v) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}', v)
                           for v in (self.issuer, self.audience, self.ingress_policy)))
        _configuration(type(self.signing_key_ids) is frozenset and 1 <= len(self.signing_key_ids) <= 2)
        _configuration(all(type(v) is str and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,31}', v)
                           for v in self.signing_key_ids))


_CONTEXT_SEAL = object()
_RESOLUTION_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedRequestContext:
    """Resolver view: no raw headers, bearer, session token or request body."""
    principal: AuthenticatedPrincipal
    authority: GatewayAuthority
    assertion: VerifiedGatewayAssertion = field(repr=False)
    _diagnostics: ChatDiagnostics = field(repr=False)
    _seal: object = field(repr=False)


@dataclass(frozen=True, slots=True, init=False)
class _Resolution:
    _identity: TrustedIP = field(repr=False)
    _context: AuthenticatedRequestContext = field(repr=False)
    _resolver: object = field(repr=False)
    _seal: object = field(repr=False)


class TrustedIdentityResolver(ABC):
    """Trusted composition extension, NOT an HTTP/header parser.

    Implement _authorize using independently trusted ingress evidence bound to
    this authenticated context. Only exact True authorizes identity construction.
    No production implementation is supplied. Tests use an explicit fixture.
    """
    def __init__(self, policy_id):
        _configuration(type(policy_id) is str and
                       re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}', policy_id) is not None)
        self._policy_id = policy_id

    @abstractmethod
    def _authorize(self, context):
        """Return True ONLY if independent evidence confirms policy and IP."""

    def resolve(self, context):
        if (type(context) is not AuthenticatedRequestContext or context._seal is not _CONTEXT_SEAL
                or context.authority.ingress_policy != self._policy_id
                or context.assertion.ip_source != self._policy_id):
            raise IdentityResolutionError()
        context._diagnostics.check()
        if self._authorize(context) is not True:
            raise IdentityResolutionError()
        context._diagnostics.check()
        # This construction is AFTER explicit resolver authorization, never a
        # default interpretation of a signed IP or any forwarding header.
        identity = TrustedIP(context.assertion.visitor_ip)
        result = object.__new__(_Resolution)
        for name, value in (('_identity', identity), ('_context', context),
                            ('_resolver', self), ('_seal', _RESOLUTION_SEAL)):
            object.__setattr__(result, name, value)
        return result


def _reject(status):
    return SessionChatResult(status, {'detail': ERROR_DETAIL}, {'cache-control': 'no-store'})


class AuthenticatedSessionChatService:
    """Bounded, deadline-supervised adapter around the EXISTING chat service.

    All dependencies/policy are fixed by trusted composition, not per-request
    caller parameters. This class is deliberately never registered with FastAPI.
    """
    def __init__(self, chat, replay, *, authority, identity_resolver):
        _configuration(type(chat) is SessionChatService and type(replay) is GatewayReplayService
                       and type(authority) is GatewayAuthority)
        _configuration(issubclass(type(identity_resolver), TrustedIdentityResolver)
                       and type(identity_resolver).resolve is TrustedIdentityResolver.resolve
                       and getattr(identity_resolver, '_policy_id', None) == authority.ingress_policy)
        settings = chat.settings
        verifier = replay._verifier
        _configuration(authority.credential_id == settings.session_chat_credential_id
                       and authority.capability is Capability.SESSION_CHAT
                       and (authority.issuer, authority.audience, authority.ingress_policy) ==
                           (verifier._issuer, verifier._audience, verifier._ip_source)
                       and authority.signing_key_ids == frozenset(verifier._keys)
                       and replay._ledger.path == settings.usage_path)
        self._chat, self._replay, self._authority = chat, replay, authority
        self._resolver, self._settings = identity_resolver, settings
        self._capacity = BoundedSemaphore(settings.max_concurrent)
        self.tasks = set()

    def _prepare(self, scope, body, compact, principal, diagnostics):
        diagnostics.check()
        # Snapshot only bounded immutable wire inputs. Never inherit leases,
        # diagnostics or authenticated principals from caller-controlled state.
        if type(scope) is not dict or type(body) is not bytes:
            return _reject(400)
        if len(body) > min(self._settings.max_body_bytes, 8192):
            return _reject(413)
        headers = scope.get('headers', [])
        if type(headers) not in (list, tuple) or len(headers) > 32:
            return _reject(400)
        if any(type(pair) not in (list, tuple) or len(pair) != 2
               or any(type(v) is not bytes for v in pair) for pair in headers):
            return _reject(400)
        headers = [(k.lower(), v) for k, v in headers]
        if sum(len(k) + len(v) for k, v in headers) > 8192:
            return _reject(400)
        state = scope.get('state', {})
        if type(state) is not dict:
            return _reject(400)
        state = ({key: state[key] for key in ('request_id', '_capability_marker') if key in state}
                 if principal is not None else {'request_id': uuid4().hex})
        request = {key: scope[key] for key in ('type', 'method', 'path', 'raw_path', 'query_string',
                                              'root_path', 'http_version', 'client', 'server') if key in scope}
        request['state'], request['headers'] = state, headers
        actor = authenticate(self._settings, request, required=Capability.SESSION_CHAT, principal=principal)
        if actor.credential_id != self._authority.credential_id:
            return _reject(401)
        if any(k == b'origin' for k, _ in headers):
            return _reject(403)
        content = [v for k, v in headers if k == b'content-type']
        encoding = [v for k, v in headers if k == b'content-encoding']
        if (content != [b'application/json'] or encoding not in ([], [b'identity'])):
            return _reject(415)
        sessions = [v for k, v in headers if k == b'x-portfolio-session']
        if len(sessions) != 1:
            return _reject(401)
        try:
            session = sessions[0].decode('ascii')
        except UnicodeError:
            return _reject(401)
        diagnostics.check()
        verified = self._replay._verifier.verify(compact, session_token=session, body=body,
                    method=request.get('method'), path=request.get('path'), now=self._replay._ledger._now())
        authority = self._authority
        if ((actor.credential_id, actor.capability, verified.issuer, verified.audience, verified.ip_source) !=
                (authority.credential_id, authority.capability, authority.issuer, authority.audience, authority.ingress_policy)
                or verified.key_id not in authority.signing_key_ids):
            return _reject(403)
        diagnostics.check()
        self._replay.claim(verified)
        diagnostics.check()
        context = object.__new__(AuthenticatedRequestContext)
        for name, value in (('principal', actor), ('authority', authority), ('assertion', verified),
                            ('_diagnostics', diagnostics), ('_seal', _CONTEXT_SEAL)):
            object.__setattr__(context, name, value)
        resolution = TrustedIdentityResolver.resolve(self._resolver, context)
        if (type(resolution) is not _Resolution or resolution._seal is not _RESOLUTION_SEAL
                or resolution._context is not context or resolution._resolver is not self._resolver
                or type(resolution._identity) is not TrustedIP):
            raise IdentityResolutionError()
        address = ipaddress.ip_address(verified.visitor_ip)
        if (resolution._identity._version != address.version or resolution._identity._packed != address.packed):
            raise IdentityResolutionError()
        diagnostics.check()
        return request, actor, resolution._identity

    async def run(self, gateway_scope, body, assertion, *, principal=None, diagnostics=None):
        started = time.monotonic()
        if diagnostics is None:
            diagnostics = ChatDiagnostics(started, self._settings.chat_deadline_seconds)
        elif (type(diagnostics) is not ChatDiagnostics
              or not all(type(v) in (int, float) and math.isfinite(v) for v in (diagnostics.started, diagnostics.deadline))
              or diagnostics.started > started
              or diagnostics.deadline > diagnostics.started + self._settings.chat_deadline_seconds):
            return _reject(503)
        try:
            diagnostics.check()
        except ChatDeadlineExceeded:
            return _reject(504)
        settings = self._settings
        if (settings.capability_auth_enabled is not True or settings.session_chat_enabled is not True
                or settings.staging_auth_enabled is not True or settings.session_admission_enabled is not True
                or settings.ip_admission_enabled is not True or self._chat.settings != settings
                or self._chat.controls.settings != settings):
            return _reject(503)
        if not self._capacity.acquire(blocking=False):
            return _reject(503)
        lease = CapacityLease(self._capacity, operation_owned=True)

        def prepare():
            if not lease.start():
                raise ChatDeadlineExceeded()
            try:
                return self._prepare(gateway_scope, body, assertion, principal, diagnostics)
            finally:
                lease.release()

        async def execute():
            try:
                prepared = await anyio.to_thread.run_sync(prepare)
                diagnostics.check()
                if type(prepared) is SessionChatResult:
                    return prepared
                request, actor, identity = prepared
                async def chunks():
                    yield body
                return await self._chat.run(request, chunks(), identity=identity, principal=actor, diagnostics=diagnostics)
            except AuthorizationError as error:
                return _reject(error.status)
            except InvalidAssertion:
                return _reject(403)
            except IdentityResolutionError:
                return _reject(403)
            except ChatDeadlineExceeded:
                return _reject(504)
            except Exception as error:
                from src.usage import UsageDenied
                return _reject(error.status if isinstance(error, UsageDenied) else 500)

        task = asyncio.create_task(execute())
        self.tasks.add(task)
        def completed(done):
            self.tasks.discard(done)
            lease.finish_operation()
            if not done.cancelled():
                done.exception()  # Consume abandoned failures without content logging.
        task.add_done_callback(completed)
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0.0, diagnostics.deadline - time.monotonic()))
            if not done or time.monotonic() >= diagnostics.deadline:
                diagnostics.stop()
                lease.abort()
                task.cancel()
                return _reject(504)
            return task.result()
        except asyncio.CancelledError:
            diagnostics.stop()
            lease.abort()
            task.cancel()
            raise
