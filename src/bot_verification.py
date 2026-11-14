"""Provisional Turnstile adapter and internal verified issuance service.

Protocol assumptions are isolated here, not assertions about current vendor
guarantees. No client is constructed or network used while disabled.
"""

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
from threading import BoundedSemaphore

import anyio
import httpx

from src.reliability import staging_authorized, logger
from src.usage import UsageDenied, UsageLedger
from src.auth import authenticate, Capability, AuthorizationError


SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
PROOF_LIMIT = 2048  # Conservative provisional local policy, not a vendor guarantee.
RESPONSE_LIMIT = 8192


class VerificationError(Exception):
    def __init__(self, category='invalid', status=403):
        super().__init__('Verification unavailable.')
        self.category, self.status = category, status


# Request-local diagnostics contain only fixed vocabulary, never exception text.
_diagnostic = ContextVar('verification_diagnostic', default=None)
_CATEGORIES = frozenset({
    'invalid', 'disabled', 'configuration', 'authentication', 'request', 'capacity',
    'provider', 'provider_http_status', 'provider_content_encoding',
    'timeout', 'network', 'age', 'usage_storage', 'usage_disabled',
    'usage_issuance_disabled', 'usage_clock', 'usage_issuance_budget',
    'verification_budget', 'verification_capacity', 'verification_replay',
})
_EXCEPTION_TYPES = (
    VerificationError, UsageDenied, AuthorizationError, RuntimeError, ValueError,
    TypeError, KeyError, AttributeError, OSError, FileNotFoundError, PermissionError,
    TimeoutError, asyncio.CancelledError, httpx.HTTPError, httpx.ConnectError,
    httpx.ReadError, httpx.WriteError, httpx.CloseError, httpx.ConnectTimeout,
    httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.ProtocolError,
    httpx.RemoteProtocolError, httpx.LocalProtocolError, httpx.ProxyError,
    httpx.DecodingError, httpx.UnsupportedProtocol,
)


def _exception_class(error):
    # Identity comparison prevents arbitrary exception class names entering logs.
    return next((kind.__name__ for kind in _EXCEPTION_TYPES if type(error) is kind), 'Exception')


def verification_stage(stage):
    state = _diagnostic.get()
    if state is not None:
        state['stage'] = stage


def _transport_failure(error):
    verification_stage('cloudflare_transport')
    state = _diagnostic.get()
    if state is not None:
        state['exception_class'] = _exception_class(error)


@contextmanager
def verification_diagnostics(request_id):
    """Log one sanitized failure without changing the endpoint's exception handling."""
    state = {'stage': 'configuration', 'exception_class': None}
    token = _diagnostic.set(state)
    try:
        yield
    except BaseException as error:
        category = error.category if type(error) in (VerificationError, UsageDenied) else None
        status = error.status if type(error) in (VerificationError, UsageDenied) else 503
        event = {
            'event': 'verified_session_failure',
            'request_id': request_id if type(request_id) is str and re.fullmatch(r'[0-9a-f]{32}', request_id) else None,
            'stage': state['stage'],
            'category': category if type(category) is str and category in _CATEGORIES else 'unexpected',
            'exception_class': state['exception_class'] or _exception_class(error),
            'status': status if type(status) is int and 400 <= status <= 599 else 503,
        }
        try:
            logger.warning(json.dumps(event))
        except Exception:
            # Diagnostic sink failure must not alter admission or public responses.
            pass
        raise
    finally:
        _diagnostic.reset(token)


def validate_proof(proof):
    if type(proof) is not str or re.fullmatch(r'[!-~]{1,2048}', proof) is None:
        raise VerificationError()


def validate_policy(settings):
    if (settings.bot_verification_enabled is not True or settings.staging_auth_enabled is not True
            or settings.session_issuance_enabled is not True):
        raise VerificationError('disabled', 503)
    if (not isinstance(settings.bot_secret, str) or re.fullmatch(r'[!-~]{1,256}', settings.bot_secret) is None
            or not settings.bot_hostnames or type(settings.bot_hostnames) is not tuple
            or any(type(h) is not str or len(h) > 253 or any(
                re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is None for label in h.split('.'))
                   for h in settings.bot_hostnames)
            or type(settings.bot_action) is not str or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', settings.bot_action) is None
            or type(settings.bot_max_age_seconds) is not int or not 1 <= settings.bot_max_age_seconds <= 300
            or type(settings.bot_timeout_seconds) not in (int, float)
            or not 0.01 <= settings.bot_timeout_seconds <= 10):
        raise VerificationError('configuration', 503)


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError()
        result[name] = value
    return result


@dataclass(frozen=True)
class VerificationResult:
    challenged_at: datetime


class TurnstileAdapter:
    def __init__(self, settings, *, transport=None, clock=None):
        self.settings = settings
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def validate_result(self, content):
        verification_stage('cloudflare_response')
        try:
            result = json.loads(content.decode('utf-8'), object_pairs_hook=_unique_object,
                                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            verification_stage('verification_validation')
            # Documented optional metadata is informational, never authorization
            # evidence. Do not persist or log it; retain all required-field checks.
            if (type(result) is not dict or set(result) - {'success', 'hostname', 'action', 'challenge_ts', 'error-codes', 'cdata', 'metadata'}
                    or result.get('success') is not True or result.get('hostname') not in self.settings.bot_hostnames
                    or result.get('action') != self.settings.bot_action
                    or ('error-codes' in result and (type(result['error-codes']) is not list or result['error-codes']))
                    or ('cdata' in result and (type(result['cdata']) is not str or len(result['cdata']) > 256))
                    or ('metadata' in result and type(result['metadata']) is not dict)):
                raise ValueError()
            timestamp = result['challenge_ts']
            if type(timestamp) is not str or len(timestamp) > 40:
                raise ValueError()
            challenged = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if challenged.tzinfo is None or challenged.utcoffset().total_seconds() != 0:
                raise ValueError()
            verified = VerificationResult(challenged)
            self.check_fresh(verified)
            return verified
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise VerificationError() from None

    def check_fresh(self, result):
        verification_stage('verification_freshness')
        age = (self.clock() - result.challenged_at).total_seconds()
        if not 0 <= age <= self.settings.bot_max_age_seconds:
            raise VerificationError('age')

    async def verify(self, proof):
        validate_policy(self.settings)
        validate_proof(proof)
        verification_stage('cloudflare_transport')
        try:
            async with asyncio.timeout(self.settings.bot_timeout_seconds):
                transport = self.transport or httpx.AsyncHTTPTransport(verify=True, retries=0, trust_env=False)
                async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False,
                                             timeout=httpx.Timeout(2, connect=2, pool=0.1)) as client:
                    # HTTPX advertises compression by default. Match negotiation
                    # to our bounded identity-only response policy instead.
                    async with client.stream('POST', SITEVERIFY_URL,
                                             headers={'Accept-Encoding': 'identity'},
                                             data={'secret': self.settings.bot_secret, 'response': proof}) as response:
                        verification_stage('cloudflare_response')
                        if response.status_code != 200:
                            raise VerificationError('provider_http_status', 503)
                        if response.headers.get('content-encoding', 'identity') != 'identity':
                            raise VerificationError('provider_content_encoding', 503)
                        if response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                            raise VerificationError()
                        lengths = response.headers.get_list('content-length')
                        if lengths and (len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 20
                                        or int(lengths[0]) > RESPONSE_LIMIT):
                            raise VerificationError()
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(content) + len(chunk) > RESPONSE_LIMIT:
                                raise VerificationError()
                            content.extend(chunk)
                        return self.validate_result(bytes(content))
        except (httpx.TimeoutException, TimeoutError) as error:
            _transport_failure(error)
            raise VerificationError('timeout', 504) from None
        except httpx.HTTPError as error:
            _transport_failure(error)
            raise VerificationError('network', 503) from None


class VerifiedSessionService:
    def __init__(self, adapter):
        self.adapter = adapter
        self.capacity = BoundedSemaphore(adapter.settings.bot_max_concurrent)

    async def issue(self, settings, scope, proof, request_id, *, principal=None):
        verification_stage('configuration')
        validate_policy(settings)
        verification_stage('authentication')
        if settings.capability_auth_enabled:
            try:
                principal = authenticate(settings, scope, required=Capability.VERIFIED_SESSION_ISSUANCE, principal=principal)
            except AuthorizationError as error:
                raise VerificationError('authentication', error.status) from None
            if principal.request_id is not None and principal.request_id != request_id:
                raise VerificationError('authentication', 401)
        elif principal is not None or not staging_authorized(scope, settings.staging_auth_token):
            raise VerificationError('authentication', 401)
        verification_stage('request_validation')
        if (scope.get('method') != 'POST' or scope.get('query_string')
                or any(k.lower() == b'origin' for k, _ in scope.get('headers', []))):
            raise VerificationError('request', 403)
        validate_proof(proof)
        verification_stage('configuration')
        if settings != self.adapter.settings:
            raise VerificationError('configuration', 503)
        verification_stage('capacity')
        if not self.capacity.acquire(blocking=False):
            raise VerificationError('capacity', 503)
        digest = hashlib.sha256(proof.encode('ascii')).digest()
        binding = (principal.binding_digest() if principal is not None else
                   hashlib.sha256(b'verification-gateway-v1\0' + settings.staging_auth_token.encode('ascii')).digest())
        claimed = False
        try:
            verification_stage('claim_reservation')
            ledger = UsageLedger.from_settings(settings)
            await anyio.to_thread.run_sync(lambda: ledger.claim_verification(
                digest, request_id, binding, minute_limit=settings.bot_attempts_minute,
                day_limit=settings.bot_attempts_day, concurrent=settings.bot_max_concurrent,
                issuance_minute_limit=settings.session_issuance_minute_limit,
                issuance_day_limit=settings.session_issuance_day_limit, live_limit=settings.session_max_live))
            claimed = True
            result = await self.adapter.verify(proof)
            self.adapter.check_fresh(result)
            verification_stage('session_finalization')
            token = secrets.token_urlsafe(32)
            expires = await anyio.to_thread.run_sync(lambda: ledger.finalize_verification(
                digest, request_id, binding, hashlib.sha256(token.encode('ascii')).digest(),
                lifetime=settings.session_lifetime_seconds, minute_limit=settings.session_issuance_minute_limit,
                day_limit=settings.session_issuance_day_limit, live_limit=settings.session_max_live,
                verified_until=int(result.challenged_at.timestamp()) + settings.bot_max_age_seconds))
            return {'token': token, 'expires_at': expires}
        except BaseException:
            if claimed:
                # Failure to mark failed leaves a durable pending claim: no reuse.
                with anyio.CancelScope(shield=True):
                    try:
                        await anyio.to_thread.run_sync(lambda: ledger.fail_verification(digest, request_id, binding))
                    except UsageDenied:
                        logger.warning(json.dumps({'event': 'verification_claim_update', 'request_id': request_id,
                                                   'status': 'unresolved', 'category': 'storage'}))
            raise
        finally:
            self.capacity.release()
