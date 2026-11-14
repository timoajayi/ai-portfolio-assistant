"""Exact route capabilities. No HTTP administrator authority or token fallback."""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
import secrets
from types import MappingProxyType


class Capability(Enum):
    VERIFIED_SESSION_ISSUANCE = 'verified_session_issuance'
    SESSION_CHAT = 'session_chat'
    LEGACY_STAGING = 'legacy_staging'


class Mechanism(Enum):
    BEARER = 'bearer'


class AuthorizationError(Exception):
    def __init__(self, status=401):
        super().__init__('Unauthorized.')
        self.status = status


ROUTE_CAPABILITIES = MappingProxyType({
    ('POST', '/internal/verified-sessions'): Capability.VERIFIED_SESSION_ISSUANCE,
    ('POST', '/internal/session-chat'): Capability.SESSION_CHAT,  # Policy only; no route registered.
    ('POST', '/chat'): Capability.LEGACY_STAGING,
    ('POST', '/internal/sessions'): Capability.LEGACY_STAGING,
    ('GET', '/docs'): Capability.LEGACY_STAGING,
    ('GET', '/redoc'): Capability.LEGACY_STAGING,
    ('GET', '/openapi.json'): Capability.LEGACY_STAGING,
})
_SEAL = object()


@dataclass(frozen=True, init=False)
class AuthenticatedPrincipal:
    mechanism: Mechanism
    capability: Capability
    credential_id: str
    method: str
    path: str
    request_id: str | None
    _fingerprint: bytes = field(repr=False)
    _marker: object = field(repr=False)
    _seal: object = field(repr=False)

    def binding_digest(self):
        # Durable claim binding without retaining the credential itself.
        return hashlib.sha256(b'portfolio-capability-v1\0' + self.credential_id.encode('ascii')
                              + b'\0' + self.capability.value.encode('ascii') + self._fingerprint).digest()


def _valid_token(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{43,256}', value) is not None


def validate_configuration(settings):
    tokens = (settings.staging_auth_token, settings.verified_session_auth_token, settings.session_chat_auth_token)
    for token in tokens:
        if token and not _valid_token(token):
            raise AuthorizationError(503)
    if settings.capability_auth_enabled is True and (settings.staging_auth_enabled is not True
                                                    or not all(_valid_token(v) for v in tokens)):
        raise AuthorizationError(503)
    if type(settings.capability_auth_enabled) is not bool:
        raise AuthorizationError(503)
    nonempty = [v for v in tokens if v]
    if any(secrets.compare_digest(a, b) for i, a in enumerate(nonempty) for b in nonempty[i + 1:]):
        raise AuthorizationError(503)
    ids = (settings.verified_session_credential_id, settings.session_chat_credential_id, 'legacy-staging')
    if (any(type(v) is not str or re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', v) is None for v in ids)
            or len(set(ids)) != len(ids)):
        raise AuthorizationError(503)


def _context(scope):
    method, path = scope.get('method'), scope.get('path')
    if scope.get('type') != 'http' or type(method) is not str or type(path) is not str:
        raise AuthorizationError()
    try:
        raw = path.encode('ascii')
    except UnicodeEncodeError:
        raise AuthorizationError() from None
    if (scope.get('query_string') or scope.get('root_path') or scope.get('raw_path', raw) != raw
            or '%' in path or '\\' in path):
        raise AuthorizationError()
    return method, path


def _credential(settings, capability):
    if capability is Capability.VERIFIED_SESSION_ISSUANCE:
        return settings.verified_session_auth_token, settings.verified_session_credential_id
    if capability is Capability.SESSION_CHAT:
        return settings.session_chat_auth_token, settings.session_chat_credential_id
    if capability is Capability.LEGACY_STAGING:
        return settings.staging_auth_token, 'legacy-staging'
    raise AuthorizationError()


def authenticate(settings, scope, *, required=None, principal=None):
    validate_configuration(settings)
    if settings.capability_auth_enabled is not True:
        raise AuthorizationError(503)
    method, path = _context(scope)
    capability = ROUTE_CAPABILITIES.get((method, path))
    if capability is None or (required is not None and (type(required) is not Capability or required is not capability)):
        raise AuthorizationError()
    expected, credential_id = _credential(settings, capability)
    headers = [v for k, v in scope.get('headers', []) if k.lower() == b'authorization']
    if len(headers) != 1 or type(headers[0]) is not bytes:
        raise AuthorizationError()
    match = re.fullmatch(rb'(?i:Bearer) ([A-Za-z0-9_-]{43,256})', headers[0])
    if match is None or not secrets.compare_digest(match[1], expected.encode('ascii')):
        raise AuthorizationError()
    fingerprint = hashlib.sha256(match[1]).digest()
    state = scope.setdefault('state', {})
    marker = state.setdefault('_capability_marker', object())
    request_id = state.get('request_id')
    if request_id is not None and (type(request_id) is not str or re.fullmatch(r'[a-f0-9]{32}', request_id) is None):
        raise AuthorizationError()
    if principal is not None:
        if (type(principal) is not AuthenticatedPrincipal or getattr(principal, '_seal', None) is not _SEAL
                or principal._marker is not marker or principal.capability is not capability
                or principal.mechanism is not Mechanism.BEARER or principal.credential_id != credential_id
                or (principal.method, principal.path, principal.request_id) != (method, path, request_id)
                or not secrets.compare_digest(principal._fingerprint, fingerprint)):
            raise AuthorizationError()
        return principal
    result = object.__new__(AuthenticatedPrincipal)
    for name, value in {'mechanism': Mechanism.BEARER, 'capability': capability, 'credential_id': credential_id,
                        'method': method, 'path': path, 'request_id': request_id, '_fingerprint': fingerprint,
                        '_marker': marker, '_seal': _SEAL}.items():
        object.__setattr__(result, name, value)
    return result
