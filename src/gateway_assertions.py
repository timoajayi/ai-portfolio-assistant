"""Isolated v1 MAC verification. This grants neither authorization nor IP trust.

No environment, network, replay database or HTTP integration is used here.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from types import MappingProxyType

PROTOCOL = 'portfolio-gateway-assertion-v1'
METHOD = 'POST'
PATH = '/internal/session-chat'
MAX_ASSERTION_BYTES = 2048
MAX_BODY_BYTES = 8192
MAX_TIME = 253402300799
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,63}', re.ASCII)
_KID = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}', re.ASCII)
_HEX = re.compile(r'[a-f0-9]{64}', re.ASCII)
_B64 = re.compile(r'[A-Za-z0-9_-]+', re.ASCII)
_FIELDS = frozenset(('v', 'iss', 'aud', 'scope', 'method', 'path', 'iat', 'exp', 'jti',
                     'session_sha256', 'body_sha256', 'visitor_ip', 'ip_source'))


class AssertionError(ValueError):
    """Intentionally generic; never includes the supplied assertion or key."""
    def __init__(self):
        super().__init__('Invalid gateway assertion.')


def _require(condition):
    if not condition:
        raise AssertionError()


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_TIME


def _identifier(value):
    return type(value) is str and _ID.fullmatch(value) is not None


def _b64(value, maximum):
    _require(type(value) is str and len(value) <= maximum * 2 and _B64.fullmatch(value) is not None)
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError):
        raise AssertionError() from None
    _require(len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') == value)
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _invalid_number(_value):
    raise AssertionError()


def _json(raw):
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                           parse_float=_invalid_number, parse_constant=_invalid_number)
    except (ValueError, UnicodeError, RecursionError):
        raise AssertionError() from None
    _require(type(value) is dict)
    return value


def canonical_ip(value):
    """Pure syntax normalization, NEVER ingress authentication."""
    _require(type(value) is str and len(value) <= 45 and '%' not in value)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AssertionError() from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


@dataclass(frozen=True)
class VerificationKey:
    kid: str
    secret: bytes = field(repr=False)
    not_before: int
    not_after: int

    def __post_init__(self):
        _require(type(self.kid) is str and _KID.fullmatch(self.kid) is not None)
        _require(type(self.secret) is bytes and 32 <= len(self.secret) <= 64)
        _require(_integer(self.not_before) and _integer(self.not_after) and self.not_after > self.not_before)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedGatewayAssertion:
    """A cryptographic result only; callers MUST enforce replay and ingress trust."""
    key_id: str
    issuer: str
    audience: str
    ip_source: str
    issued_at: int
    expires_at: int
    nonce: str = field(repr=False)
    visitor_ip: str = field(repr=False)
    session_sha256: str = field(repr=False)
    body_sha256: str = field(repr=False)
    replay_protection_required: bool = field(default=True, init=False)
    ingress_trust_verified: bool = field(default=False, init=False)
    _key_not_before: int = field(repr=False)
    _key_not_after: int = field(repr=False)
    _verifier_context: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)
    _attestation: bytes = field(repr=False, compare=False)


# Provenance is process-local, not durable replay state. Python is not a sandbox:
# code with reflection/module mutation authority remains trusted. No key material
# from the gateway is retained in a result. Result serialization is unsupported;
# fresh workers must reverify the original wire assertion.
_RESULT_SEAL = object()
_RESULT_KEY = secrets.token_bytes(32)
_RESULT_FIELDS = ('key_id', 'issuer', 'audience', 'ip_source', 'issued_at', 'expires_at',
                  'nonce', 'visitor_ip', 'session_sha256', 'body_sha256',
                  'replay_protection_required', 'ingress_trust_verified',
                  '_key_not_before', '_key_not_after', '_verifier_context')


def _result_mac(value):
    encoded = json.dumps([getattr(value, name) for name in _RESULT_FIELDS],
                         ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return hmac.digest(_RESULT_KEY, b'portfolio-verified-result-v1\0' + encoded, 'sha256')


def _replay_binding(value, now, *, verifier):
    """Internal boundary: reject constructed, altered or stale verifier results.

    Returns only storage-safe replay metadata, never IP/session/body data.
    This does not authenticate a gateway bearer or the ingress provenance.
    """
    try:
        _require(type(verifier) is GatewayAssertionVerifier)
        _require(type(value) is VerifiedGatewayAssertion and value._seal is _RESULT_SEAL)
        _require(type(value._verifier_context) is str and len(value._verifier_context) == 64
                 and hmac.compare_digest(value._verifier_context, verifier._context))
        _require(type(value.key_id) is str and _KID.fullmatch(value.key_id) is not None)
        _require(all(_identifier(v) for v in (value.issuer, value.audience, value.ip_source)))
        _require(all(_integer(v) for v in (value.issued_at, value.expires_at, value._key_not_before,
                                          value._key_not_after, now)))
        _require(len(_b64(value.nonce, 32)) == 32 and len(set(_b64(value.nonce, 32))) > 1)
        _require(canonical_ip(value.visitor_ip) == value.visitor_ip)
        _require(all(type(v) is str and _HEX.fullmatch(v) is not None
                     for v in (value.session_sha256, value.body_sha256)))
        _require(value.replay_protection_required is True and value.ingress_trust_verified is False)
        _require(type(value._attestation) is bytes and len(value._attestation) == 32)
        _require(hmac.compare_digest(value._attestation, _result_mac(value)))
        _require(0 < value.expires_at - value.issued_at <= 30 and value.issued_at <= now + 5
                 and now < value.expires_at)
        _require(value._key_not_before <= value.issued_at and value.expires_at <= value._key_not_after
                 and value._key_not_before <= now < value._key_not_after)
    except (AttributeError, TypeError, ValueError):
        raise AssertionError() from None
    scope = json.dumps([PROTOCOL, value.issuer, value.audience, value.key_id, value.nonce],
                       separators=(',', ':')).encode('ascii')
    return hashlib.sha256(b'portfolio-gateway-replay-id-v1\0' + scope).digest(), value.expires_at


class GatewayAssertionVerifier:
    """Inject current key and optionally one time-bounded verification-only key.

    There is no signing API and no default key/configuration. These objects must
    not be used as authorization principals or TrustedIP values.
    """
    def __init__(self, *, issuer, audience, ip_source, current_key, previous_key=None):
        _require(all(_identifier(v) for v in (issuer, audience, ip_source)))
        _require(type(current_key) is VerificationKey)
        _require(previous_key is None or type(previous_key) is VerificationKey)
        keys = [current_key] + ([] if previous_key is None else [previous_key])
        _require(len({k.kid for k in keys}) == len(keys))
        _require(len(keys) == 1 or not hmac.compare_digest(keys[0].secret, keys[1].secret))
        self._context = secrets.token_hex(32)
        self._keys = MappingProxyType({k.kid: k for k in keys})
        self._issuer, self._audience, self._ip_source = issuer, audience, ip_source

    def verify(self, assertion, *, session_token, body, method=METHOD, path=PATH, now=None):
        _require(type(assertion) is str and 0 < len(assertion) <= MAX_ASSERTION_BYTES and assertion.isascii())
        parts = assertion.split('.')
        _require(len(parts) == 3)
        header_raw, payload_raw, signature = (_b64(parts[0], 256), _b64(parts[1], 1024), _b64(parts[2], 32))
        _require(len(signature) == 32)
        header = _json(header_raw)
        _require(set(header) == {'typ', 'alg', 'kid'})
        _require(header['typ'] == PROTOCOL and header['alg'] == 'HS256')
        _require(type(header['kid']) is str and _KID.fullmatch(header['kid']) is not None)
        key = self._keys.get(header['kid'])
        _require(key is not None)
        expected = hmac.digest(key.secret, (parts[0] + '.' + parts[1]).encode('ascii'), 'sha256')
        _require(hmac.compare_digest(signature, expected))
        payload = _json(payload_raw)
        _require(set(payload) == _FIELDS)
        _require(type(payload['v']) is int and payload['v'] == 1)
        _require(all(_identifier(payload[k]) for k in ('iss', 'aud', 'ip_source')))
        _require((payload['iss'], payload['aud'], payload['ip_source']) ==
                 (self._issuer, self._audience, self._ip_source))
        _require(type(method) is str and type(path) is str and method == METHOD and path == PATH)
        _require(payload['scope'] == 'session:chat' and payload['method'] == method and payload['path'] == path)
        current = int(time.time()) if now is None else now
        iat, exp = payload['iat'], payload['exp']
        _require(all(_integer(v) for v in (current, iat, exp)))
        _require(0 < exp - iat <= 30 and iat <= current + 5 and current < exp)
        _require(key.not_before <= iat and exp <= key.not_after and key.not_before <= current < key.not_after)
        nonce = _b64(payload['jti'], 32)
        _require(len(nonce) == 32 and len(set(nonce)) > 1)
        _require(type(session_token) is str and len(session_token) == 43 and len(_b64(session_token, 32)) == 32)
        _require(type(body) is bytes and len(body) <= MAX_BODY_BYTES)
        for name, raw in (('session_sha256', session_token.encode('ascii')), ('body_sha256', body)):
            _require(type(payload[name]) is str and _HEX.fullmatch(payload[name]) is not None)
            _require(hmac.compare_digest(payload[name], hashlib.sha256(raw).hexdigest()))
        address = canonical_ip(payload['visitor_ip'])
        _require(address == payload['visitor_ip'])
        result = object.__new__(VerifiedGatewayAssertion)
        values = (key.kid, payload['iss'], payload['aud'], payload['ip_source'], iat, exp,
                  payload['jti'], address, payload['session_sha256'], payload['body_sha256'],
                  True, False, key.not_before, key.not_after, self._context)
        for name, value in zip(_RESULT_FIELDS, values):
            object.__setattr__(result, name, value)
        object.__setattr__(result, '_seal', _RESULT_SEAL)
        object.__setattr__(result, '_attestation', _result_mac(result))
        return result
