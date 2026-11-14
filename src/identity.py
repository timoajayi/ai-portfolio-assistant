"""Pseudonymization only: this module cannot establish network/proxy trust."""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import re


def identity_key(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z0-9_-]{43}', value) is None:
        raise ValueError('Identity key must encode 32 random bytes as canonical unpadded base64url.')
    key = base64.urlsafe_b64decode(value + '=')
    if len(key) != 32 or base64.urlsafe_b64encode(key).rstrip(b'=').decode() != value:
        raise ValueError('Identity key is invalid.')
    return key


def identity_key_tag(key):
    return hmac.digest(key, b'portfolio-ip-key-check-v1', hashlib.sha256)


@dataclass(frozen=True, init=False)
class TrustedIP:
    """Construct ONLY after the server independently establishes peer identity.

    The type names a trust contract, not proof that a proxy/header is trusted.
    No application HTTP handler currently constructs or accepts this object.
    """
    _packed: bytes = field(repr=False)
    _version: int = field(repr=False)

    def __init__(self, server_validated_address):
        try:
            if (type(server_validated_address) is not str or '%' in server_validated_address
                    or server_validated_address != server_validated_address.strip()):
                raise ValueError()
            address = ipaddress.ip_address(server_validated_address)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
        except ValueError:
            raise ValueError('Trusted identity is invalid.') from None
        object.__setattr__(self, '_packed', address.packed)
        object.__setattr__(self, '_version', address.version)

    def digest(self, key):
        return hmac.digest(key, b'portfolio-ip-identity-v1\0' + bytes([self._version]) + self._packed, hashlib.sha256)
