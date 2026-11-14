"""Disabled internal adapter; never derives trusted identities from HTTP."""

from contextlib import contextmanager

from src.identity import TrustedIP, identity_key, identity_key_tag
from src.session_admission import admitted_session
from src.usage import UsageDenied


@contextmanager
def admitted_identity(settings, scope, identity=None, *, principal=None):
    if settings.ip_admission_enabled is not True:
        raise UsageDenied('usage_identity_disabled')
    if type(identity) is not TrustedIP:
        raise UsageDenied('usage_identity', 401)
    try:
        key = identity_key(settings.ip_rate_hmac_key)
    except ValueError:
        raise UsageDenied('usage_identity_key') from None
    accounting = {'identity_digest': identity.digest(key), 'identity_key_tag': identity_key_tag(key),
                  'identity_minute_limit': settings.ip_admission_minute_limit,
                  'identity_day_limit': settings.ip_admission_day_limit}
    with admitted_session(settings, scope, identity_accounting=accounting, principal=principal):
        yield
