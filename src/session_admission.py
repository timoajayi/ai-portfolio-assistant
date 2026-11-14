"""Internal admission adapter only. No HTTP route, cookies, or provider calls."""

import base64
from contextlib import contextmanager
import hashlib
import re

from src.diagnostics import current_diagnostics
from src.reliability import staging_authorized
from src.usage import UsageDenied, UsageLedger, chat_usage
from src.auth import authenticate, Capability, AuthorizationError


@contextmanager
def admitted_session(settings, scope, *, identity_accounting=None, principal=None):
    """Gateway-authenticated ASGI contract, entered inside the actual worker.

    Callers must preserve request validation, deadline supervision and worker
    leases. No existing endpoint calls this adapter or accepts session tokens.
    """
    if settings.session_admission_enabled is not True or settings.staging_auth_enabled is not True:
        raise UsageDenied('usage_session_disabled')
    if settings.capability_auth_enabled:
        try:
            authenticate(settings, scope, required=Capability.SESSION_CHAT, principal=principal)
        except AuthorizationError as error:
            raise UsageDenied('usage_authentication', error.status) from None
    elif (principal is not None or not isinstance(settings.staging_auth_token, str)
          or re.fullmatch(r'[A-Za-z0-9_-]{43,256}', settings.staging_auth_token) is None):
        raise UsageDenied('usage_session_disabled')
    if (scope.get('type') != 'http' or scope.get('method') != 'POST'
            or scope.get('query_string') or any(key.lower() == b'origin' for key, _ in scope.get('headers', []))):
        raise UsageDenied('usage_session', 401)
    if not settings.capability_auth_enabled and not staging_authorized(scope, settings.staging_auth_token):
        raise UsageDenied('usage_session', 401)
    values = [value for key, value in scope.get('headers', []) if key.lower() == b'x-portfolio-session']
    if len(values) != 1 or re.fullmatch(rb'[A-Za-z0-9_-]{43}', values[0]) is None:
        raise UsageDenied('usage_session', 401)
    raw = values[0]
    decoded = base64.urlsafe_b64decode(raw + b'=')
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b'=') != raw:
        raise UsageDenied('usage_session', 401)
    diagnostics = current_diagnostics.get()
    if diagnostics is not None:
        diagnostics.check()
    ledger = UsageLedger.from_settings(settings)
    with chat_usage(ledger, session_digest=hashlib.sha256(raw).digest(),
                    minute_limit=settings.session_admission_minute_limit,
                    hour_limit=settings.session_admission_hour_limit, identity_accounting=identity_accounting):
        yield
