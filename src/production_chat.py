"""Explicit Render composition for the directly hosted Vercel gateway.

No flag activation, dotenv loading, database creation/migration or provider calls.
Vercel ingress provenance is established by the gateway; this resolver delegates
only to the pinned scoped credential AND pinned assertion authority, not headers.
"""
import base64
import hmac
import re
import time

from src.auth import Capability, Mechanism, validate_configuration
from src.authenticated_session_chat import (
    AuthenticatedSessionChatService, GatewayAuthority, TrustedIdentityResolver,
)
from src.gateway_assertions import GatewayAssertionVerifier, VerificationKey, canonical_ip
from src.gateway_replay import GatewayReplayService
from src.legacy_policy import validate_legacy_configuration
from src.session_chat import SessionChatService
from src.usage import UsageLedger

POLICY = 'vercel-direct-v1'


class VercelGatewayIdentity(TrustedIdentityResolver):
    """Deployment-approved delegation, only after scoped auth, MAC and replay.

    Render's socket/forwarding headers cannot identify the original browser.
    Compromise of the trusted gateway or either credential remains a deployment
    incident; neither a bare signature nor an arbitrary signed IP grants access.
    """
    def __init__(self, authority):
        super().__init__(POLICY)
        self._authority = authority

    def _authorize(self, context):
        actor, assertion, authority = context.principal, context.assertion, self._authority
        return (context.authority == authority
                and actor.mechanism is Mechanism.BEARER
                and actor.capability is Capability.SESSION_CHAT
                and actor.credential_id == authority.credential_id
                and actor.method == 'POST' and actor.path == '/internal/session-chat'
                and assertion.issuer == authority.issuer and assertion.audience == authority.audience
                and assertion.key_id in authority.signing_key_ids
                and assertion.ip_source == POLICY
                and canonical_ip(assertion.visitor_ip) == assertion.visitor_ip)


def _timestamp(value):
    if type(value) is not str or re.fullmatch(r'0|[1-9][0-9]{0,11}', value) is None:
        raise ValueError()
    result = int(value)
    if result > 253402300799:
        raise ValueError()
    return result


def compose_production_chat(application, controls, request_model, worker, environment):
    """Return existing pipeline after explicit configuration; never enable it.

    The caller publishes the result only after the complete configuration and
    existing ledger have been validated. Existing local composition is separate.
    """
    try:
        settings = controls.settings
        if (environment.get('RENDER') != 'true'
                or environment.get('GATEWAY_INGRESS_POLICY') != POLICY
                or settings.backend_deployment_policy != 'production'
                or settings.legacy_chat_enabled is not False
                or not all(getattr(settings, name) is True for name in (
                    'session_chat_http_enabled', 'session_chat_enabled', 'capability_auth_enabled',
                    'staging_auth_enabled', 'session_admission_enabled', 'ip_admission_enabled'))):
            raise ValueError()
        validate_configuration(settings)
        validate_legacy_configuration(settings)
        encoded = environment.get('GATEWAY_ASSERTION_KEY')
        if type(encoded) is not str or re.fullmatch(r'[A-Za-z0-9_-]{43,86}', encoded) is None:
            raise ValueError()
        secret = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        if not 32 <= len(secret) <= 64 or base64.urlsafe_b64encode(secret).rstrip(b'=').decode() != encoded:
            raise ValueError()
        if any(hmac.compare_digest(encoded, token) for token in (
                settings.staging_auth_token, settings.session_chat_auth_token,
                settings.verified_session_auth_token, settings.ip_rate_hmac_key)):
            raise ValueError()
        key = VerificationKey(environment.get('GATEWAY_ASSERTION_KEY_ID'), secret,
                              _timestamp(environment.get('GATEWAY_ASSERTION_KEY_NOT_BEFORE')),
                              _timestamp(environment.get('GATEWAY_ASSERTION_KEY_NOT_AFTER')))
        if not key.not_before <= int(time.time()) < key.not_after:
            raise ValueError()
        verifier = GatewayAssertionVerifier(issuer=environment.get('GATEWAY_ASSERTION_ISSUER'),
            audience=environment.get('GATEWAY_ASSERTION_AUDIENCE'), ip_source=POLICY, current_key=key)
        authority = GatewayAuthority(settings.session_chat_credential_id, verifier._issuer,
            verifier._audience, frozenset({key.kid}), POLICY)
        ledger = UsageLedger.from_settings(settings)
        # Read-only validation. Missing/disabled/corrupt storage is not repaired.
        ledger.status()
        chat = SessionChatService(settings, controls, application, request_model, worker)
        return AuthenticatedSessionChatService(chat, GatewayReplayService(ledger, verifier),
            authority=authority, identity_resolver=VercelGatewayIdentity(authority))
    except Exception:
        raise RuntimeError('Production chat configuration unavailable.') from None
