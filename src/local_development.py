"""Explicit loopback-only development composition; never imported by production.

No dotenv, operational storage, migration or provider work occurs on import.
The durable profile is created exclusively by an operator's `init` command.
"""
import argparse
import base64
import importlib
import json
import os
from pathlib import Path
import secrets
import sys
from unittest.mock import patch

POLICY = 'local-loopback-development-v1'
ISSUER = 'portfolio-local-gateway'
AUDIENCE = 'portfolio-local-backend'
CLOUD_MARKERS = ('VERCEL', 'RAILWAY_ENVIRONMENT_ID', 'RENDER')


def local_only():
    if os.environ.get('NODE_ENV') == 'production' or any(os.environ.get(k) for k in CLOUD_MARKERS):
        raise ValueError('Local development is unavailable in hosted/production environments.')


def state_directory(value):
    path = Path(value).expanduser().absolute()
    if path.is_symlink():
        raise ValueError('Local state cannot be a symlink.')
    path = path.resolve()
    if any((parent / '.git').exists() for parent in (path, *path.parents)):
        raise ValueError('Local state must be outside repositories and symlinked directories.')
    return path


def read_profile(directory):
    directory = state_directory(directory)
    for path in (directory, directory / 'profile.json'):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Private local state permissions required.')
    with (directory / 'profile.json').open() as stream:
        value = json.load(stream)
    fields = {'version', 'staging', 'issuance', 'chat', 'signing', 'ip_key'}
    if type(value) is not dict or set(value) != fields or value['version'] != 1:
        raise ValueError('Invalid local profile.')
    from src.identity import identity_key
    decoded = [identity_key(value[k]) for k in fields - {'version'}]
    if len(set(decoded)) != len(decoded):
        raise ValueError('Independent local credentials required.')
    return value


def initialize(directory):
    local_only()
    directory = state_directory(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    profile = {'version': 1, **{k: secrets.token_urlsafe(32) for k in ('staging', 'issuance', 'chat', 'signing', 'ip_key')}}
    fd = os.open(directory / 'profile.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(profile, stream)
    from src.usage import UsageLedger
    from src.identity import identity_key, identity_key_tag
    ledger = UsageLedger(directory / 'usage.sqlite3')
    ledger.initialize()
    ledger.migrate(workers_stopped=True)
    ledger.migrate_issuance(workers_stopped=True)
    ledger.migrate_identity(identity_key_tag(identity_key(profile['ip_key'])), workers_stopped=True)
    ledger.migrate_verification(workers_stopped=True)
    ledger.migrate_gateway_replay(workers_stopped=True)
    # Both durable emergency switches remain disabled. Never enable on startup.
    return ledger


def configure_environment(directory, profile, *, session_only=False):
    """Process-only overrides. No real environment files are loaded or changed."""
    local_only()
    if not os.environ.get('GOOGLE_API_KEY') or not os.environ.get('BOT_PROVIDER_SECRET'):
        raise ValueError('Supply GOOGLE_API_KEY and BOT_PROVIDER_SECRET privately in the process environment.')
    os.environ.update({
        'BACKEND_DEPLOYMENT_POLICY': 'production', 'LEGACY_CHAT_ENABLED': 'false',
        'STAGING_AUTH_ENABLED': 'true', 'CAPABILITY_AUTH_ENABLED': 'true',
        'STAGING_AUTH_TOKEN': profile['staging'], 'VERIFIED_SESSION_AUTH_TOKEN': profile['issuance'],
        'SESSION_CHAT_AUTH_TOKEN': profile['chat'], 'IP_RATE_HMAC_KEY': profile['ip_key'],
        'VERIFIED_SESSION_CREDENTIAL_ID': 'local-issuance', 'SESSION_CHAT_CREDENTIAL_ID': 'local-chat',
        'SESSION_CHAT_ENABLED': 'false' if session_only else 'true',
        'SESSION_CHAT_HTTP_ENABLED': 'false' if session_only else 'true',
        'SESSION_ADMISSION_ENABLED': 'true', 'IP_ADMISSION_ENABLED': 'true',
        'SESSION_ISSUANCE_ENABLED': 'true', 'BOT_VERIFICATION_ENABLED': 'true',
        'BOT_ALLOWED_HOSTNAMES': 'localhost', 'BOT_EXPECTED_ACTION': 'portfolio_session',
        'FRONTEND_ORIGINS': '', 'USAGE_LEDGER_PATH': str(directory / 'usage.sqlite3'),
    })


def compose(api, profile):
    from src.authenticated_session_chat import AuthenticatedSessionChatService, GatewayAuthority, TrustedIdentityResolver
    from src.gateway_assertions import GatewayAssertionVerifier, VerificationKey
    from src.gateway_replay import GatewayReplayService
    from src.session_chat import SessionChatService
    from src.usage import UsageLedger

    class LoopbackDelegation(TrustedIdentityResolver):
        def _authorize(self, context):
            local_only()
            return (context.authority.issuer == ISSUER and context.authority.audience == AUDIENCE
                    and context.principal.credential_id == 'local-chat'
                    and context.assertion.visitor_ip == '127.0.0.1'
                    and context.assertion.ip_source == POLICY)

    controls = api.app.state.chat_controls
    settings = controls.settings
    ledger = UsageLedger.from_settings(settings)
    # Validate existing schema/storage without creating, repairing or enabling it.
    ledger.status()
    key = base64.urlsafe_b64decode(profile['signing'] + '=')
    verifier = GatewayAssertionVerifier(issuer=ISSUER, audience=AUDIENCE, ip_source=POLICY,
        current_key=VerificationKey('local-key-1', key, 0, 253402300799))
    chat = SessionChatService(settings, controls, api.app, api.ChatRequest, api._chat_worker)
    api.app.state.session_chat_pipeline = AuthenticatedSessionChatService(chat, GatewayReplayService(ledger, verifier),
        authority=GatewayAuthority('local-chat', ISSUER, AUDIENCE, frozenset({'local-key-1'}), POLICY),
        identity_resolver=LoopbackDelegation(POLICY))
    return LoopbackOnly(api.app)


class LoopbackOnly:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            peer = scope.get('client')
            if not peer or peer[0] != '127.0.0.1':
                from starlette.responses import JSONResponse
                await JSONResponse({'detail': 'Local access required.'}, status_code=403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def create_app(directory, *, session_only=False):
    local_only()
    directory = state_directory(directory)
    profile = read_profile(directory)
    configure_environment(directory, profile, session_only=session_only)
    if 'src.api' in sys.modules or 'src.embeddings' in sys.modules:
        raise ValueError('Local runner requires a fresh process.')
    # Existing API modules normally load dotenv. This isolated entry point uses
    # process configuration exclusively; suppress file loading before imports.
    with patch('dotenv.load_dotenv', return_value=False):
        api = importlib.import_module('src.api')
    application = compose(api, profile)
    if session_only:
        # Reuse the existing execution gates; never touch durable emergency state.
        configuration = api.app.state.chat_controls.settings
        if (configuration.session_chat_enabled or configuration.session_chat_http_enabled
                or configuration.legacy_chat_enabled or not configuration.bot_verification_enabled
                or not configuration.session_issuance_enabled):
            raise ValueError('Session diagnostic configuration unavailable.')
        api.logger.info(json.dumps({'event': 'local_session_diagnostic',
            'gemini_execution': 'blocked', 'verified_session_issuance': 'enabled',
            'verification_diagnostics': 'enabled'}))
    return application


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'enable', 'disable', 'serve'))
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--allow-live-providers', action='store_true')
    parser.add_argument('--session-only', action='store_true',
                        help='Serve verification/issuance with all FastAPI chat execution disabled.')
    args = parser.parse_args(argv)
    try:
        if args.session_only and args.command != 'serve':
            raise ValueError('Session-only diagnostics apply exclusively to serve.')
        local_only()
        directory = state_directory(args.state)
        if args.command == 'init':
            initialize(directory)
        elif args.command in ('enable', 'disable'):
            read_profile(directory)
            from src.usage import UsageLedger
            ledger = UsageLedger(directory / 'usage.sqlite3')
            if args.command == 'enable':
                if not args.allow_live_providers:
                    raise ValueError('Explicit live-provider authorization required.')
                ledger.set_disabled(False)
                ledger.set_issuance_disabled(False)
            else:
                try:
                    ledger.set_issuance_disabled(True)
                finally:
                    ledger.set_disabled(True)
        else:
            if not args.allow_live_providers:
                raise ValueError('Explicit live-provider authorization required.')
            import uvicorn
            uvicorn.run(create_app(directory, session_only=args.session_only), host='127.0.0.1', port=8001, workers=1,
                        proxy_headers=False, access_log=False)
        return 0
    except Exception:
        print('Local runner unavailable. Check private configuration, storage and operator prerequisites.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
