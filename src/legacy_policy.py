"""Explicit server deployment authorization; never inferred from peers or headers."""
import posixpath
import re


def validate_legacy_configuration(settings):
    if (settings.backend_deployment_policy not in ('production', 'staging')
            or type(settings.legacy_chat_enabled) is not bool):
        raise ValueError('Invalid backend deployment policy.')
    if settings.legacy_chat_enabled:
        if (settings.backend_deployment_policy != 'staging' or settings.staging_auth_enabled is not True
                or type(settings.staging_auth_token) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{43,256}', settings.staging_auth_token) is None
                or settings.session_chat_http_enabled is not False):
            raise ValueError('Legacy chat requires isolated authenticated staging policy.')


def legacy_execution_allowed(settings):
    try:
        validate_legacy_configuration(settings)
    except (ValueError, AttributeError, TypeError):
        return False
    return settings.backend_deployment_policy == 'staging' and settings.legacy_chat_enabled is True


def legacy_path(scope):
    """Normalization identifies aliases only to deny them, never to grant access."""
    path = scope.get('path')
    return type(path) is str and posixpath.normpath('/'+path.replace('\\', '/').lstrip('/')) == '/chat'


def canonical_legacy_request(scope):
    return (scope.get('type') == 'http' and scope.get('method') == 'POST' and scope.get('path') == '/chat'
            and scope.get('raw_path', b'/chat') == b'/chat' and not scope.get('root_path')
            and not scope.get('query_string'))
