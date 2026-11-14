"""Validated operational settings. Load after dotenv at application entry points."""

from dataclasses import dataclass, field
import math
import os
import re
from pathlib import Path
from urllib.request import getproxies
from urllib.parse import urlsplit
from src.identity import identity_key


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def validate_usage_path(value: Path, rag_path: Path | None = None) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("USAGE_LEDGER_PATH must be an absolute regular-file path outside application/index directories.")
    path = path.resolve()
    protected = [REPOSITORY_ROOT]
    if rag_path is not None:
        protected.append(rag_path.resolve().parent)
    if any(path == directory or directory in path.parents for directory in protected):
        raise ValueError("USAGE_LEDGER_PATH must be outside application/index directories.")
    return path


def usage_busy_ms() -> int:
    value = positive_integer("USAGE_SQLITE_BUSY_MS", 250)
    if value > 2000:
        raise ValueError("USAGE_SQLITE_BUSY_MS must be between 1 and 2000.")
    return value


def staging_authentication() -> tuple[bool, str]:
    enabled = os.environ.get("STAGING_AUTH_ENABLED", "false").strip().lower()
    if enabled not in ("true", "false"):
        raise ValueError("STAGING_AUTH_ENABLED must be true or false.")
    if enabled == "false":
        return False, ""
    token = os.environ.get("STAGING_AUTH_TOKEN", "")
    if re.fullmatch(r"[A-Za-z0-9_-]{43,256}", token) is None:
        raise ValueError("STAGING_AUTH_TOKEN must contain 43 to 256 URL-safe characters.")
    return True, token


def configured_frontend_origins(staging: bool) -> list[str]:
    # Staging requires an explicit allowlist; local development keeps its defaults.
    default = "" if staging else "http://localhost:3000,http://127.0.0.1:3000"
    origins = [origin.strip() for origin in os.environ.get("FRONTEND_ORIGINS", default).split(",")
               if origin.strip()]
    if staging:
        for origin in origins:
            try:
                parsed = urlsplit(origin)
                valid = (parsed.scheme in ("http", "https") and parsed.hostname
                         and not any(c in origin for c in ("*", "\\", "?", "#", "\r", "\n", "\t", " "))
                         and parsed.username is None and parsed.password is None
                         and not parsed.path and not parsed.query and not parsed.fragment)
                parsed.port  # Validate malformed ports without echoing the value.
            except ValueError:
                valid = False
            if not valid:
                raise ValueError("FRONTEND_ORIGINS must contain explicit HTTP(S) origins in staging.")
    return origins


def index_path() -> Path:
    value = os.environ.get("RAG_INDEX_PATH", "data/index/portfolio.json").strip()
    if not value:
        raise ValueError("RAG_INDEX_PATH must not be empty.")
    path = Path(value)
    return path if path.is_absolute() else REPOSITORY_ROOT / path


def positive_integer(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
        if value > 0:
            return value
    except ValueError:
        pass
    # Never include the supplied value: configuration may contain secrets.
    raise ValueError(f"{name} must be a positive integer.")


def chat_deadline_seconds() -> float:
    try:
        value = float(os.environ.get("CHAT_DEADLINE_SECONDS", "40"))
        if math.isfinite(value) and 0.01 <= value <= 120:
            return value
    except ValueError:
        pass
    raise ValueError("CHAT_DEADLINE_SECONDS must be between 0.01 and 120 seconds.")


def generation_output_tokens() -> int:
    value = positive_integer("GEMINI_MAX_OUTPUT_TOKENS", 1024)
    if value > 65536:
        raise ValueError("GEMINI_MAX_OUTPUT_TOKENS must be between 1 and 65536.")
    return value


def session_issuance_enabled(staging: bool) -> bool:
    value = os.environ.get('SESSION_ISSUANCE_ENABLED', 'false').strip().lower()
    if value not in ('true', 'false') or (value == 'true' and not staging):
        raise ValueError('Session issuance requires explicit valid configuration and staging authentication.')
    return value == 'true'


def session_limit(name: str, default: int, maximum: int) -> int:
    value = positive_integer(name, default)
    if value > maximum:
        raise ValueError(f'{name} exceeds its supported maximum.')
    return value


def session_admission_enabled(staging: bool) -> bool:
    value = os.environ.get('SESSION_ADMISSION_ENABLED', 'false').strip().lower()
    if value not in ('true', 'false') or (value == 'true' and not staging):
        raise ValueError('Session admission requires explicit valid configuration and staging authentication.')
    return value == 'true'


def ip_admission_configuration(staging: bool, session_enabled: bool):
    value = os.environ.get('IP_ADMISSION_ENABLED', 'false').strip().lower()
    if value not in ('true', 'false') or (value == 'true' and not (staging and session_enabled)):
        raise ValueError('IP admission requires explicit valid configuration and authenticated session admission.')
    key = os.environ.get('IP_RATE_HMAC_KEY', '')
    if key or value == 'true':
        identity_key(key)
    return value == 'true', key


def generation_thinking_level() -> str:
    # gemini-3.8-flash supports these levels; MINIMAL is not supported.
    value = os.environ.get("GEMINI_THINKING_LEVEL", "LOW").strip().upper()
    if value not in ("LOW", "MEDIUM", "HIGH"):
        raise ValueError("GEMINI_THINKING_LEVEL must be LOW, MEDIUM, or HIGH.")
    return value


def validate_network_policy(value: str) -> str:
    if not isinstance(value, str) or value.strip().lower() not in ("auto", "ipv4"):
        raise ValueError("GEMINI_NETWORK_POLICY must be auto or ipv4.")
    policy = value.strip().lower()
    # HTTPX disables automatic proxy mounts when given a custom transport.
    # Fail closed instead of silently bypassing environment/system proxies.
    if policy == "ipv4":
        proxies = getproxies()
        if any(proxies.get(scheme) for scheme in ("http", "https", "all")):
            raise ValueError("GEMINI_NETWORK_POLICY=ipv4 requires direct connectivity; configured proxies are unsupported.")
    return policy


@dataclass(frozen=True)
class Settings:
    backend_deployment_policy: str = 'production'
    legacy_chat_enabled: bool = False
    capability_auth_enabled: bool = False
    verified_session_auth_token: str = field(default='', repr=False)
    session_chat_auth_token: str = field(default='', repr=False)
    verified_session_credential_id: str = 'verified-session-v1'
    session_chat_credential_id: str = 'session-chat-v1'
    session_chat_enabled: bool = False
    session_chat_http_enabled: bool = False
    bot_verification_enabled: bool = False
    bot_secret: str = field(default='', repr=False)
    bot_hostnames: tuple[str, ...] = ()
    bot_action: str = 'portfolio_session'
    bot_max_age_seconds: int = 300
    bot_timeout_seconds: float = 5.0
    bot_attempts_minute: int = 10
    bot_attempts_day: int = 100
    bot_max_concurrent: int = 2
    ip_admission_enabled: bool = False
    ip_rate_hmac_key: str = field(default='', repr=False)
    ip_admission_minute_limit: int = 10
    ip_admission_day_limit: int = 60
    session_admission_enabled: bool = False
    session_admission_minute_limit: int = 3
    session_admission_hour_limit: int = 12
    session_issuance_enabled: bool = False
    session_lifetime_seconds: int = 14400
    session_issuance_minute_limit: int = 10
    session_issuance_day_limit: int = 100
    session_max_live: int = 500
    usage_path: Path = Path("/var/lib/ai-portfolio-assistant/usage.sqlite3")
    usage_daily_limit: int = 100
    usage_monthly_limit: int = 1000
    usage_max_concurrent: int = 2
    usage_busy_ms: int = 250
    staging_auth_enabled: bool = False
    staging_auth_token: str = field(default="", repr=False)
    staging_budget_requests: int = 10
    staging_budget_window_seconds: int = 60
    gemini_network_policy: str = "auto"
    chat_deadline_seconds: float = 40.0
    index_path: Path = REPOSITORY_ROOT / "data/index/portfolio.json"
    embedding_timeout_ms: int = 10_000
    generation_timeout_ms: int = 20_000
    max_output_tokens: int = 1024
    thinking_level: str = "LOW"
    max_body_bytes: int = 8192
    max_concurrent: int = 4
    rate_requests: int = 20
    rate_window_seconds: int = 60
    rate_max_clients: int = 1024

    @classmethod
    def from_env(cls):
        deployment_policy = os.environ.get('BACKEND_DEPLOYMENT_POLICY', 'production')
        legacy_flag = os.environ.get('LEGACY_CHAT_ENABLED', 'false')
        if deployment_policy not in ('production', 'staging') or legacy_flag not in ('true', 'false'):
            raise ValueError('Invalid backend deployment policy.')
        capability_flag = os.environ.get('CAPABILITY_AUTH_ENABLED', 'false')
        if capability_flag not in ('true', 'false'):
            raise ValueError('CAPABILITY_AUTH_ENABLED must be exact true or false.')
        staging, token = staging_authentication()
        configured_frontend_origins(staging)
        session_enabled = session_admission_enabled(staging)
        ip_enabled, ip_key = ip_admission_configuration(staging, session_enabled)
        session_chat_flag = os.environ.get('SESSION_CHAT_ENABLED', 'false')
        if (session_chat_flag not in ('true', 'false')
                or (session_chat_flag == 'true' and not (staging and session_enabled and ip_enabled))):
            raise ValueError('SESSION_CHAT_ENABLED requires exact configuration and authenticated session/IP admission.')
        http_flag = os.environ.get('SESSION_CHAT_HTTP_ENABLED', 'false')
        if (http_flag not in ('true', 'false')
                or (http_flag == 'true' and not (capability_flag == 'true' and session_chat_flag == 'true'
                                               and staging and session_enabled and ip_enabled))):
            raise ValueError('SESSION_CHAT_HTTP_ENABLED requires exact configuration and scoped session/IP authentication.')
        bot_flag = os.environ.get('BOT_VERIFICATION_ENABLED', 'false').strip().lower()
        if bot_flag not in ('true', 'false'):
            raise ValueError('BOT_VERIFICATION_ENABLED must be a valid boolean.')
        try:
            bot_timeout = float(os.environ.get('BOT_TIMEOUT_SECONDS', '5'))
            if not math.isfinite(bot_timeout) or not 0.01 <= bot_timeout <= 10:
                raise ValueError()
        except ValueError:
            raise ValueError('BOT_TIMEOUT_SECONDS must be between 0.01 and 10.') from None
        result = cls(
            backend_deployment_policy=deployment_policy,
            legacy_chat_enabled=legacy_flag == 'true',
            capability_auth_enabled=capability_flag == 'true',
            verified_session_auth_token=os.environ.get('VERIFIED_SESSION_AUTH_TOKEN', ''),
            session_chat_auth_token=os.environ.get('SESSION_CHAT_AUTH_TOKEN', ''),
            verified_session_credential_id=os.environ.get('VERIFIED_SESSION_CREDENTIAL_ID', 'verified-session-v1'),
            session_chat_credential_id=os.environ.get('SESSION_CHAT_CREDENTIAL_ID', 'session-chat-v1'),
            session_chat_enabled=session_chat_flag == 'true',
            session_chat_http_enabled=http_flag == 'true',
            bot_verification_enabled=bot_flag == 'true',
            bot_secret=os.environ.get('BOT_PROVIDER_SECRET', ''),
            bot_hostnames=tuple(h.strip() for h in os.environ.get('BOT_ALLOWED_HOSTNAMES', '').split(',') if h.strip()),
            bot_action=os.environ.get('BOT_EXPECTED_ACTION', 'portfolio_session'),
            bot_max_age_seconds=session_limit('BOT_MAX_AGE_SECONDS', 300, 300),
            bot_timeout_seconds=bot_timeout,
            bot_attempts_minute=session_limit('BOT_ATTEMPTS_MINUTE', 10, 1000),
            bot_attempts_day=session_limit('BOT_ATTEMPTS_DAY', 100, 1000),
            bot_max_concurrent=session_limit('BOT_MAX_CONCURRENT', 2, 4),
            ip_admission_enabled=ip_enabled,
            ip_rate_hmac_key=ip_key,
            ip_admission_minute_limit=session_limit('IP_ADMISSION_MINUTE_LIMIT', 10, 10000),
            ip_admission_day_limit=session_limit('IP_ADMISSION_DAY_LIMIT', 60, 10000),
            session_admission_enabled=session_enabled,
            session_admission_minute_limit=session_limit('SESSION_ADMISSION_MINUTE_LIMIT', 3, 10000),
            session_admission_hour_limit=session_limit('SESSION_ADMISSION_HOUR_LIMIT', 12, 10000),
            session_issuance_enabled=session_issuance_enabled(staging),
            session_lifetime_seconds=session_limit('SESSION_LIFETIME_SECONDS', 14400, 86400),
            session_issuance_minute_limit=session_limit('SESSION_ISSUANCE_MINUTE_LIMIT', 10, 10000),
            session_issuance_day_limit=session_limit('SESSION_ISSUANCE_DAY_LIMIT', 100, 10000),
            session_max_live=session_limit('SESSION_MAX_LIVE', 500, 10000),
            usage_path=validate_usage_path(Path(os.environ.get("USAGE_LEDGER_PATH", "/var/lib/ai-portfolio-assistant/usage.sqlite3")), index_path()),
            usage_daily_limit=positive_integer("USAGE_DAILY_LIMIT", 100),
            usage_monthly_limit=positive_integer("USAGE_MONTHLY_LIMIT", 1000),
            usage_max_concurrent=positive_integer("USAGE_MAX_CONCURRENT", 2),
            usage_busy_ms=usage_busy_ms(),
            staging_auth_enabled=staging,
            staging_auth_token=token,
            staging_budget_requests=positive_integer("STAGING_BUDGET_REQUESTS", 10),
            staging_budget_window_seconds=positive_integer("STAGING_BUDGET_WINDOW_SECONDS", 60),
            gemini_network_policy=validate_network_policy(os.environ.get("GEMINI_NETWORK_POLICY", "auto")),
            chat_deadline_seconds=chat_deadline_seconds(),
            index_path=index_path(),
            embedding_timeout_ms=positive_integer("GEMINI_EMBEDDING_TIMEOUT_MS", 10_000),
            generation_timeout_ms=positive_integer("GEMINI_GENERATION_TIMEOUT_MS", 20_000),
            max_output_tokens=generation_output_tokens(),
            thinking_level=generation_thinking_level(),
            max_body_bytes=positive_integer("CHAT_MAX_BODY_BYTES", 8192),
            max_concurrent=positive_integer("CHAT_MAX_CONCURRENT", 4),
            rate_requests=positive_integer("CHAT_RATE_LIMIT_REQUESTS", 20),
            rate_window_seconds=positive_integer("CHAT_RATE_LIMIT_WINDOW_SECONDS", 60),
            rate_max_clients=positive_integer("CHAT_RATE_LIMIT_MAX_CLIENTS", 1024),
        )
        from src.legacy_policy import validate_legacy_configuration
        validate_legacy_configuration(result)
        from src.auth import validate_configuration, AuthorizationError
        try:
            validate_configuration(result)
        except AuthorizationError:
            raise ValueError('Capability authentication configuration is invalid.') from None
        if result.bot_verification_enabled:
            from src.bot_verification import validate_policy, VerificationError
            try:
                validate_policy(result)
            except VerificationError:
                raise ValueError('Bot verification configuration is invalid.') from None
        return result
