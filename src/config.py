"""Validated operational settings. Load after dotenv at application entry points."""

from dataclasses import dataclass
import math
import os
from pathlib import Path
from urllib.request import getproxies


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


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
        return cls(
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
