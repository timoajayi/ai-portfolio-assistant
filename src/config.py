"""Validated operational settings. Load after dotenv at application entry points."""

from dataclasses import dataclass
import os


def positive_integer(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
        if value > 0:
            return value
    except ValueError:
        pass
    # Never include the supplied value: configuration may contain secrets.
    raise ValueError(f"{name} must be a positive integer.")


@dataclass(frozen=True)
class Settings:
    embedding_timeout_ms: int = 10_000
    generation_timeout_ms: int = 20_000
    max_output_tokens: int = 512
    max_body_bytes: int = 8192
    max_concurrent: int = 4
    rate_requests: int = 20
    rate_window_seconds: int = 60
    rate_max_clients: int = 1024

    @classmethod
    def from_env(cls):
        return cls(
            embedding_timeout_ms=positive_integer("GEMINI_EMBEDDING_TIMEOUT_MS", 10_000),
            generation_timeout_ms=positive_integer("GEMINI_GENERATION_TIMEOUT_MS", 20_000),
            max_output_tokens=positive_integer("GEMINI_MAX_OUTPUT_TOKENS", 512),
            max_body_bytes=positive_integer("CHAT_MAX_BODY_BYTES", 8192),
            max_concurrent=positive_integer("CHAT_MAX_CONCURRENT", 4),
            rate_requests=positive_integer("CHAT_RATE_LIMIT_REQUESTS", 20),
            rate_window_seconds=positive_integer("CHAT_RATE_LIMIT_WINDOW_SECONDS", 60),
            rate_max_clients=positive_integer("CHAT_RATE_LIMIT_MAX_CLIENTS", 1024),
        )
