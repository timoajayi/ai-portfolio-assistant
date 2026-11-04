"""Provider transport policy and deliberately sanitized error classification."""

import httpx
from google.genai import errors, types
from src.diagnostics import ChatDeadlineExceeded
from src.config import validate_network_policy


ERROR_DETAIL = "The AI assistant could not generate a response."


def http_options(timeout_ms: int, *, network_policy: str = "auto") -> types.HttpOptions:
    # In google-genai 2.30.1 timeout is milliseconds; attempts includes the
    # original request. One attempt means zero automatic retries.
    policy = validate_network_policy(network_policy)
    client_args = None
    if policy == "ipv4":
        # Public SDK passthrough + public HTTPX IPv4 source binding. The
        # destination remains the SDK's hostname, preserving DNS, TLS/SNI,
        # and hostname validation. SDK-owned HTTPX clients close this transport.
        client_args = {"transport": httpx.HTTPTransport(
            local_address="0.0.0.0", verify=True, retries=0, trust_env=True
        )}
    return types.HttpOptions(
        timeout=timeout_ms,
        retry_options=types.HttpRetryOptions(attempts=1),
        client_args=client_args,
    )


class EmptyResponseError(Exception):
    pass


class BlockedResponseError(Exception):
    pass


class IncompleteResponseError(Exception):
    pass


class InvalidResponseError(Exception):
    pass


FINISH_REASONS = frozenset(reason.value for reason in types.FinishReason)
BLOCKED_REASONS = frozenset({
    "SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "RECITATION",
    "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION",
})
TOKEN_FIELDS = (
    "prompt_token_count", "candidates_token_count", "thoughts_token_count",
    "total_token_count",
)


def response_candidates(response):
    candidates = getattr(response, "candidates", None)
    return candidates if isinstance(candidates, (list, tuple)) else ()


def finish_reason(candidate) -> str:
    reason = getattr(candidate, "finish_reason", None)
    if reason is None:
        return "MISSING"
    if isinstance(reason, types.FinishReason):
        reason = reason.value
    if type(reason) is not str:
        return "MALFORMED"
    # Never copy an arbitrary upstream string into logs.
    return reason if reason in FINISH_REASONS else "UNKNOWN"


def generation_metadata(response) -> dict:
    candidates = response_candidates(response)
    metadata = {
        "finish_reason": finish_reason(candidates[0]) if candidates else "MISSING_CANDIDATE",
    }
    usage = getattr(response, "usage_metadata", None)
    for name in TOKEN_FIELDS:
        value = getattr(usage, name, None)
        # Reject booleans, strings, negative/nonfinite and unreasonable values.
        metadata[name] = value if type(value) is int and 0 <= value <= 2**63 - 1 else None
    return metadata


def response_text(response) -> str:
    feedback = getattr(response, "prompt_feedback", None)
    reason = getattr(feedback, "block_reason", None)
    reason = getattr(reason, "value", reason)
    if reason not in (None, 0, "BLOCK_REASON_UNSPECIFIED"):
        raise BlockedResponseError()
    candidates = response_candidates(response)
    if not candidates:
        raise InvalidResponseError()
    reasons = [finish_reason(candidate) for candidate in candidates]
    if any(reason in BLOCKED_REASONS for reason in reasons):
        raise BlockedResponseError()
    if any(reason in ("MAX_TOKENS", "CONTINUATION") for reason in reasons):
        raise IncompleteResponseError()
    if any(reason != "STOP" for reason in reasons):
        raise InvalidResponseError()
    answer = getattr(response, "text", None)
    if not isinstance(answer, str) or not answer.strip():
        raise EmptyResponseError()
    return answer


def classify_failure(error: Exception) -> tuple[int, str, dict[str, str]]:
    if isinstance(error, ChatDeadlineExceeded):
        return 504, "deadline", {}
    if isinstance(error, (TimeoutError, httpx.TimeoutException)):
        return 504, "timeout", {}
    if isinstance(error, BlockedResponseError):
        return 502, "blocked_response", {}
    if isinstance(error, EmptyResponseError):
        return 502, "empty_response", {}
    if isinstance(error, IncompleteResponseError):
        return 502, "incomplete_response", {}
    if isinstance(error, InvalidResponseError):
        return 502, "invalid_response", {}
    if isinstance(error, errors.APIError):
        if error.code in (408, 504):
            return 504, "timeout", {}
        if error.code == 429:
            return 503, "quota", {"Retry-After": "60"}
        return 502, "provider_error", {}
    if isinstance(error, httpx.RequestError):
        return 502, "provider_connection", {}
    return 500, "unexpected", {}
