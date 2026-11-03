"""Provider transport policy and deliberately sanitized error classification."""

import httpx
from google.genai import errors, types


ERROR_DETAIL = "The AI assistant could not generate a response."


def http_options(timeout_ms: int) -> types.HttpOptions:
    # In google-genai 2.30.1 timeout is milliseconds; attempts includes the
    # original request. One attempt means zero automatic retries.
    return types.HttpOptions(
        timeout=timeout_ms, retry_options=types.HttpRetryOptions(attempts=1)
    )


class EmptyResponseError(Exception):
    pass


class BlockedResponseError(Exception):
    pass


def response_text(response) -> str:
    feedback = getattr(response, "prompt_feedback", None)
    reason = getattr(feedback, "block_reason", None)
    reason = getattr(reason, "value", reason)
    if reason not in (None, 0, "BLOCK_REASON_UNSPECIFIED"):
        raise BlockedResponseError()
    blocked_reasons = {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "RECITATION"}
    for candidate in getattr(response, "candidates", None) or []:
        reason = getattr(candidate, "finish_reason", None)
        if getattr(reason, "value", reason) in blocked_reasons:
            raise BlockedResponseError()
    answer = response.text
    if not isinstance(answer, str) or not answer.strip():
        raise EmptyResponseError()
    return answer


def classify_failure(error: Exception) -> tuple[int, str, dict[str, str]]:
    if isinstance(error, (TimeoutError, httpx.TimeoutException)):
        return 504, "timeout", {}
    if isinstance(error, BlockedResponseError):
        return 502, "blocked_response", {}
    if isinstance(error, EmptyResponseError):
        return 502, "empty_response", {}
    if isinstance(error, errors.APIError):
        if error.code in (408, 504):
            return 504, "timeout", {}
        if error.code == 429:
            return 503, "quota", {"Retry-After": "60"}
        return 502, "provider_error", {}
    if isinstance(error, httpx.RequestError):
        return 502, "provider_connection", {}
    return 500, "unexpected", {}
