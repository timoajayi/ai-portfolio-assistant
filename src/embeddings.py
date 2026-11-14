import os
import json
import logging
from threading import Lock

from dotenv import load_dotenv
from google import genai
from google.genai import errors
import httpx

from src.chunking import chunk_portfolio_by_section
from src.config import Settings
from src.provider import http_options
from src.index_store import EMBEDDING_MODEL, EMBEDDING_DIMENSIONS
from src.diagnostics import phase
from src.usage import paid_call


load_dotenv()

api_key = os.getenv("GOOGLE_API_KEY")

settings = Settings.from_env()
client = None
_client_lock = Lock()


def get_client():
    global client
    with phase("embedding_client_initialization"), _client_lock:
        if client is None:
            if not api_key:
                raise ValueError("GOOGLE_API_KEY is required for embedding requests.")
            options = http_options(
                settings.embedding_timeout_ms, network_policy=settings.gemini_network_policy
            ).model_copy(update={
                'api_version': 'v1beta', 'base_url': 'https://generativelanguage.googleapis.com/',
            })
            # This application uses the Developer API; SDK environment defaults
            # must not select Vertex/Enterprise mode or redirect this API key.
            client = genai.Client(vertexai=False, api_key=api_key, http_options=options)
        return client


def close_client():
    global client
    with _client_lock:
        if client is not None:
            try:
                client.close()
            finally:
                client = None



_SDK_ERROR_STATUSES = frozenset({
    'CANCELLED', 'UNKNOWN', 'INVALID_ARGUMENT', 'DEADLINE_EXCEEDED', 'NOT_FOUND',
    'ALREADY_EXISTS', 'PERMISSION_DENIED', 'UNAUTHENTICATED', 'RESOURCE_EXHAUSTED',
    'FAILED_PRECONDITION', 'ABORTED', 'OUT_OF_RANGE', 'UNIMPLEMENTED', 'INTERNAL',
    'UNAVAILABLE', 'DATA_LOSS',
})
_EMBEDDING_ERROR_TYPES = (
    errors.APIError, errors.ClientError, errors.ServerError,
    httpx.ConnectError, httpx.ReadError, httpx.WriteError, httpx.ConnectTimeout,
    httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout,
    httpx.RemoteProtocolError, httpx.LocalProtocolError, httpx.DecodingError,
    TimeoutError, ValueError, RuntimeError,
)



_REJECTION_REASONS = frozenset({
    'API_KEY_INVALID', 'API_KEY_EXPIRED', 'API_KEY_SERVICE_BLOCKED',
    'API_KEY_HTTP_REFERRER_BLOCKED', 'API_KEY_IP_ADDRESS_BLOCKED',
    'SERVICE_DISABLED', 'BILLING_DISABLED',
})


def _structured_rejection_reason(error):
    """Read only bounded ErrorInfo fields; never serialize provider details."""
    if not isinstance(error, errors.APIError) or type(error.details) is not dict:
        return None
    envelope = error.details.get('error', error.details)
    if type(envelope) is not dict:
        return None
    details = envelope.get('details', [])
    if type(details) is not list or len(details) > 16:
        return None
    reasons = set()
    for item in details:
        if type(item) is not dict or item.get('@type') != 'type.googleapis.com/google.rpc.ErrorInfo':
            continue
        reason, domain = item.get('reason'), item.get('domain')
        if (type(domain) is not str or domain not in ('googleapis.com', 'generativelanguage.googleapis.com')
                or type(reason) is not str or reason not in _REJECTION_REASONS):
            return None
        reasons.add(reason)
    return next(iter(reasons)) if len(reasons) == 1 else None


def _log_embedding_failure(error):
    code = error.code if isinstance(error, errors.APIError) else None
    status = error.status if isinstance(error, errors.APIError) else None
    mode = getattr(client, 'vertexai', None)
    record = {
        'upstream_http_status': code if type(code) is int and 100 <= code <= 599 else None,
        'sdk_status': status if type(status) is str and status in _SDK_ERROR_STATUSES else None,
        'exception_class': next((kind.__name__ for kind in _EMBEDDING_ERROR_TYPES
                                 if type(error) is kind), 'Exception'),
        'operation': 'embedding',
        'api_mode': 'developer' if mode is False else 'vertex' if mode is True else 'unknown',
        'rejection_reason': _structured_rejection_reason(error),
    }
    try:
        logging.getLogger('portfolio.api').warning(json.dumps(record))
    except Exception:
        pass  # Diagnostic sink errors must not replace the provider failure.


def create_embedding(
    text: str,
    task_type: str = "RETRIEVAL_DOCUMENT",
) -> list[float]:
    def operation():
        try:
            return get_client().models.embed_content(
                model=EMBEDDING_MODEL,
                contents=text,
                config={
                    "task_type": task_type,
                    "output_dimensionality": EMBEDDING_DIMENSIONS,
                },
            )
        except Exception as error:
            _log_embedding_failure(error)
            raise

    with phase("embedding"):
        response = paid_call("embedding", operation)

    return response.embeddings[0].values


if __name__ == "__main__":
    chunks = chunk_portfolio_by_section()

    first_chunk = chunks[0]

    embedding = create_embedding(first_chunk)

    print("TEXT:")
    print(first_chunk)

    print("\nEMBEDDING PREVIEW:")
    print(embedding[:10])

    print(f"\nEMBEDDING DIMENSIONS: {len(embedding)}")
