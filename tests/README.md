# Offline regression tests

Run from the repository root using the existing environment:

```sh
.venv/bin/python -B -m unittest discover -s tests -v
```

With that environment activated, the equivalent command is:

```sh
python -B -m unittest discover -s tests -v
```

The suite uses Python's built-in `unittest`, the installed FastAPI/Starlette
TestClient, HTTPX, and google-genai. No installation, real API key, model call,
or live ingestion is required. All existing regression scenarios remain;
none are skipped or marked as expected failures.

## Current coverage

- Routing: broad project lists, technology filters, named projects, wording
  variations, curly apostrophes, and unrelated questions.
- Expansion: word boundaries prevent unrelated words such as "storage" from
  activating RAG expansion.
- Knowledge/chunking: missing and empty sources, shortened project sections,
  nonempty chunks, and discovery of newly added projects.
- Retrieval: cosine dimensions and zero vectors, empty corpora, BM25 arithmetic,
  top_k validation, and preservation of hybrid ranking.
- Persistent indexes: version/model/source validation, deterministic IDs,
  chunk coverage/order/text, vector dimensions and finite values, strict JSON,
  bounded artifact size, atomic publication, and preservation on failure.
- Runtime: imports make no provider calls; startup loads a validated index;
  missing or stale artifacts fail safely; health/readiness do not contact Gemini.
- API: successful response schema, invalid JSON and fields, message/body limits,
  streaming body limits, rate thresholds/reset/Retry-After, capacity saturation,
  cancellation, provider failures, and sanitized operational logs.
- Generation: explicit STOP is required; empty, blocked, truncated, missing,
  malformed, and unsupported completion states fail safely. Optional token
  usage is sanitized; token and thinking settings are validated.
- Transport: IPv4 source binding, unchanged provider hostname, certificate and
  hostname verification, SNI, proxy rejection, timeouts, and no global changes.
- Protected staging: opt-in default-deny HTTP authentication, constant-time
  comparison, duplicate/malformed credential rejection, future-route protection,
  public health checks, disabled docs, explicit CORS allowlists, sanitized
  validation errors, and an IP-independent aggregate budget. Rejections make no
  provider calls; existing deadlines, worker leases, body limits and peer rate
  limits also run under authenticated staging. The shared fixture disables
  staging by default and never reads a real staging credential.

The original Phase 1 baseline had 63 tests exposing 15 production defects.
Those defects are fixed; historical failure counts are not current results.
Classes named `Known…RegressionTests` continue asserting the corrected behavior.
Subtests cover additional inputs without increasing the test-method count.

## Application deadline and capacity

Tests use short configurable deadlines and event-controlled provider mocks.
They verify that HTTP 504 arrives before a blocked synchronous worker finishes,
including slow client initialization, embedding, generation, body reading, and
worker-pool admission. Health/readiness remain responsive. A timed-out worker
keeps its capacity lease until the worker and ASGI operation actually finish;
release occurs exactly once, and late work cannot start another provider phase
or emit a misleading success log. HTTP transport timeouts are tested separately.

These checks validate application supervision, not forced thread termination.
An already-running provider operation can continue after HTTP 504. The deadline
requires a responsive event loop, and transport timeouts are not total deadlines.

## SDK continuation and retry protection

`test_provider_lifecycle.py` runs the actual installed Gemini SDK against
`httpx.MockTransport`, with external network guards still active. A simulated
CONTINUATION response includes a valid continuation token. The application sets
`automatic_continuation=False`, so exactly one generation HTTP request occurs
and the incomplete response becomes a sanitized HTTP 502. A second request
would cause the regression test to fail.

The same tests cover STOP success, MAX_TOKENS rejection, and quota/server errors
without automatic HTTP retries. They check the unchanged model, token budget,
LOW thinking, 20-second generation timeout, and 40-second application deadline.
Query embedding remains a separate mocked operation with its existing task type
and dimensions. No provider response text or credentials enter request logs.

## Provider shutdown

Separate generation and embedding client doubles test successful cleanup,
either close failing, both closes failing, and shutdown without initialized
clients. Both cleanup attempts occur regardless of an ordinary close exception;
references are cleared, a fixed structured error identifies failed clients, and
a generic shutdown exception excludes provider messages and exception chains.
These tests make no provider requests. A failed close may still leave resources
for the process supervisor to reclaim; these tests do not prove close is bounded.

## Offline guarantees

`offline.py` provides a scoped `OfflineTestCase` fixture that:

- Blocks socket connections, DNS, and synchronous/asynchronous HTTPX network
  transports. TestClient uses an in-process ASGI transport.
- Patches `google.genai.Client` before importing production entry points.
  SDK integration tests deliberately use the actual constructor with a mocked
  transport or fake sockets; network access remains blocked.
- Supplies a clearly fake API key and disables dotenv loading, so the real
  `.env` is never read.
- Creates validated synthetic 3072-dimensional index artifacts in temporary
  directories; no real document embeddings are generated.
- Restores provider patches, module cache entries, and package attributes after
  every test, including failures.

Intentional guard probes raise before making connections. Atomic-ingestion
unit tests invoke ingestion only with mocked embedding clients and temporary
artifacts; they do not run the paid ingestion CLI against portfolio artifacts.

## Evaluators and limitations

Evaluator tests verify all-pass, all-fail, one-failure, and CLI exit statuses
under offline guards. The standalone retrieval evaluator is still a live query
embedding tool: do not run `python -m src.evaluate_retrieval` for offline checks.
The router evaluator is offline.

Synthetic vectors establish arithmetic and ordering, not real semantic quality,
Recall@3, grounding, provider availability, safety behavior, or production cost
and latency. STOP does not prove factual or grammatical completeness. Live
verification requires separate authorization and is never part of this suite.

The installed Starlette TestClient emits an HTTPX deprecation warning. Tests
run with existing dependencies; no dependency is installed to silence it.
