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

`test_usage.py` also rejects same-column schemas with missing constraints or
primary-key indexes, unsupported schema changes, negative/nonintegral counters,
invalid identifiers and inconsistent accounting. Authenticated malformed-storage
requests fail closed without initializing provider clients or repairing storage.
Formatting-only schema differences and previously admitted work above newly
lowered limits remain valid. A validation-work guard is exercised with a synthetic
historical ledger. All databases are temporary; no operational state is accessed.

`test_usage.py` covers explicit disabled initialization, atomic UTC day/month
allowances, thread and subprocess races, durable concurrency and restart state,
bounded SQLite busy waits, missing/corrupt/permission failures, operator recovery,
emergency disable, provider accounting, alternate embedding/CLI gates and safe
errors. A blocked mocked provider proves the HTTP deadline retains the durable
slot until worker exit. Every test uses a temporary ledger; no operational ledger
is created or enabled, and `.env` is never read. The shared fixture explicitly
enables only synthetic temporary databases for existing provider tests.

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

`test_auth.py` covers the opt-in capability matrix, independent configuration,
generic failures, constant-time comparison, credential/principal rotation,
request-bound principals, method/path/encoding/query variants, duplicate headers,
forged capability claims and denial of HTTP administration. HTTP tests run against
mocked verification transports and temporary ledgers. Scoped internal chat tests
exercise original-context supervision, TrustedIP/session/global requirements and
the absence of the future HTTP route. Compatibility-mode regression tests remain
unchanged. No real credential, operational database or external provider is used.

`test_session_chat.py` covers the internal service only: disabled configuration,
gateway/session authentication, absence of trusted ingress, forged IP/header
claims, strict streamed JSON validation, atomic quotas, RAG reuse, provider guards,
storage errors, safe logs, and worker-owned cleanup after timeout/cancellation.
It explicitly verifies `/internal/session-chat` is absent even with the internal
flag enabled, and that legacy `/chat` remains unchanged. Synthetic `TrustedIP`
objects do not establish production ingress trust. A subsequent controlled local
HTTP/session/RAG test succeeded; production ingress and deployment remain unverified.

`test_bot_verification.py` uses mocked HTTPX transports and temporary version 5
ledgers. It covers strict provisional provider policy, TLS/retry/redirect settings,
overall deadlines and streamed response bounds, age boundaries, malformed JSON,
hostname/action errors, durable replay and cross-process claims, request binding,
attempt/capacity limits, migration rollback/preservation, finalization rollback,
cancellation, emergency changes during verification, and safe API/log behavior.
It verifies the separate disabled route rejects browser CORS, malformed bodies
and unauthenticated callers. No Cloudflare/Gemini request or operational migration
occurs. Offline success does not confirm current provider protocol or privacy terms.

`test_ip_admission.py` verifies the disabled internal trusted-identity contract,
IP normalization and mapped-address aliases, HMAC/key validation and mismatch
rejection, explicit version 4 migration and rollback, exact rolling minute/day
boundaries, same-IP limits across sessions, independent identities, thread/process
final-slot races and restart persistence. It checks cleanup without refunds,
schema/storage failures, global/session/emergency controls, rollback after prior
accounting writes, provider-call isolation and absence of raw IPs or keys in
storage/logs/errors. All identities and secrets are synthetic, databases are
temporary, and subprocesses block network and dotenv access. No HTTP identity
extraction or public integration is exercised or enabled.

`test_session_admission.py` exercises the isolated, disabled-by-default gateway
adapter and atomic version 3 session/global admission. Coverage includes strict
dual-header authentication, unverified/expired/revoked/unknown identities, rolling
minute/hour boundaries, final-slot thread/process races, different-session global
competition, rollback, durable quotas/concurrency, provider attempt/no-refund
behavior, revocation races, worker completion, storage failures and safe logs.
It verifies the existing `/chat` contract and absence of a new session chat route.
Existing deadline tests remain in the full suite; the adapter does not add an
HTTP supervisor. Providers are mocked and all ledgers are temporary.

`test_issuance.py` covers disabled-by-default configuration, mandatory gateway
bearer authentication, one-time 256-bit token delivery and digest-only storage,
strict empty bodies, independent ASGI streamed-size/length/timeout probes,
non-sliding expiration, revocation and unverified-session rejection. It checks
durable rolling minute/day and live-session limits, concurrent final-slot races,
fresh-process persistence, independent emergency shutdown, version 3 migration
and rollback, accounting preservation, and sanitized errors/logs. All databases
are temporary and providers/network are mocked or blocked. No operational
issuance is enabled by the tests.

`test_sessions.py` verifies schema versions 1 and 2, explicit disabled-maintenance
migration, preservation of counters/emergency state/active reservations, rollback
after SQL or final-validation failure, and fresh-process migration/restart.
It covers strict session constraints and indexes, foreign keys, digest uniqueness,
expiration/revocation/verification, concurrent thread/process storage, event
queries, and safeguarded retention cleanup with accounting preservation. Runtime
and HTTP checks prove no automatic migration or migration endpoint exists.
All storage is temporary; subprocesses block network and dotenv access. These
tests do not issue public tokens, create cookies, enable public chat or contact
Gemini. Existing version 1 validation regressions remain unchanged.

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

### Gateway assertion replay (schema 6)

`test_gateway_assertions.py` retains the offline cross-language vectors and strict
cryptographic/request-binding tests. `test_gateway_replay.py` additionally verifies
consume-once SQLite claims, pinned verifier provenance and mutation resistance,
thread/process races, fresh-process restart and operator migration, same-nonce
re-signing, namespace/key rotation, time/skew/rollback boundaries, lock timeouts,
storage/schema failures, transactional rollback, post-commit expiry, and permanent
claims after downstream errors, cancellation and lost responses. Cleanup/recovery
cannot remove replay history. SQL work-budget exhaustion denies admission.

Migration fixtures start from actual version 5 and preserve daily/monthly/provider
counts, active reservations, session/issuance/IP records, all bot-proof states and
both emergency controls. Version 6 tests re-exercise session/IP/global limits and
provider accounting. Startup still does not migrate, and no session-chat HTTP
route is registered. Neither providers nor operational storage are used.

Run locally with existing network guards:

```sh
.venv/bin/python -B -m unittest tests.test_gateway_assertions tests.test_gateway_replay -v
.venv/bin/python -B -m unittest discover -s tests -v
```

Clock correctness, hosting ingress provenance, actual filesystem durability and
disaster-recovery discipline remain operational assumptions; unit tests do not
prove those deployment properties. See `docs/gateway-replay-v6.md`.

### Authenticated internal request integration

`test_authenticated_session_chat.py` composes the actual scoped authenticator,
assertion verifier, schema 6 replay service, shared chat supervisor/worker and
atomic session/IP/global admission against temporary databases. Gemini clients
remain mocked and network access blocked. Its resolver holds explicit synthetic
fixture evidence; it does not prove production ingress trust.

Coverage includes credential/authority/key separation, forged/modified principals,
exact byte/session/method/path binding, replay races, invalid storage, resolver
policy/IP/authorization failures and forged resolved identities, session validity,
all admission budgets, emergency shutdown and no legacy dispatch. It checks one
absolute deadline across slow verification, replay, resolver, worker-pool waiting,
SQLite session admission and provider execution; cancellation and 504 retain
worker-owned capacity/accounting, and replay claims are never refunded.
IPv6 identities use the existing HMAC accounting, and resolver execution occurs
after the replay transaction has closed. Logs/errors exclude raw credentials,
proof/session tokens, body content and IP values.

Run the focused suite with:

```sh
.venv/bin/python -B -m unittest tests.test_authenticated_session_chat -v
```

The existing full offline suite remains required. Production resolver evidence,
HTTP upload/deadline handoff and route/header integration are separate tasks;
these tests neither activate public chat nor access an operational database.

### Disabled internal HTTP adapter

`test_session_chat_http.py` exercises the actual FastAPI application through
TestClient, plus raw ASGI streams for framing, upload deadlines and cancellation.
It uses temporary schema 6 ledgers, test-only signing/bearer credentials, an
explicit fixture identity resolver and mocked Gemini. Network access stays blocked.

Coverage includes exact disabled feature configuration, fail-closed startup without
composition, capability/credential isolation, duplicate required headers, assertion
and exact raw-body/session binding, malformed JSON/Unicode, unknown/duplicate fields,
1,000 Unicode codepoints, body/stream limits, framing ambiguity, origins/forwarded
identity headers, route aliases/methods, replay races, database failure, quota and
emergency shutdown, inherited upload/worker deadlines, provider failure, cancellation,
no sensitive logs/metadata, health/readiness and legacy-route isolation. No test
resolver can be selected from normal environment configuration.

```sh
.venv/bin/python -B -m unittest tests.test_session_chat_http -v
.venv/bin/python -B -m unittest discover -s tests -v
```

Existing authentication and deadline tests remain unchanged. Reserved-path handling
preserves existing wrong-credential denials when HTTP execution is disabled.
The release-context regression suite checks the expanded runtime import allowlist
without building Docker or regenerating embeddings. See `docs/session-chat-http.md`.
Live ingress provenance, proxy framing and public deployment readiness are not
established by these offline tests.


### Production legacy isolation and identity boundary

`test_production_policy.py` checks production/default denial before any paid work,
exact operator configuration, authenticated isolated staging, credential scope
separation, alias/method/query denial without redirects, forged request-state
rejection, handler defense, sanitized errors, health/readiness and Docker runtime
manifest consistency. Existing legacy execution tests now explicitly authenticate
under isolated staging; their provider, deadline, capacity and RAG assertions are
retained. Anonymous local legacy execution is no longer supported.

The full suite runs using temporary ledgers and mocked providers. Existing
frontend identity-provider and backend resolver negative tests still cover
missing providers, policy mismatch, identity mismatch, forwarding spoofing and
sealed context requirements. No fixture proves Vercel/Railway ingress provenance.
See `docs/production-trust-boundary.md` for evidence still required before any
production resolver or public activation. Docker coverage here is static only.

### Isolated local development integration

`test_local_development.py` and `local_frontend_workflow.mjs` exercise the real
Node gateway modules against FastAPI over an offline pipe bridge. Disposable
schema6 SQLite, mocked Siteverify transport and mocked Gemini preserve verified
issuance, secure cookie attributes, signing/replay, accounting and RAG checks.
`node --test tests/local_frontend.test.mjs` covers local peer, origin/header,
private profile and hosted-mode rejection. See `docs/local-development.md` for
commands, the operator-confirmed local browser/TLS/live-provider result, and the
remaining unverified production deployment/ingress requirements. Automated tests
continue to use mocked providers and disposable state.
