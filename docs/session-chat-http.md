# Disabled internal session-chat HTTP adapter

`POST /internal/session-chat` is implemented as an outer ASGI adapter around the
existing FastAPI application. **It is disabled by default. Public chat is not
activated. Production visitor-IP provenance has not been verified.**

## Registration and composition

The application is a module-level FastAPI instance rather than a configurable
app factory. A fail-closed reserved-path middleware is therefore used instead of
conditionally mutating the router. No FastAPI route/OpenAPI operation is
registered in either mode. The middleware intercepts this path before CORS,
shared middleware and slash redirects. Disabled requests cannot execute chat;
canonical requests return 404 after preserving existing scoped-authentication
401 denials when capability mode is enabled. Aliases never become executable.

The new server setting `SESSION_CHAT_HTTP_ENABLED` defaults to `false`. Only the
exact string `true` is accepted as enabling it; invalid values fail configuration.
Enabling requires the existing scoped authentication, staging authentication,
internal session-chat, session admission and IP admission protections. No existing
flag is automatically enabled or modified.

A flag alone is insufficient. Trusted server composition must provide an actual
`AuthenticatedSessionChatService` in `app.state.session_chat_pipeline` before
startup. Its immutable settings, application and shared chat controls must match.
Enabled startup fails without this composition. Requests recheck it and fail
closed with 503 if it is missing or inconsistent. No environment setting selects
or creates a resolver, fixture, signing key, pipeline or trusted identity.
The default application supplies none; this phase cannot run production chat by
changing a flag alone. No real environment file is changed.

## Exact request contract

```text
POST /internal/session-chat
Authorization: Bearer <session-chat gateway credential>
X-Portfolio-Session: <canonical session token>
X-Portfolio-Gateway-Assertion: <v1 compact signed assertion>
Content-Type: application/json

{"message":"..."}
```

Each required header occurs exactly once, with case-insensitive header names.
Bearer syntax and constant-time comparison use the existing scoped authenticator.
Issuance and legacy credentials cannot authorize this operation. Canonical session
text is the existing unpadded 43-character base64url encoding of 32 bytes.
The assertion is ASCII, no more than 2,048 characters, and has no whitespace.
Its signature and all claims are verified only by the existing verifier.

Requests must use the exact unprefixed path/method and raw path. Trailing slashes,
queries, mounts/root prefixes, encoded aliases, dot/double-slash aliases and
unsupported methods are rejected without redirects. Normalization is used only
to reject aliases, never to authorize them. A client that normalizes its URL
before transmission sends a different, canonical request; tests distinguish this
from an alias actually received by ASGI.

No Origin header is accepted, including `null`. There is no browser CORS access
or preflight bypass. `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `Forwarded`,
`X-Identity-Digest` and `X-Visitor-IP` are rejected. The connection peer is not
used to prove original visitor identity. Recognizable header names or a gateway
signature alone do not establish ingress trust.

## Framing, body and upload limits

- At most 32 headers and 8,192 combined header-name/value bytes. Malformed names,
  CR/LF/NUL values and duplicate critical headers fail closed.
- Exact `application/json`; no charset/media-type alternatives. Content encoding
  is absent or exactly `identity`; compression is unsupported.
- At most one canonical unsigned decimal Content-Length. Duplicate/combined,
  signed, padded or oversized lengths are rejected. Actual received bytes must
  equal the declared length.
- Transfer-Encoding may be exactly one `chunked` header on HTTP/1.1, without
  Content-Length or trailers. Other/combined/duplicate encodings are rejected.
  ASGI's server must parse HTTP framing correctly: the adapter reads already
  dechunked body bytes, never raw chunk syntax. HTTP/2 Transfer-Encoding is rejected.
- The body is capped while reading at `min(CHAT_MAX_BODY_BYTES, 8192)`, regardless
  of Content-Length. Missing length is not an unbounded-body exception.
- Upload has a five-second maximum, additionally capped by the remaining overall
  chat deadline. Upload timeout returns 408, or 504 when the overall deadline is
  exhausted. HTTP upload admission is bounded and non-blocking; saturation is 503.

The shared `validate_chat_body` parser is used here and by SessionChatService.
It rejects invalid UTF-8/BOM, escaped lone surrogates, duplicate keys (including
escaped equivalents), malformed JSON, non-object bodies, unknown fields and
trailing content. It delegates message validation to the existing `ChatRequest`
model: exactly one nonblank string with a maximum of 1,000 Unicode codepoints.
It does not create a second message policy. Valid supplementary Unicode characters
count as codepoints, not UTF-8 bytes or UTF-16 code units.

Framing is checked, the shared authenticator mints a scoped principal before any
body read, then the raw body is bounded and validated. The adapter never
reserializes it. The exact received bytes and canonical session text enter the
existing assertion verifier. Caller ASGI state is discarded; header claims cannot
inject a principal, capability, request marker, identity or extended deadline.

## Pipeline, identity and replay

The adapter invokes the existing authenticated pipeline with the authenticator's
principal. Existing boundaries revalidate that principal; they do not introduce
a separate bearer implementation, fallback or capability selection. The pipeline
checks authority/key bindings and exact signed request bindings, commits durable
schema 6 replay consumption, asks the independently supplied resolver to authorize
identity, and reuses SessionChatService and the shared worker.

The HTTP adapter never constructs TrustedIP. There is no production resolver in
this phase. Offline tests inject a resolver that holds explicit synthetic fixture
identity and checks the authenticated assertion context. That fixture is not in
the release allowlist and cannot be selected through production configuration.
Hosting-specific ingress evidence remains a prerequisite for any real use.

Verified/unexpired/non-revoked sessions and all existing atomic session/IP/global
budgets, durable concurrency, emergency shutdown and provider-attempt guards
remain mandatory. Replay is consumed before these downstream checks; rejection,
provider failure, cancellation and lost responses do not refund it. Database
failure never recreates storage or migrates schema. No transaction spans providers.
No automatic retries or fallback to legacy `/chat` exist.

## One deadline and cleanup

A monotonic `ChatDiagnostics` starts at entry to the reserved-path adapter,
before authentication, upload or parsing. That same object is inherited by the
internal pipeline and SessionChatService supervisor/worker. No stage adds a fresh
provider budget. Inherited deadlines are checked against the configured maximum;
request headers/state cannot extend them. Response serialization is bounded and
checked before sending headers. Actual network delivery/backpressure is not a
promise that an already-sent response can be replaced with 504.

An HTTP slot bounds uploads and in-flight adapters; pipeline preprocessing and
provider workers retain their existing separate bounded leases. Cancellation and
504 do not kill a synchronous provider call or refund accounting. Actual workers
own capacity/reservation cleanup until they exit. Cancellation during execution
propagates into the existing supervisor; upload disconnects admit nothing. An
underlying operation may continue until its timeout/exit after a lost connection;
there is no exactly-once response-delivery guarantee.

## Responses and isolation

Success is JSON `{"answer":"..."}` with HTTP 200. Errors use a generic sanitized
`{"detail":"..."}` body with appropriate 400/401/403/404/405/408/413/415/422/429/
500/502/503/504 statuses. Responses use `Cache-Control: no-store`, never redirects,
cookies or CORS. Only bounded Retry-After and fixed Bearer challenge headers may
be forwarded; session/assertion/identity/credential metadata is not returned.
No submitted text, proof, credential, IP or provider exception is logged by the
adapter. The existing worker emits its sanitized structured diagnostics only.

Legacy `/chat`, health/readiness, other route policies and local admin commands
remain unchanged. Scoped chat credentials cannot authorize legacy `/chat`, and
legacy credentials cannot authorize this adapter. **Legacy `/chat` is not yet
claimed to be production-isolated**: its dedicated production exposure policy
still needs review before a public deployment.

The release-context allowlist includes the adapter and its existing authenticated
pipeline/assertion/replay imports so packaged API imports remain complete. No
image build, publication, index change or deployment is performed in this phase.

## Offline validation and remaining blockers

`tests/test_session_chat_http.py` uses actual FastAPI TestClient conventions,
raw ASGI streams for framing/upload/cancellation, temporary SQLite ledgers,
public test-only credentials/keys and mocked Gemini clients. It covers disabled
and invalid composition, authorization, malformed inputs, exact bytes, aliases,
replay/concurrency, storage, quota/emergency controls, inherited deadlines,
cleanup, logging and legacy isolation. Existing tests remain required.

Production ingress provenance/resolver approval, actual proxy/HTTP-server framing
validation, deployment task draining/storage/clock discipline, credential delivery
and legacy-route isolation remain blockers. No public activation procedure is
provided. Application limits supplement provider quotas; they are not exact
monetary spending caps.
