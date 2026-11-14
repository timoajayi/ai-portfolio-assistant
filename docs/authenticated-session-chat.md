# Authenticated internal session-chat orchestration

Status: local, internal composition only. **This phase does not prove production
visitor-IP provenance. This phase does not activate public chat.** No HTTP route,
frontend gateway, cookie, environment setting, migration or admin command is
added or changed. The production ingress resolver is deliberately not supplied.

## Existing interfaces and required adaptation

`authenticate(settings, scope, required=Capability.SESSION_CHAT, principal=...)`
produces or revalidates the existing request-bound `AuthenticatedPrincipal`.
It checks the fixed route/method policy, bearer, credential identity, request
marker, optional request ID and private seal. The internal route policy exists
but its HTTP route remains unregistered. No new credential scope is introduced.

`GatewayAssertionVerifier.verify(...)` checks the original compact assertion,
exact body bytes and canonical session-token text and returns a sealed
`VerifiedGatewayAssertion`. `GatewayReplayService(ledger, verifier).claim(result)`
requires the same verifier instance, checks freshness and commits a permanent
schema 6 replay claim. Neither component grants Gemini authority.

`SessionChatService.run(...)` reuses the private request supervisor, existing
shared `_chat_worker` and `admitted_identity` -> `admitted_session` -> atomic
SQLite session/IP/global admission. It does not dispatch the application router
or call the legacy `/chat` handler. Previously it always created a fresh request
budget; it now accepts an optional internal `diagnostics` argument so a caller
can inherit an earlier absolute deadline. Existing callers without it retain
their existing behavior. No RAG/provider implementation is duplicated.

## Composition and authority binding

`AuthenticatedSessionChatService(chat, replay, authority=...,
identity_resolver=...)` accepts the existing concrete services. Its immutable
`GatewayAuthority` is trusted server configuration containing:

- The configured session-chat credential identity.
- Exact gateway issuer and backend audience.
- The bounded set of configured signing key IDs.
- The approved ingress-policy identifier.
- The fixed `Capability.SESSION_CHAT` capability, which callers cannot select.

Construction rejects mismatched verifier policy/key IDs, credential identities,
resolver policy or ledger path. Replay and paid admission must use the same
persistent database. Settings must be validated by normal trusted composition;
paths must be resolved as normal `Settings.from_env` already does. Do not build
an authority mapping from request headers or token claims. An unrelated gateway
bearer and valid assertion cannot be combined merely because each is valid.
Credential/key rotation requires reviewed, coordinated reconstruction of this
mapping and the verifier/replay pair. No new environment variables are introduced.

Reuse one pipeline instance per application instance so its bounded preprocessing
admission is shared. It is never constructed by an HTTP handler in this phase.
All existing authentication/session/IP feature gates must be explicitly enabled
in isolated tests for a request to execute. Defaults and actual configuration
remain unchanged; no compatibility fallback to legacy credentials exists here.

## Internal request contract and ordering

`await pipeline.run(gateway_scope, body_bytes, compact_assertion,
principal=optional_pre_authenticated_principal)` accepts internal inputs, not
browser authorization. The optional principal must pass the existing authentication
implementation again for this request. Caller-selected capabilities, forged or
modified principals, wrong credentials, aliases, encoded paths and queries fail.
No parameter accepts a visitor address, identity digest, resolver or TrustedIP.

1. Start one monotonic deadline at pipeline entry; acquire bounded non-waiting
   preprocessing capacity. A full pipeline returns sanitized 503.
2. Snapshot bounded immutable wire inputs and authenticate the gateway for exact
   `POST /internal/session-chat` and `SESSION_CHAT`. Discard caller-supplied state
   such as diagnostics, leases and authenticated-principal values. Only an
   explicitly supplied principal's original authentication marker/request ID is
   retained for revalidation.
3. Require no Origin header, exact `application/json`, supported identity content
   encoding and exactly one canonical session-token header (`x-portfolio-session`).
   The existing verifier validates token canonicality. Headers are bounded to 32
   entries/8,192 bytes; body bytes are bounded by the existing configured limit
   and the assertion protocol's 8,192-byte maximum.
4. Verify the compact assertion against those exact immutable body bytes and
   session-token text, the actual method/path and trusted policy. No body parsing
   or reserialization occurs before digest verification. Check the explicit
   credential/issuer/audience/key/capability/ingress mapping.
5. Commit the durable replay claim. Missing, corrupt, mismatched or locked
   storage fails closed. No transaction remains open during identity resolution
   or execution. A valid assertion consumed before a later failure stays consumed.
6. Create an internal sealed `AuthenticatedRequestContext` and ask the injected
   resolver to independently authorize the visitor identity.
7. Hand the preserved scope, authenticated principal, resolved identity, exact
   body bytes and original deadline to `SessionChatService`. Its strict JSON and
   message validation, aggregate/process rate controls and provider capacity remain.
8. The existing worker atomically enforces verified session validity, session/IP
   rolling windows, global day/month budgets, durable concurrency and emergency
   shutdown, then executes existing RAG/Gemini with provider-attempt accounting.
9. Return the existing successful `{"answer":"..."}` response or sanitized
   no-store error. There is no legacy dispatch, fallback, retry or replay refund.

The method receives already-buffered bytes. This phase does not provide an HTTP
upload reader or assertion-header parser. Future routing must enforce bounded
upload time/body reading and duplicate assertion-header rejection, and inherit
an ingress deadline if work begins before this method is called. HTTP integration
is a separate review; do not register this service as a route without it.

## Resolver trust boundary

`TrustedIdentityResolver` is an abstract server-side extension. There is no
default resolver and no forwarding-header implementation. A plain callable,
arbitrary object, wrong-policy resolver or subclass overriding `resolve` is
rejected at composition. Per-request code cannot substitute a resolver.

Its `_authorize(context)` implementation must return **exactly True only after
independent trusted ingress evidence confirms the assertion's canonical IP and
policy for that authenticated request**. It receives a sealed context with the
principal, fixed authority, verified assertion and deadline; no raw bearer,
session token, request body or headers are exposed. A policy name alone is not
evidence. A signature alone is not evidence. Forwarding headers supplied by a
browser are not evidence.

The base resolver checks policy/context before invoking this authorization hook,
then checks the original deadline again. Only after authorization does it mint
`TrustedIP` and a private resolution bound to this exact resolver/context. The
pipeline checks that binding, exact type and canonical packed IP/version before
execution. Returning an arbitrary IP string, truthy flag, preconstructed or forged
TrustedIP instead of authorization is rejected. No browser verification flag,
cookie, supplied digest or forwarded IP acts as an identity source.

The offline fixture resolver holds an independently supplied synthetic address
and checks it against the authenticated context. **It is a test fixture, not a
production ingress implementation.** Hosting-specific evidence, authenticated
transport and request correlation must be designed and verified separately.
Without a trusted resolver, construction/execution fails closed. Python is not a
sandbox: server composition, the resolver implementation and code capable of
private-state reflection or module mutation are in the trusted computing base.

## Deadline, cancellation and capacity

One `ChatDiagnostics` starts before authentication/worker-pool admission.
Verification, SQLite lock/validation/commit time, identity resolution, session
admission, RAG and response preparation all consume the same deadline. The
existing supervisor receives that exact object; it never adds a fresh full
budget. Internal inherited diagnostics must be finite, already started, no longer
than configured, and supplied with a valid scoped principal. Request headers/state
cannot supply or extend this budget.

Potentially blocking preprocessing runs in the existing AnyIO worker pool under
a separate bounded non-blocking admission lease. Deadline expiry returns sanitized
504 without waiting for a blocked sync verifier, SQLite call or resolver. Its
lease remains held until the actual preprocessing worker exits. Cancellation or
timeout sets stopped diagnostics; late preprocessing cannot proceed to admission
or providers. There is no unbounded queue or background-worker creation.

The existing provider supervisor/capacity lease and worker-owned durable cleanup
remain responsible for provider workers. Timeouts do not kill an already-running
synchronous operation. Capacity and active reservations stay held until that
worker's actual exit; paid accounting and consumed assertions are not refunded.
Late work cannot emit a successful response after deadline/cancellation. Existing
transport timeouts, generation limits and SDK retry settings are unchanged.

The service is not wired into application startup/shutdown. Future composition
must also drain supervised tasks/actual worker leases on shutdown; a task ending
alone does not prove an abandoned synchronous worker has exited.

## Offline evidence and remaining work

`tests/test_authenticated_session_chat.py` uses temporary schema 6 databases,
public test-only keys/credentials, the existing mocked Gemini fixture, actual
shared chat execution and existing admission controls. It exercises successful
execution, principal/authority/key binding, signatures/body/session/path errors,
replay races, storage failures, resolver decisions and forged identities, quotas,
emergency shutdown, cancellations and inherited deadlines. Existing authentication,
assertion/replay, session/IP, bot issuance, RAG and lifecycle suites still run.
Independent probes additionally exercise fresh-process pipeline replay and a
cross-process final assertion race with mocked execution.

Persistent storage durability, trustworthy host time, backups, key separation,
SQLite growth and recovery risks remain as documented for schema 6. No operational
DB is opened by this phase. Missing/invalid identity evidence remains a deployment
blocker. The original phase deferred HTTP routing and browser integration; the
HTTP adapter and loopback runner now provide a locally verified session/RAG/Gemini
flow. Production IP provenance and deployment remain unverified. See
[local development](local-development.md) for the current working configuration.

## Phase 6B-4G-1E update

A separate disabled HTTP adapter now implements the previously deferred transport
and upload/deadline handoff. See [HTTP contract](session-chat-http.md). It registers
no FastAPI route and requires explicit server composition; production resolver
and ingress trust remain unimplemented. `run` now accepts internal inherited
diagnostics, checked against the configured maximum, so upload never grants a
fresh execution budget. The authentication/replay/admission sequence above remains
unchanged. No public activation or schema migration is introduced.
