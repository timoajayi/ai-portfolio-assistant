# Isolated gateway assertion protocol v1

Status: offline utility only. Neither implementation is imported by HTTP routes.
The cryptographic utility changes no feature, credential, session issuance, chat,
IP admission, cookie or provider behavior. Separate replay storage is described below. This document is a protocol contract, not public
activation instructions.

## Wire format and verification

`base64url(header).base64url(payload).base64url(signature)` uses unpadded RFC 4648
URL-safe encoding with canonical unused bits. Only ASCII compact input is valid.
HMAC-SHA256 signs the **original encoded header, one dot, and encoded payload**.
The MAC is exactly 32 bytes and is checked using Python `hmac.compare_digest`.
Decoded JSON is never reserialized to reconstruct the signed bytes. JSON key
order and insignificant whitespace are not a canonicalization requirement.
Duplicate JSON keys (including escaped equivalents), unknown fields, nulls,
coercions, floats, exponent numbers and nonfinite numbers are rejected.

Exact protected header: `{"typ":"portfolio-gateway-assertion-v1","alg":"HS256","kid":"gateway-key-1"}`.
These are the only fields. There is no algorithm negotiation, unsigned mode,
embedded key, remote key discovery or critical-extension support. `kid` matches
`[a-z0-9][a-z0-9_-]{0,31}` exactly.

Exact payload field set:

| Field | Contract |
| --- | --- |
| `v` | Integer `1`, never boolean |
| `iss` | Configured gateway issuer |
| `aud` | Configured backend audience |
| `scope` | Literal `session:chat` |
| `method` | Literal `POST` |
| `path` | Literal `/internal/session-chat`, no slash alias or query |
| `iat` | Integer Unix UTC seconds |
| `exp` | Integer Unix UTC seconds |
| `jti` | Canonical base64url of 32 CSPRNG bytes |
| `session_sha256` | Lowercase 64-character hexadecimal SHA-256 |
| `body_sha256` | Lowercase 64-character hexadecimal SHA-256 |
| `visitor_ip` | Canonical IP literal |
| `ip_source` | Configured ingress-policy identifier |

Issuer, audience and ingress-policy identifiers match
`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}` exactly. No trimming, case folding or Unicode
normalization applies to identifiers. No optional fields exist.

Limits: 2,048 compact ASCII bytes, 256 decoded header bytes, 1,024 decoded payload
bytes, 8,192 request-body bytes, session token exactly 43 canonical base64url
characters encoding 32 bytes. Hash **the exact ASCII session-token text**, not
its decoded secret bytes. Hash **the exact transmitted body bytes**, not parsed
or reserialized JSON. Future callers must retain and transmit the very buffer
used for signing. Trailing newlines and UTF-8 encoding matter.

IPv4 is dotted decimal without leading zeros. IPv6 uses lowercase compressed
RFC 5952-style literals; IPv4-mapped IPv6 is normalized to dotted IPv4 before
signing. Zones, ports, brackets, CIDRs, forwarding lists and DNS names are
rejected. The verifier rejects a noncanonical wire literal. Parsing an address
does not establish its provenance. No `TrustedIP` object is constructed.

## Roles, clocks and keys

Python `GatewayAssertionVerifier` accepts injected issuer, audience, ingress
policy and `VerificationKey` objects, with one current key and optionally one
previous verification-only key (maximum two). Node `GatewayAssertionSigner`
accepts one `currentKey` and a fixed policy; there is no previous-key signing
selection or per-request algorithm, key, issuer, scope, timestamp or nonce field.
No module reads environment files, environment variables or an operational DB.
No real signing keys or runtime activation settings are introduced here.

Keys are independent 32–64-byte cryptographically random secrets. Length is a
minimum configuration check, not proof of entropy. Never reuse a staging bearer,
issuance bearer, chat bearer, `IP_RATE_HMAC_KEY` or Gemini key. Key IDs are public
identifiers, not secrets. HMAC requires the verifier to possess the signing
secret: compromise of either trusted server can enable forgery. This is not an
asymmetric signature protocol. Python key representations and Node private
fields omit secret values; neither module emits logs. Callers must also avoid
logging configuration objects, compact assertions, raw sessions and IPs.

Each key has explicit integer `not_before`/`not_after` (Python) or
`notBefore`/`notAfter` (Node) UTC validity bounds. A verified assertion must have
its entire issuance/expiry interval inside its key window; the verification time
must also be inside it. Different keys must have distinct IDs and secret bytes.
Remove a previous verification key to revoke it. Rotation requires coordinated
server-only provisioning: provision the next verifier key, switch the signer,
retain the previous verifier key only for a short explicit overlap, then remove
it. The Node signer snapshots key bytes and exposes `destroy()` to clear its
private copy and prevent subsequent signing. It cannot erase callers' copies or
guarantee garbage-collector/OS-level secret erasure.

Unix timestamps are integers in `[0, 253402300799]` (through year 9999). Require
`0 < exp - iat <= 30`, `iat <= now + 5`, and `now < exp`. There is **no expiry
skew allowance**. Production signer clock defaults to integer wall-clock seconds;
verifier does too. Synchronize server clocks. Tests inject fixed clocks and
nonces only. Production nonces use Node `randomBytes(32)`. Both modules reject
degenerate nonces made of one repeated byte. Format validation still cannot
prove that a caller used randomness.

## Explicit limitations and future integration

A valid assertion authenticates the gateway's statement. It does **not** prove
that its visitor IP came from a trustworthy hosting ingress. `ip_source` binds
the configured policy name only. A separately reviewed ingress must establish
IP provenance, normalize headers and strip browser-supplied identity claims.
Neither recognizable forwarding-header names nor existing bearer auth is
sufficient evidence. No new HTTP route, authorization grant or TrustedIP
conversion is included.

The sealed, frozen Python result always marks `replay_protection_required=True` and
`ingress_trust_verified=False`. Repeated valid assertions, including the same
nonce, verify cryptographically. The cryptographic verifier alone performs no replay
detection. The separate
`GatewayReplayService` now implements durable atomic nonce consumption in ledger
schema 6; see [replay and migration contract](gateway-replay-v6.md). It accepts
only intact results from its pinned verifier instance, rechecks validity and
consumes a domain-separated issuer/audience/key/nonce digest. No HTTP integration
exists yet; future request handling must invoke this boundary before admission.
A MAC-valid result alone must never reach Gemini. Unknown keys, invalid config, encodings,
bindings, clocks or payloads fail with a generic exception; no retry/fallback is
performed. Existing scoped authentication remains a separate prerequisite.

## Offline evidence

Identical `tests/fixtures/gateway_assertions_v1.json` files in both repositories
contain public test-only keys, clocks, nonces, exact body bytes (base64), canonical
session text and Node-generated assertions. They must never be used as keys in
any deployment. Four vectors cover IPv4, IPv6, mapped addresses and UTF-8 bodies.
Python independently calculates HMACs and verifies the original compact vectors;
Node signing reproduces them byte for byte. Negative cases cover strict JSON,
encodings, signatures, keys, clocks, IP syntax, identifiers and request binding.

Backend: `.venv/bin/python -B -m unittest tests.test_gateway_assertions -v`.
Frontend: `node --test tests/gateway-assertions.test.mjs` (uses the existing local
TypeScript compiler in memory). Full suites remain offline. No package changes,
provider access or actual credentials are needed. Future route integration,
assertion transport/header normalization, hosting validation, monitoring and deployment remain separate phases.
