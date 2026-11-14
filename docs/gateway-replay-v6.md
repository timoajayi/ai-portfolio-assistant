# Durable gateway assertion replay claims (schema 6)

This is an internal, offline implementation. No HTTP route imports the replay
service; no feature flag or production setting is changed. No TrustedIP object
is created. A successful replay claim alone grants no authentication, session,
IP admission, global budget or Gemini authority.

## Trust boundary and use

Construct a `GatewayAssertionVerifier` with trusted server-side policy and keys,
then construct `GatewayReplayService(ledger, verifier)` with that **same verifier
instance**. First call `verifier.verify(...)` with the original compact assertion,
exact body bytes and canonical session-token text. Only pass its returned
`VerifiedGatewayAssertion` to `service.claim(result)`.

The frozen, slotted result has no field constructor. It carries a private
process-local seal, a verifier-instance context and an integrity MAC covering all
claims, flags and key-validity bounds. Replay admission checks exact runtime
types, context, field invariants and the MAC. Constructed objects, modified
copies, results from other verifiers (even the same configuration), raw headers,
raw payloads and caller-selected identities cannot substitute for this boundary.
Logical result equality is not authorization or evidence of provenance.

The ephemeral result MAC is separate from gateway signing keys and is never
persisted. Reverify the original wire assertion in each worker after restart;
never serialize verifier results for cross-process use. Python is not a sandbox:
code able to inspect private module secrets, monkeypatch these checks or write
arbitrary SQL is within the trusted computing base. The service's verifier and
ledger must be constructed by trusted application composition, not visitors.
A compromised gateway signing key can still forge assertions; replay protection
is not a substitute for scoped bearer authentication or trusted ingress.

`claim` returns normally only after a committed first claim. All denials raise
sanitized `UsageDenied`; no identifiers or submitted values appear in its message.
Storage errors use existing generic storage failures. There is no retry,
release/refund, fallback or execution callback. The service calls no provider.
Paid emergency disable also rejects claims, without clearing consumed claims.

## Replay identifier

Compute the following, with ASCII JSON, no whitespace and the exact listed order:

```text
scope = JSON(["portfolio-gateway-assertion-v1", issuer, audience, kid, jti])
replay_digest = SHA256(b"portfolio-gateway-replay-id-v1\0" + scope)
```

JSON list encoding avoids delimiter ambiguity. The digest is stable across
processes and restarts; process-local verifier seals are **not** part of it.
Issuer/audience/key namespaces are distinct. A new signature, different body,
address, expiration or JSON formatting with the same issuer/audience/kid/nonce
cannot bypass the consumed digest. Hashing the whole assertion instead would
allow such bypasses, so it is deliberately not the identifier.

A different key ID is a different namespace, as required by this protocol.
Rotation must use fresh random nonces and correctly scoped key windows; do not
re-sign old requests under a new key ID as a retry. Changing only the secret
while retaining the same key ID does not reset nonce consumption. Policy changes
or signing-key compromise are not solved by replay storage. SHA-256 collision
resistance is an underlying cryptographic assumption.

## Schema and transaction

Actual prior schema is version 5. Version 6 adds:

- `gateway_replay_claims`: `replay_digest` BLOB primary key (32 bytes), integer
  `expires_at`, integer `claimed_at`, and exact protocol string. UTC timestamps
  have explicit ranges and CHECK constraints. Require
  `claimed_at < expires_at <= claimed_at + 35`, covering the 30-second maximum
  lifetime plus five seconds of permitted future issue skew.
- `gateway_replay_control`: one constrained row, `id=1`, with integer `high_water`.
  Migration sets it to the operator host's current UTC seconds. It must never be
  below any stored claim time.

There are no foreign keys to sessions, credentials or active reservations. The
primary-key autoindex enforces uniqueness; no expiry index is needed because no
claim deletion is implemented. Strict DDL-token, column/index metadata, physical
integrity and persisted-state validation extend existing versions without
weakening their constraints.

A short existing `BEGIN IMMEDIATE` transaction validates version 6 and all
accounting, checks paid shutdown, rechecks verifier provenance/expiry after lock
acquisition, rejects time below the durable floor, and inserts the digest with
`ON CONFLICT(replay_digest) DO NOTHING`. Exactly one insertion can succeed.
The clock watermark advances in the same transaction. Expiry/clock are checked
again before commit. No SQLite transaction spans downstream or network work.

After commit there is one more expiry/clock check: if commit waiting/fsync spent
the remaining lifetime, execution is denied **without removing the claim**.
Errors before commit roll back; an uncertain commit never authorizes execution.
A subsequent caller must try a fresh assertion, not automatically retry a claim.
Committed claims survive failed execution, cancellation, crashes and lost
responses. This provides at-most-once admission, not exactly-once execution or
response delivery. Existing usage counters are not changed by a replay claim.

## Explicit operator migration

No normal startup, request or constructor initializes or migrates storage.
Initialization intentionally remains disabled version 1. Old supported ledger
versions continue to work for their existing operations; replay requires version
6. Missing/corrupt/mismatched storage fails closed without recreation or repair.

For a reviewed version 5 persistent database:

1. Durably disable paid usage using the existing local operator command.
2. Stop **all** backend workers and independently confirm they are stopped.
3. Take and validate a private consistent SQLite backup using the existing
   backup procedure. Include journals/WAL correctly; do not copy a live DB file.
4. Check that operator/server UTC time is trustworthy, then run locally:

```sh
python -B -m src.usage_admin --database /var/lib/ai-portfolio-assistant/usage.sqlite3 migrate-v6 --confirm-workers-stopped
```

The confirmation flag is an operator assertion, **not proof** workers stopped.
Migration validates complete version 5 and its accounting, requires paid shutdown,
adds only the new tables/clock row and version marker in one transaction, then
validates complete version 6 before commit. Any failure rolls back schema,
version and data. Repeating the command on version 6 refuses without mutation.
It requires no provider credentials and does not read `.env`. It preserves all
sessions, issuance audit, IP accounting, bot-proof states, daily/monthly counters,
provider attempts, active reservations and both emergency controls. It never
enables paid usage or clears abandoned reservations. There is no HTTP migration
or down-migration endpoint.

Do not restore an older backup to regain budgets or replay allowances. Disaster
recovery must preserve the latest claims/accounting or invalidate affected keys
and assertions under a separately reviewed recovery plan before resuming. Do not
silently point runtime at a fresh or disposable ledger.

## Retention, clocks and resource limits

Claims are permanent consume-once tombstones. **No destructive replay cleanup is
implemented or authorized by this phase.** Expiration is not permission to delete:
a newly signed assertion can reuse the same nonce, and wall clocks can roll back.
Deleting a digest would undermine the stated scope-wide at-most-once guarantee.
Session cleanup and existing worker/bot recovery never delete these claims.
Any future compaction must retain uniqueness tombstones and the clock floor;
pruning identifiers needs a new reviewed protocol/key-epoch retirement design.

The durable floor rejects observed UTC rollback below the migration or last
successful claim watermark, including across restarts. Checks also detect
rollback during the operation. There is no expiry grace. These checks cannot
prove real UTC correctness or detect every clock change between observations.
A trusted, synchronized host clock and clock-health monitoring remain deployment
requirements. If clock health is uncertain, operators must disable paid usage;
there is no unsafe clock-floor reset command. A forward clock error can cause
fail-closed unavailability until trusted time catches up. No local-only scheme
can attest external time without another trusted source.

History growth is intentional. Existing SQLite lock waiting is bounded (default
250 ms, maximum 2 seconds), synchronous durability is FULL, and the existing
transaction SQL-step budget bounds validation work. Exhaustion denies work;
it never skips validation or discards history. Monitor private storage size,
validation latency, free disk, backups and lock failures before eventual use.
An archive/compaction design preserving tombstones is future work, not an
unreviewed deletion job. SQLite is suitable for one persistent backend instance
or coordinated processes on its local disk, not independent replicas with
separate ephemeral disks or unverified network-filesystem locking.

## Required future HTTP ordering (not implemented)

1. Authenticate the correctly scoped gateway credential.
2. Verify signature and exact method/path/session/body bindings.
3. Verify the assertion's clock/key validity.
4. Commit the replay claim.
5. Construct the authenticated request context only after separately establishing
   the hosting ingress identity trust boundary.
6. Enforce existing atomic session/IP/global budgets, durable concurrency and
   emergency shutdown.
7. Execute existing RAG/Gemini with provider-attempt guards and deadlines.
8. Return a sanitized no-store response; never refund a used assertion on error.

There is no legacy `/chat` fallback. Assertion authenticity does not establish
visitor-IP provenance. HTTP integration and trusted identity transport remain
blocked pending separate review. Public chat remains disabled.

## Offline verification

`tests/test_gateway_replay.py` uses temporary SQLite files, injected clocks,
public test-only keys and mocked providers. It covers independent connections,
thread/process races, fresh-process migration/restarts, sealed-result forgery,
resigning, exact clock boundaries, missing/corrupt/locked/read-only storage,
migration/claim rollback, post-commit expiration, permanent consumption after
failure/cancellation/lost responses, preserved accounting, privacy and strict
schema/state rejection. Existing assertion vectors and security tests also run.
No operational database or external service is needed.
