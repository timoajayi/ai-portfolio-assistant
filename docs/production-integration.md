# Render composition for the Vercel gateway

Implemented and offline tested; not deployed or production verified. No activation
flags, real environment files, schemas, index or model configuration were changed.

## Initialization

The existing FastAPI lifespan composes session chat only when the existing HTTP
feature is enabled and no trusted pipeline was already supplied. Disabled startup
never composes it. Existing explicit loopback development composition is retained.
Missing/invalid production configuration fails startup with a sanitized error.

`src/production_chat.py` requires Render's server-side runtime marker, production
policy, disabled legacy execution, existing scoped authentication and session/IP
gates. It pins issuer, audience, key ID, active validity window, chat credential ID
and the fixed `vercel-direct-v1` ingress policy. It reuses SessionChatService,
GatewayAssertionVerifier, GatewayReplayService, AuthenticatedSessionChatService and
UsageLedger. Existing storage is validated; it is not created, migrated, repaired
or enabled. Emergency disable remains enforced by admission, not bypassed at startup.

The resolver is an explicit delegation to the approved Vercel deployment, after
scoped authentication, signed body/session/IP/policy validation and durable replay
consumption. A signature alone grants no identity authority. Render's proxy/socket
address is not the visitor. Compromise of the approved gateway or its credentials
requires revocation/rotation and is outside what forwarded headers can solve.

Render documents adding `x-forwarded-for` ([Render edge behavior](https://render.com/articles/how-render-handles-ddos-attacks)).
Only when this production resolver is composed, that field is discarded after
original header bounds/validation. It never changes the assertion or per-IP digest.
Other forbidden identity headers remain rejected. A spoofed transport address
cannot repair invalid credentials/signatures or bypass session/rate/budget controls.
Actual Render headers must still be checked before public activation.

## Environment variable names

Render supplies `RENDER` ([runtime variables](https://render.com/docs/environment-variables)).
Composition reads these operator-controlled names, matching the frontend:

- `GATEWAY_ASSERTION_ISSUER`, `GATEWAY_ASSERTION_AUDIENCE`, `GATEWAY_ASSERTION_KEY_ID`
- `GATEWAY_ASSERTION_KEY`, `GATEWAY_ASSERTION_KEY_NOT_BEFORE`, `GATEWAY_ASSERTION_KEY_NOT_AFTER`
- `GATEWAY_INGRESS_POLICY`

The key is canonical unpadded base64url for independent 32–64 random bytes. Validity
bounds are canonical integer Unix seconds; the active key must be valid at startup.
The fixed ingress policy authorizes only directly hosted Vercel production ingress.
Existing settings remain required; their enablement defaults are unchanged:

- `BACKEND_DEPLOYMENT_POLICY`, `LEGACY_CHAT_ENABLED`
- `STAGING_AUTH_ENABLED`, `STAGING_AUTH_TOKEN`, `CAPABILITY_AUTH_ENABLED`
- `VERIFIED_SESSION_AUTH_TOKEN`, `SESSION_CHAT_AUTH_TOKEN`
- `VERIFIED_SESSION_CREDENTIAL_ID`, `SESSION_CHAT_CREDENTIAL_ID`
- `SESSION_CHAT_ENABLED`, `SESSION_CHAT_HTTP_ENABLED`, `SESSION_ADMISSION_ENABLED`
- `IP_ADMISSION_ENABLED`, `IP_RATE_HMAC_KEY`, `IP_ADMISSION_MINUTE_LIMIT`, `IP_ADMISSION_DAY_LIMIT`
- `SESSION_ADMISSION_MINUTE_LIMIT`, `SESSION_ADMISSION_HOUR_LIMIT`
- `SESSION_ISSUANCE_ENABLED`, `SESSION_LIFETIME_SECONDS`, `SESSION_ISSUANCE_MINUTE_LIMIT`, `SESSION_ISSUANCE_DAY_LIMIT`, `SESSION_MAX_LIVE`
- `BOT_VERIFICATION_ENABLED`, `BOT_PROVIDER_SECRET`, `BOT_ALLOWED_HOSTNAMES`, `BOT_EXPECTED_ACTION`
- `USAGE_LEDGER_PATH`, `USAGE_DAILY_LIMIT`, `USAGE_MONTHLY_LIMIT`, `USAGE_MAX_CONCURRENT`, `USAGE_SQLITE_BUSY_MS`
- `CHAT_DEADLINE_SECONDS`, `CHAT_MAX_CONCURRENT`, `STAGING_BUDGET_REQUESTS`, `STAGING_BUDGET_WINDOW_SECONDS`
- `GOOGLE_API_KEY` (backend only; existing model/index settings stay unchanged)

Keep bearer roles, assertion key and IP HMAC key independent. Frontend chat bearer
maps only to session chat; issuance bearer maps only to verified-session issuance.
Legacy bearer has no production execution route. No values or activation commands
are supplied here. Keep public features disabled pending separate authorization.

## Remaining deployment verification

Confirm approved Vercel ingress overwrite guarantees and direct hosting; HTTPS,
canonical browser origin, Render transport/header shape and request limits; matching
secrets, authority/key windows and synchronized clocks; real Turnstile compatibility;
existing persistent SQLite schema and operational kill switches/quotas. Do not enable
multiple isolated SQLite ledgers for one deployment-wide budget. No operational DB
was accessed, no migration run, and no production image built. Release allowlists
include the new composition module; the local-only launcher stays excluded.

Offline tests use synthetic credentials, mocked verification/Gemini and disposable
SQLite. Production composition tests cover startup, config failure, replay, invalid
assertions/session/scope, limits and ignoring conflicting Render forwarding metadata.
The existing local HTTPS regression suite remains required and unchanged.
