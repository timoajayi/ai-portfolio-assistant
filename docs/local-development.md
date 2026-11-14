# Isolated secure local development

The local flow has been verified in a controlled live test: Cloudflare verification
completed, a verified session was issued (HTTP201), and the assistant answered a
question about BundesHost using the existing RAG/Gemini pipeline. This verification
was reported by the operator on 2026-11-14; it is separate from the mocked offline
regression suite. It does not verify production deployment or production visitor-IP
provenance. Public chat and normal production feature defaults remain disabled.
Further live-provider requests still require explicit authorization.

## Composition

```
Browser https://localhost:3443
  -> real bot widget (only after authorization)
  -> existing session gateway and Secure HttpOnly cookie
  -> existing signed/scoped chat gateway
  -> http://127.0.0.1:8001/internal/session-chat
  -> existing replay/session/IP/global/concurrency admission
  -> existing RAG/Gemini worker
```

`scripts/local_frontend.mjs` is a separate Node HTTPS development launcher. It
compiles the four existing frontend server modules in memory using the installed
TypeScript compiler, then invokes their existing factories. It does not change
Next.js production routes or install packages. UI/assets stream from a separately
started Next dev process on `127.0.0.1:3000`. API requests are handled on the HTTPS
launcher, never forwarded to legacy `/chat`. Unknown API paths are denied.

The launcher binds only `127.0.0.1:3443`, accepts only Host `localhost:3443`, derives
identity from the actual accepted socket, and rejects non-loopback peers. All local
visitors deliberately share canonical identity `127.0.0.1` and its durable quota.
This is local operator access, **not production visitor provenance**. Do not put a
proxy, tunnel, port forward or public listener in front of it. The ordinary Next
route still has no production identity provider; no environment variable selects
this provider. The launcher refuses production NODE_ENV and known cloud markers.

`python -m src.local_development` is a separate backend entry point. It composes
the existing authenticated service with fixed local issuer/audience/policy and a
resolver that authorizes only that local delegation. The outer backend app also
requires an actual loopback peer. Uvicorn binds `127.0.0.1:8001`, one worker, no
proxy-header trust, no reload/access log. Other existing backend services are not touched.
The module is absent from the Docker release allowlist.

Both runners use only a newly generated private local profile, outside Git
repositories. Raw keys are never printed. The backend masks dotenv loading before
importing existing API modules; secrets come only from the invoking process.
Normal production entry points, frontend sources, `.codex`, and ProjectCard are
unchanged. No existing configuration or credential files are read by the runners.
The runner must of course read its own newly created profile/TLS private key.

## One-time preparation (no provider requests)

Use the existing Python environment, installed Node dependencies and OpenSSL.
Choose a **new** persistent state directory, outside both repositories. Init refuses
existing directories; failure leaves the partial directory for operator inspection,
never deletes/recreates storage. Do not repeat init to regain allowances.

```sh
cd /Users/timothyajayi/PycharmProjects/PythonProject/ai-portfolio-assistant
portfolio_dev_state="$HOME/.local/state/portfolio-assistant-development"
.venv/bin/python -B -m src.local_development init --state "$portfolio_dev_state"
```

This explicitly creates a dedicated schema6 ledger through existing migrations,
with both paid usage and issuance disabled; no operational ledger is accessed.
Profile/ledger mode is0600 and directory mode0700. Distinct development-only keys
are generated for staging, issuance, chat, assertions and IP HMAC. They are not
production credentials. Preserve this directory across restarts; never copy it
into an image/repository. Coordinate any later key rotation; changing the IP key
without its existing maintenance procedure fails closed. Protect backups and do
not restore older accounting to recover allowances.

Create a short-lived localhost-only self-signed certificate:

```sh
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -keyout "$portfolio_dev_state/localhost.key" \
  -out "$portfolio_dev_state/localhost.crt" \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'extendedKeyUsage=serverAuth'
openssl verify -trusted "$portfolio_dev_state/localhost.crt" \
  -verify_hostname localhost "$portfolio_dev_state/localhost.crt"
```

Inspect the certificate before explicitly trusting **only this development
certificate** in your browser/user trust store. On macOS, import its public `.crt`
into the login Keychain and review its SSL trust setting. Never import/share the
private key. Remove the trust entry when finished. No trust-store operation was
performed automatically. Renew the certificate before it expires. Never use
`NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k`, insecure cookies, or disabled TLS checks.

## Private configuration supplied by the operator

No `.env` files are created/edited. Supply these in the relevant terminal's process
environment using a private secret manager or an interactive shell prompt; do not
paste values into commands committed to Git or share terminal dumps:

| Variable | Terminal | Requirement |
| --- | --- | --- |
| `GOOGLE_API_KEY` | Backend | Dedicated development Gemini credential |
| `BOT_PROVIDER_SECRET` | Backend | Real development Turnstile secret matching the site key |
| `NEXT_PUBLIC_TURNSTILE_SITE_KEY` | Next dev | Public development site key, with localhost approved and action `portfolio_session` |
| `RAG_INDEX_PATH` | Backend, optional | Existing validated index; default existing repository artifact |
| Existing budget/deadline settings | Backend, optional | Keep conservative defaults or stricter existing values |

Bot verification is real for browser issuance: no test-key auto-pass, fake verified
flag or verification shortcut is installed. Cloudflare localhost acceptance/key
configuration and real Gemini service access remain to be authorized and tested.
Do not use production provider keys. The new profile supplies scoped backend keys
internally; the browser never receives them. Existing ceilings/deadlines are not
increased. Missing provider settings or invalid storage fail closed.

The backend expects `GOOGLE_API_KEY` in its launch-process environment. The local
runner suppresses dotenv loading; updating frontend `.env.local` or a backend
`.env` does not change the running backend credential. Restart only with operator
authorization after privately updating the launch environment. The embedding
client explicitly uses the Gemini Developer API at its standard endpoint with
API version `v1beta`, model `gemini-embedding-001` and 3072 dimensions. Siteverify
requests identity encoding. Verification and embedding failure diagnostics use
sanitized categories/allowlisted fields, never secret or provider-message logging.

## Startup commands — only after explicit live-provider authorization

These commands do not themselves submit a chat. Opening the widget contacts
Cloudflare; submitting a verified message can invoke Gemini. They are documented
for later authorized use, not executed as part of offline verification.

Terminal1, after privately exporting `GOOGLE_API_KEY` and `BOT_PROVIDER_SECRET`:

```sh
cd /Users/timothyajayi/PycharmProjects/PythonProject/ai-portfolio-assistant
portfolio_dev_state="$HOME/.local/state/portfolio-assistant-development"
.venv/bin/python -B -m src.local_development enable --state "$portfolio_dev_state" --allow-live-providers
.venv/bin/python -B -m src.local_development serve --state "$portfolio_dev_state" --allow-live-providers
```

The explicit enable command changes only this development ledger's two emergency
switches. Serve never enables, migrates, resets counters or clears reservations.
The `--allow-live-providers` flag records operator intent, not proof of external
approval. Do not use it until authorization exists.

Terminal2, after exporting the public `NEXT_PUBLIC_TURNSTILE_SITE_KEY`:

```sh
cd /Users/timothyajayi/PycharmProjects/ai-engineer-portfolio
npm run dev -- --hostname 127.0.0.1 --port 3000
```

If port3000 already has this frontend, do not start another server. A separately
approved restart is needed to pick up a newly supplied public site key. Do not
stop unrelated servers. Next's own development process retains its normal
configuration loading; the integration scripts neither inspect nor edit its files.

Terminal3:

```sh
cd /Users/timothyajayi/PycharmProjects/PythonProject/ai-portfolio-assistant
NODE_ENV=development node scripts/local_frontend.mjs \
  /Users/timothyajayi/PycharmProjects/ai-engineer-portfolio \
  "$HOME/.local/state/portfolio-assistant-development"
```

Use **https://localhost:3443**, not the underlying HTTP Next port. Secure,
HttpOnly, SameSite=Strict, host-only Path=/ session cookies are set by the existing
session gateway. Chat and issuance opt-ins exist only inside this explicit runner;
normal production `CHAT_ENABLED`/`CHAT_SESSION_ENABLED` and backend defaults remain
off. Backend deployment policy remains production with legacy execution disabled.
Never deploy this launcher or reuse the local delegation policy in production.

Emergency stop paid local usage without touching existing services:

```sh
cd /Users/timothyajayi/PycharmProjects/PythonProject/ai-portfolio-assistant
.venv/bin/python -B -m src.local_development disable \
  --state "$HOME/.local/state/portfolio-assistant-development"
```

This requires no provider credentials. It blocks new admissions; it cannot revoke
already-issued external work. Counters/replay claims remain spent. Stop only these
new runners with Ctrl-C; do not clear abandoned reservations while workers run.

## Offline verification and limitations

```sh
.venv/bin/python -B -m unittest tests.test_local_development -v
NODE_ENV=development node --test tests/local_frontend.test.mjs
.venv/bin/python -B -m unittest discover -s tests -v
```

The cross-language test uses mocked fetch over pipes into FastAPI TestClient,
actual scoped credentials/assertion signing and verification, real disposable
SQLite, mocked Siteverify HTTP transport and mocked Gemini SDK. It verifies secure
cookie attributes, verified issuance, RAG execution, exact accounting, replay and
quota denial, emergency shutdown, loopback/policy rejection, private storage and
hosted/production refusal. No TCP listener, real provider or operational database
is needed. Fixtures do not authorize real browser sessions.

The HTTPS listener/assets, HTTP101 HMR handshake, React hydration, mouse open/close,
Enter activation and Escape close/focus return have been verified in isolated
Chrome with external providers and chat APIs blocked. The existing installed
local certificate was used without disabling HTTPS or certificate validation.
A subsequent controlled live test also verified the Cloudflare widget, server-side
proof verification, verified-session issuance, and a Gemini/RAG answer about
BundesHost. Production hosting, ingress identity, and deployment remain unverified.
Next's existing Google-font download build dependency remains. The local HTTPS
launcher forwards only `/_next/hmr` (optionally with Next's `id` query parameter)
to fixed `127.0.0.1:3000`. The connection requires the exact loopback peer, Host
`localhost:3443`, Origin `https://localhost:3443`, and a valid WebSocket handshake.
Other upgrade paths and ambiguous headers are rejected. Browser cookies,
Authorization and portfolio session/assertion headers are not forwarded for HMR.
There are at most eight HMR tunnels, a five-second handshake deadline and
bidirectional close/error cleanup. HTTPS/TLS and chat security are unchanged.

HMR is required by this Next.js development runtime's React debug channel;
dropping its WebSocket can prevent initial hydration, not just hot reload.
After a launcher change, restart only that launcher with operator authorization.
A plain page reload cannot update the already-running Node proxy implementation.
Local processes with access to your user account/profile are trusted; loopback
is not protection against a compromised host or deliberately published tunnel.


## Temporary session-only diagnosis

The existing backend runner accepts `serve --session-only`. This uses the existing
`SESSION_CHAT_ENABLED=false`, `SESSION_CHAT_HTTP_ENABLED=false` and production
legacy-denial controls. It disables every FastAPI chat execution path before RAG,
embedding or generation, while keeping authenticated Turnstile verification and
verified-session issuance configured. No ledger switches, counters, credentials or
files are reset. Existing emergency shutdown and issuance quotas remain binding;
this mode does not enable disabled storage.

After authorization to restart **only** the local backend, append `--session-only`
to its existing `serve --state ... --allow-live-providers` command, retaining the
same private process credentials and state directory. The frontend and HTTPS
launcher require no changes or restarts. Do not run init/enable or replace storage.

The backend emits a sanitized `local_session_diagnostic` startup event with
`gemini_execution=blocked`, `verified_session_issuance=enabled` and
`verification_diagnostics=enabled`. These describe execution/configuration gates,
not a promise that issuance will succeed: storage and provider checks still apply.
Confirm successful startup on port8001 and this event in the same server terminal
before the separately authorized browser test. A session failure still emits the
existing `verified_session_failure` diagnostic.

The normal portfolio interface can submit the genuine verification proof. If
session creation succeeds (HTTP201), its following chat request is denied by the
backend, so no assistant answer is expected during this diagnostic. Do not
interpret that deliberate chat error as session failure or repeat verification.
No browser fetch patch is required. The mode is local-only and is not included in
the production image. Removing the command option requires another authorized
backend restart; no real provider test is implied or authorized by removing it.
