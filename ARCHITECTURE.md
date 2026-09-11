# Architecture

SecLog is two deployables sharing one Rust crate (`seclog`):

- **`seclog`** (`src/main.rs`) — the server: an axum API, a static-file
  host for the dashboard, and the log ingestion/classification pipeline.
  Runs in Docker alongside MariaDB.
- **`shipper`** (`src/bin/shipper.rs`) — a standalone, dependency-free
  binary that runs on a monitored machine, tails configured log sources,
  classifies each line, and POSTs it to the server. Built for Linux,
  macOS, and Windows (`.github/workflows/release.yml`) and distributed as
  a single static-ish binary, not a container.

Both binaries link the shared library code in `src/lib.rs` — `parser`
(detection rules + severity classification) and `models` (wire types) —
so a log line is classified identically regardless of which side of the
wire it happens on.

## Server (`src/main.rs`, `src/db.rs`, `src/auth.rs`, `src/notify.rs`)

- **`main.rs`** — the axum `Router`, all HTTP handlers, and two
  `FromRequestParts` extractors that double as auth middleware:
  - `AuthUser` — validates the `__Host-seclog_session` cookie against the
    `sessions` table. Also enforces same-origin on state-changing
    requests (`check_same_origin`) and blocks all but `/change-password`
    and `/me` while `must_change_password` is set.
  - `AgentAuth` — validates the `X-Agent-Key` header against the `agents`
    table. Used by every shipper-facing endpoint (`/logs` POST,
    `/agents/config`, `/agents/ping`). Deliberately a separate credential
    type from session cookies: it's a long-lived machine credential, not
    a human login.
  - `AdminUser` wraps `AuthUser` and additionally requires `role ==
    "admin"`.
- **`db.rs`** — all SQL (via `sqlx`, MariaDB). Owns schema creation and
  idempotent migrations (`init_*_schema` functions, run on every
  startup — see `main()`). No ORM; queries are hand-written and mostly
  return tuples or `#[derive(FromRow)]` structs.
- **`auth.rs`** — password hashing (Argon2id), session/API-key token
  generation and hashing (tokens are stored as SHA-256 digests, never in
  plaintext — see `hash_token`), TOTP/MFA, and the in-memory
  `LoginRateLimiter`.
- **`notify.rs`** — fans a classified event out to enabled notification
  channels (email, Slack, Discord, Telegram, ntfy, generic webhook) by
  severity threshold. Fire-and-forget: dispatch runs on a detached
  `tokio::spawn` from `create_log` so a slow/dead webhook never delays
  the HTTP response back to the shipper that sent the event.
- Two background loops started in `main()`: hourly expired
  session/MFA-pending cleanup, and a 15-minute retention sweep (age- and
  row-count-based, both configurable via **Settings**).

## Shipper (`src/bin/shipper.rs`)

Single binary, no config file — everything comes from two environment
variables (`SHIPPER_API_URL`, `SECLOG_ENROLLMENT_TOKEN`) and state it
persists next to itself:

- `.seclog_agent_key` — the API key, written once after a successful
  `/agents/self-register` call. On every subsequent start, its presence
  means "already enrolled" — the enrollment token (single-use) is only
  consulted on a truly first run.
- `.shipper_state_<sanitized-path>_<hash>` — one file per watched path,
  storing the last byte offset shipped from that file. The hash suffix
  exists because the sanitized-path prefix alone isn't collision-proof
  (see the comment on `state_file_for`).

Startup sequence in `main()`:

1. Load or obtain (`self-register`) the API key.
2. Blocking-loop `GET /agents/config` until it succeeds, to learn the
   server-assigned hostname (attached to every event this run ships,
   rather than trusting a locally-detected one).
3. On Windows/macOS only, spawn the platform-specific watcher
   (`watch_windows_security_log` / `watch_macos_unified_log`) — these
   read from `wevtutil` / `log stream` respectively, not a flat file,
   since neither OS exposes security events as one.
4. Enter the reconciliation loop: poll `/agents/config` every 30s, diff
   the returned `paths` against the currently-running set
   (`active: HashMap<String, JoinHandle<()>>`), `tokio::spawn` a
   `watch_file` task for anything new, `.abort()` the task for anything
   removed. Changing watched paths in the dashboard takes effect on the
   next poll — no shipper restart needed.

`watch_file` polls its path once a second: reopen-on-error, detect
rotation/truncation (`size < position` ⇒ reset to 0), and read exactly
the newly-appended bytes using `read_until(b'\n', ...)` with manual byte
accounting — not `BufRead::lines()`, which strips line endings before you
can count them and would incorrectly treat a not-yet-`\n`-terminated
line (very possible when polling a file mid-write) as a complete one.
An incomplete trailing chunk is left unconsumed and retried next poll.

`ship_line` runs each line through `parser::parse_line`, POSTs the
result to `/logs`, and retries transport failures *and* non-2xx
responses up to three times before giving up on that line (the read
position only advances on confirmed success — see
[CHANGELOG](CHANGELOG.md)).

`looks_like_own_output` exists to break a specific feedback loop: under
systemd, the shipper's own stdout goes to the journal, which on several
distros gets forwarded back into `/var/log/messages`/`/var/log/secure`.
If those are also watched paths, the shipper would re-ingest its own
"Shipped: ..." output, ship *that*, and so on — each generation slightly
longer, filling a disk overnight. Every journal line for a process is
tagged `<name>[<pid>]:`, so any line matching `shipper[\d+]:` is skipped
before it ever reaches the classifier.

## Detection pipeline (`src/parser.rs`)

`parse_line` runs each raw line through an ordered table of regex rules
(`rules()`) — first match wins — assigning a `Severity`
(Low/Medium/High/Critical) and a human-readable label, which gets
prefixed onto the stored message (`[<label>] <original line>`). Rule
ordering is load-bearing: more specific patterns must precede broader
ones that would otherwise shadow them (see the ordering comment at the
top of `rules()`). A username is opportunistically extracted via a
second, smaller pattern table (`extract_user`), falling back to
`"system"`.

Windows events flowing through the generic text path (rare — mostly
whatever `classify_event_id` in the shipper doesn't already handle
directly) and macOS unified-log output use the same table; only the
Windows Security-log watcher builds its `NewLogEntry` directly from
`wevtutil` output instead of going through `parse_line`.

`hash_line` (SHA-256 of the fully-classified message + host) backs the
`logs.line_hash` unique constraint — `db::insert_log` uses `INSERT
IGNORE`, so a shipper retry after a dropped response never creates a
duplicate row.

## Data flow, end to end

```
watched file / journal / event log
        │  (shipper: tail, classify via parser::parse_line)
        ▼
POST /logs  { severity, user, message, host }   [X-Agent-Key]
        │  (server: AgentAuth, NewLogEntry::is_valid, hash_line)
        ▼
INSERT IGNORE INTO logs               ──▶ tokio::spawn notify::trigger_alert
        │                                        │
        │                                        ▼
        │                         enabled channels (severity ≥ threshold)
        ▼
GET /logs, /logs/summary   [session cookie]
        │  (server: AuthUser)
        ▼
dashboard (static/pages/dashboard.html + app.js)
```

## Frontend (`static/`)

No build step, no framework — plain HTML fragments and vanilla JS,
served directly by axum's `ServeDir` fallback.

- **`index.html`** — login/signup/MFA screen.
- **`app.html`** — the authenticated shell: a topbar (`nav.js`) plus a
  `#content` div that `router.js` swaps fragments into.
- **`router.js`** — a tiny hash-free client router: each route maps a
  path to an HTML fragment under `pages/` and an `init*()` function
  (`app.js`) to run once that fragment is in the DOM. Uses
  `history.pushState`/`popstate`, not a routing library.
- **`auth.js`** — `authFetch()` wraps `fetch` with `credentials:
  'include'` and a blanket "401 ⇒ redirect to login" handler. The
  session cookie is httpOnly, so the client never handles a token
  directly.
- **`app.js`** — everything else: dashboard rendering, the Agents page
  (enrollment, path management), Settings (general/security/alerts
  tabs), all built with `document.createElement` rather than
  `innerHTML` for anything containing server-supplied text.

## Persistence

MariaDB, schema created and migrated at server startup (`db::init_*`),
not via a separate migration tool — every `init_*_schema` function is
idempotent (`CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`)
so it's safe to run on every boot, including against an existing
database from an older version. See `db::init_schema` for an example of
an actual data migration (the old `level` column with `Info/Warn/Error`
values, remapped to `severity` with `Low/Medium/High`).

## Deployment

- **Server**: `Dockerfile` (multi-stage: `rust:bookworm` builder →
  `debian:bookworm-slim` runtime), orchestrated by `docker-compose.yml`
  (app + MariaDB + optional Caddy profile for automatic TLS). `install.sh`
  bootstraps `.env` and prompts for the TLS setup.
  `.github/workflows/docker-publish.yml` builds and pushes the image to
  GHCR on pushes to `main`/`dev` and on version tags.
- **Shipper**: cross-compiled for Linux/macOS/Windows and attached to a
  GitHub Release by `.github/workflows/release.yml` on a `v*` tag push.
  `/install/linux.sh` and `/install/windows.ps1` (served by the running
  server, see `main.rs`) download the right binary, verify it's a real
  executable (not an error page), and install it as a systemd
  service / scheduled task respectively.
