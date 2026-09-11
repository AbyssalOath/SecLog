# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions correspond to the `VERSION` file / `Cargo.toml` `version` and
the Git tags (`vX.Y.Z`) that trigger shipper release builds.

## [Unreleased]

### Added

- **Display timezone**: Settings → **Preferences** lets you pick the
  timezone every timestamp in SecLog (Dashboard reviews, Audit Log,
  Directory, Syslog, Archival Storage) renders in, instead of always
  using the browser's own system timezone implicitly. Saved per-browser
  (`localStorage`), not on the account, so it needs no admin-gated API
  and is available to every role that can reach Settings at all.
  (`app.js`'s new `formatTimestamp`, replacing the old
  `formatDirectoryTimestamp` and every ad hoc `toLocaleString()` call)

### Changed

- **Directory moved into Settings**: what was a standalone top-level
  **Directory** nav page is now the **Settings → Directory** tab —
  it's exclusively admin configuration (LDAP connection, directory
  login, deployment packages, discovered hosts), same as every other
  Settings tab, not its own navigation-level concern. No functional
  change: every panel, field, and button works exactly as before, just
  relocated. Existing bookmarks/links to `#/directory` no longer
  resolve — use `#/settings` and select the Directory tab.
- **Settings is no longer admin-only as a whole page**: an `auditor`
  account can now open Settings to reach the new Preferences tab (its
  timezone), but still sees none of the admin-only tabs (General,
  Security, Alerts, Directory) — those, and everything they configure,
  remain `AdminUser`-gated exactly as before. A plain `user` account
  still can't open Settings at all.

## [0.2.0] - 2026-09-11

### Added

- **Correlation rules**: Settings → Alerts → **Correlation Rules** adds
  threshold detection on top of the existing `[Label]`-prefixed
  detection rule table (e.g. 5 "SSH failed login" events from one host
  within 5 minutes fires an alert). A rule references an existing
  detection label from a dropdown, not a free-text pattern or query, so
  it extends the maintained rule table rather than adding a second, less
  trustworthy way to define "suspicious." Checked every 60s; fires once
  per burst, and again on a later, separate burst. Three defaults
  seeded on first run, fully editable/deletable like any added rule.
  See [README § Correlation rules](README.md#correlation-rules).
  (`parser::classify`/`known_labels`, new `correlation_rules` table,
  new `GET /correlation-rules(/labels)`, `POST /correlation-rules`,
  `PATCH`/`DELETE /correlation-rules/{id}`)
- **Syslog receiver**: the new **Syslog** page accepts UDP and/or TCP
  syslog on port 514 from devices that can't run the shipper (firewalls,
  switches, etc.), off by default. Gated by a fail-closed source-IP/CIDR
  allowlist — the same practical mitigation real syslog receivers rely
  on, since the protocol itself has no per-message authentication.
  RFC 3164 and RFC 5424 headers are parsed for hostname and timestamp;
  anything else still ingests, labeled by source IP. Enabling/disabling
  UDP/TCP takes a restart (a real socket bind); the allowlist applies
  live. See [README § Syslog receiver](README.md#syslog-receiver).
  (`src/syslog.rs`, new `syslog_config` table, new `GET/POST
  /syslog/config`, `docker-compose.yml`'s new `514:514` UDP/TCP ports)
- **Archival storage**: Settings → General → **Archival Storage** can
  upload logs to S3-compatible object storage (AWS S3, MinIO, Backblaze
  B2, etc.) or SFTP before Retention deletes them, instead of only ever
  deleting. A dated JSON Lines file is uploaded before each delete
  actually runs; on upload failure, that cycle's delete is skipped
  entirely (never silently loses rows behind a bad credential) and
  raises a `[SYSTEM]` alert, same as every other retention failure mode.
  Secrets are encrypted via the existing `SECLOG_MASTER_KEY` mechanism,
  same "write-only, shown once" contract as the LDAP bind password. See
  [README § Archival storage](README.md#archival-storage).
  (`src/archive.rs`, new `archive_config` table, new `GET/POST
  /archive/config`, `POST /archive/test`)
- **Compliance & audit trail** (CJIS AU-2, AU-3, AU-3(1), AU-5, AU-6,
  AU-8): SecLog now keeps a record of its own activity, not just what
  the shipper reports from monitored machines.
  - Every login (success/failure, local or directory), admin action
    (user/agent/path/settings/notification/directory changes), and read
    of log data is recorded with actor, timestamp, resource, outcome,
    and source IP — viewable at the **Audit Log** page. Secrets are
    never recorded: a directory config change logs that the bind
    password changed, never the password itself.
    (`db::record_audit_event`, new `audit_log` table, new
    `GET /audit-log`)
  - Three failure conditions now raise a `[SYSTEM]` alert through the
    existing notification channels: an agent gone dark past a
    configurable threshold (Settings → General → Agent Health, default
    120 min), a failed retention run, and log storage crossing 90% of
    the row cap. A failed audit-log write raises one too.
  - Any log row can be marked Open/Reviewed/False Positive with an
    investigation note from its status pill in the Dashboard's per-host
    detail view — itself an audited action. (new `POST
    /logs/{id}/review`, `logs.review_status`/`reviewed_by`/
    `reviewed_at`/`review_note`)
  - Where recoverable from the source line (auditd's embedded epoch
    time, a leading ISO8601 timestamp, or classic BSD syslog format),
    the event's own time is now stored separately from `created_at`
    (ingestion time) — so a shipper catching up on a backlog after an
    outage doesn't make every event look like it happened at catch-up
    time. Skew between reported and server time past 15 minutes is
    logged; past 60 minutes also raises a `[SYSTEM]` alert.
    (`parser::extract_event_time`, `logs.event_time`)
  - See [README § Compliance notes (CJIS)](README.md#compliance-notes-cjis).
- **Tamper-evidence, an `auditor` role, and two smaller compliance
  closes** (CJIS AU-9, AU-11):
  - `audit_log` is now a real hash chain — every row cryptographically
    links to the one before it (`prev_hash`/`row_hash`), computed inside
    a transaction that locks the current chain tip. **Verify Chain** on
    the new Audit Log page re-derives every row's hash and reports the
    first broken one, if any. Rows from before this existed are `''` and
    are treated as pre-chain, not as breaks.
  - `logs` gets hourly **checkpoints** instead of a per-row chain — a
    linear chain there would serialize every shipper write across every
    agent, which is a real throughput cost this table specifically can't
    absorb. Each checkpoint hashes everything ingested since the last
    one; re-checking later distinguishes rows legitimately purged by
    retention (**Unverifiable**) from rows that still exist but no
    longer match what was checkpointed (**Broken**).
    (`db::create_log_checkpoint`, new `log_checkpoints` table, new
    `GET /logs/checkpoints`)
  - New `auditor` role (`admin`/`user`/`auditor` — role is now validated
    at account-creation time, previously unchecked): can view and review
    log/audit data, administers nothing else. New `AuditAccess`
    extractor gates exactly the endpoints that are actually about
    reviewing evidence; everything else stays `AdminUser`-only.
  - Event-time extraction (see above) now also covers the Windows and
    macOS *native* shipper paths (`wevtutil`'s `Date:` field; macOS
    `log stream`'s space-separated, colonless-offset timestamp format,
    which the ISO8601 extractor silently failed to match before this).
  - The AU-5 storage-capacity alert and Settings now show the `logs`
    table's real on-disk byte size, read from MariaDB's own metadata —
    the `app` and `mariadb` containers don't share a filesystem, so this
    is the accurate way to answer "how much room is this taking,"
    unlike a raw disk-free check from the wrong container.
    (`db::get_table_size_bytes`)
- **Deployment packages (GPO / Intune)**: the Directory page can now
  generate a headless PowerShell script, backed by a new multi-use,
  time-limited enrollment token, for pushing the shipper to an entire
  OU via Group Policy (Computer Startup Script) or Intune (Platform
  Script) instead of running the one-time install command on each
  machine by hand. One script covers both mechanisms — both just run
  PowerShell unattended as `SYSTEM`. Unlike the existing interactive
  script, this one actually finishes setting up persistence: it
  registers the shipper as a Scheduled Task that starts at boot and
  restarts on failure (the shipper isn't a real Windows service, so
  `sc.exe` alone can't start it), and skips re-installing on a machine
  that's already enrolled. Deployment tokens are listed and revocable
  from the same panel; existing single-use tokens (Agents page,
  per-host Directory rows) are unaffected. See
  [README § Deployment packages](README.md#deployment-packages-gpo--intune).
  (`db::create_bulk_enrollment_token`/`list_enrollment_tokens`/
  `revoke_enrollment_token`, `main::windows_unattended_install_script`,
  new `POST /directory/deployment-package`,
  `GET /directory/deployment-tokens`,
  `DELETE /directory/deployment-tokens/{id}`)
- **Directory sync**: connect SecLog to an LDAP or Active Directory
  server (**Directory** in the dashboard) to discover domain-joined
  computers and see, per host, whether the shipper is likely already
  running there. Deliberately read-only — SecLog binds and searches on
  a schedule but never connects to, or executes anything on, a
  discovered machine; rollout still goes through the existing one-time
  enrollment token, now surfaced per-host from the Directory page.
  Requires `SECLOG_MASTER_KEY` (generated automatically by
  `install.sh`) to save an LDAP bind password, since it's the first
  credential in SecLog that has to be decrypted back to plaintext
  rather than one-way hashed. See
  [README § Directory sync](README.md#directory-sync-ldap--active-directory).
  (`src/directory.rs`, `src/crypto.rs`, new `/directory/*` endpoints)
- **Directory login**: sign in to the dashboard with a domain
  username/password, using the same LDAP/AD connection Directory sync
  already has configured. A local account with a matching username
  always takes priority — the directory is only ever consulted when no
  local account exists for that username, so this can't shadow or take
  over an existing account. Accounts are created automatically on first
  successful directory login, and both the account's existence and its
  role (admin vs. user, from `memberOf` against a configured admin
  group) are re-verified live against the directory on every login, not
  cached. See
  [README § Directory login](README.md#directory-login).
  (`directory::authenticate_user`, `users.auth_source`, `ldap_config`'s
  new `login_enabled`/`user_base_dn`/`user_filter_template`/
  `admin_group_dn` columns)
- **`install.sh` safety net**: warns if `docker-compose.yml`/
  `docker-compose.dev.yml` reference an environment variable `.env`
  doesn't have, instead of the container silently starting with an
  empty value. Exists to catch a future change that adds a new required
  variable without a matching generation/prompt step in `install.sh` —
  see [CONTRIBUTING § Environment variables](CONTRIBUTING.md#environment-variables).

### Changed

- **Log access is now admin-only** (CJIS AU-9): `GET /logs` and
  `/logs/summary` require the admin role — a `"user"`-role account can
  no longer view ingested events. This is a behavior change for any
  existing non-admin accounts that were relying on Dashboard access.
- **Default log retention raised from 30 to 365 days** (CJIS AU-11).
  Only affects fresh installs — `log_retention_days` is stored per-row
  in the `settings` table, so an existing install keeps whatever it's
  already set to; update it under Settings → General if you need the
  new minimum. See
  [README § Compliance notes (CJIS)](README.md#compliance-notes-cjis).

### Fixed

- **Dashboard was broken for every user.** `initDashboard()` called
  `GET /logs` with no `host` query parameter, but `host` is a required
  field on that endpoint (by design — it exists specifically to prevent
  a repeat of an earlier incident where an unpaginated "give me
  everything" fetch pushed 600k+ rows into the browser and crashed the
  tab). The mismatch meant every page load 400'd silently and the
  dashboard never showed real data. Rewritten to use the two endpoints
  that already existed for exactly this: `GET /logs/summary` for the
  host overview, and paginated `GET /logs?host=...&limit=...&offset=...`
  for the per-host drill-down — both already implemented server-side,
  just never wired up on the frontend. (`static/app.js`)
- **Shipper: a non-2xx response from the server was treated as a
  successful delivery.** `ship_line` only distinguished "the request
  failed to send" (`Err`) from "a response came back" (`Ok`) — it never
  looked at the response's status code. A rejected payload (400), a
  revoked/invalid agent key (401), or a server-side error (5xx) all
  logged `Shipped (<code>)` exactly like a real success, the shipper's
  read position advanced past that line, and the event was gone for
  good — no retry, no re-send, nothing visibly wrong in the shipper's
  own output. This is the most likely cause of "the shipper is running
  but nothing shows up on the dashboard." Non-2xx responses now go
  through the same retry-then-give-up path as a transport error.
  (`src/bin/shipper.rs`)
- **Shipper: reading a partial line as if it were complete could corrupt
  the read position.** The file watcher polls once a second, so it can
  legitimately catch a log file mid-write. The old code read with
  `BufRead::lines()`, which will return whatever bytes are available at
  EOF even if they don't end in `\n` yet — the shipper then advanced its
  saved position by that content's length **+ 1**, assuming a trailing
  newline that didn't actually exist. If nothing else was appended
  before the next poll, that phantom byte made the position exceed the
  file's actual size, which falsely tripped the "file appears
  rotated/truncated" check and re-shipped the entire file from byte 0.
  If something *was* appended in between, the extra byte instead got
  silently skipped off the front of it. The watcher now reads with exact
  byte accounting (`read_until`) and only advances past a line once it's
  confirmed complete (ends in `\n`), leaving an in-progress line for the
  next poll. (`src/bin/shipper.rs`)
- **Shipper: no request timeout on any outbound HTTP client.**
  `reqwest::Client::new()` has no timeout by default; a connection that
  stalls without ever closing or erroring (a dead NAT mapping, a proxy
  that swallows the response) could hang a watch task indefinitely —
  including the startup config fetch, blocking that shipper instance
  from ever shipping anything until it was restarted. Every client in
  `shipper.rs` now goes through one constructor with a 15s timeout.
  (`src/bin/shipper.rs`)
- **Shipper: two different watched paths could share one state file.**
  `state_file_for` mapped every non-alphanumeric character — including a
  literal `_` already present in a path — to `_`, so e.g.
  `/var/log/auth.log` and `/var/log/auth_log` both produced
  `.shipper_state__var_log_auth_log` and would read/write each other's
  saved position if both were ever watched on the same host. State
  filenames now carry a content-hash suffix that makes every path
  unique regardless of what characters it contains. Existing shippers
  will re-derive fresh state filenames on upgrade and resume from the
  current end of each watched file (the same safe default already used
  for a newly-added path), not from a stale position. (`src/bin/shipper.rs`)
- Silently-swallowed write failure when persisting the agent's API key
  (`save_key`) — unlike the equivalent path for read-position state,
  a failed write here previously left no trace, so a permissions issue
  in the shipper's working directory would surface only much later, as
  a confusing "enrollment token already used" error on the next
  restart. Now logs a warning explaining the consequence.
  (`src/bin/shipper.rs`)

## Earlier history

Versions prior to this file's introduction were tracked only in commit
messages and Git tags — see `git log` and the
[Releases page](https://github.com/AbyssalOath/SecLog/releases) for that
history. Notable earlier milestones, for context:

- Per-agent, per-path log watching with live config reconciliation
  (no shipper restart needed to add/remove a watched path).
- Self-service agent enrollment via single-use, admin-issued tokens
  (`/agents/self-register`), replacing manually-typed API keys.
- TOTP-based MFA for dashboard logins.
- Configurable log retention (age- and row-count-based).
- Outbound alerting to email, Slack, Discord, Telegram, ntfy, and
  generic webhooks, gated by per-channel minimum severity.
- Move to hashed session tokens and hashed agent API keys/enrollment
  tokens at rest (previously compared in plaintext).
