# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions correspond to the `VERSION` file / `Cargo.toml` `version` and
the Git tags (`vX.Y.Z`) that trigger shipper release builds.

## [Unreleased]

### Fixed

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
