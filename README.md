# SecLog

A self-hosted, security-focused log aggregation platform. Lightweight shipper
agents run on Linux, macOS, and Windows machines, watch security-relevant
logs (SSH/sudo activity, Windows Event Log, macOS unified log), classify
events by severity using a built-in detection rule set, and ship them to a
central web dashboard with role-based access control.

## Architecture

- **Server**: Rust (axum) + MariaDB, containerized via Docker Compose.
  Serves a JSON API and the web dashboard.
- **Shipper**: a single cross-platform binary. Enrolls itself with a
  one-time token, auto-detects its hostname, and watches configured log
  sources, shipping classified events back to the server over HTTPS/HTTP.

## Server installation

Requires Docker + Docker Compose.

```bash
git clone https://github.com/LordSodomiser/SecLog.git
cd SecLog
./install.sh
```

This generates a `.env` with strong random database credentials and starts
the server + database. Visit `http://<server-ip>:3000` **(the first
account created becomes admin automatically.)**

### Updating the server

```bash
git pull origin main
docker compose pull
docker compose up -d
```

The dashboard shows the running version and flags when a newer release is
available.

## Adding an agent

1. Log in as admin → **Agents** → **Generate Enrollment Token**.
2. On the target machine, run the install command shown (it's tailored to
   that machine's OS and points at your server automatically):
   - **Linux:** `curl -sL http://<server>:3000/install/linux.sh | bash`
   - **Windows:** `iwr http://<server>:3000/install/windows.ps1 | iex`
3. Back in **Agents**, select the new agent and add the paths you want
   watched (e.g. `/var/log/auth.log`). Changes take effect within ~30s,
   no restart needed.

> **macOS/Windows note:** these platforms don't expose security events as
> flat text files. The shipper includes dedicated watchers for the macOS
> unified log and the Windows Security event log; no manual path
> configuration is needed for those sources.

## Development

```bash
cargo run --bin seclog     # server (needs DATABASE_URL in .env)
cargo run --bin shipper    # shipper, against a local test file
```

## Security notes

- Passwords hashed with Argon2id; 15-character minimum.
- Sessions are revocable server-side tokens, not self-contained JWTs.
- Login is rate-limited per username.
- Agents authenticate with a separate long-lived API key, obtained via a
  single-use, admin-issued enrollment token.
- Admin-created accounts get a temporary password and must change it on
  first login.
