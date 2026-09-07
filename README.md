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
git clone https://github.com/AbyssalOath/SecLog.git
cd SecLog
./install.sh
```

This generates a `.env` with strong random database credentials and starts
the server + database. The first account created via the dashboard
automatically becomes admin.

Seclog's session cookie is browser-enforced HTTPS-only (see
[Security notes](#security-notes)), so `install.sh` will ask how you want
to handle TLS:

- **You already run a reverse proxy** (NGINX Proxy Manager, Traefik, etc.)
  — the installer skips Caddy and prints the upstream address
  (`http://<this-host-ip>:3000`) to point your proxy at. Just make sure
  your proxy terminates HTTPS on the browser-facing side.
- **You don't have one** — the installer sets up [Caddy](https://caddyserver.com/)
  for you automatically. Give it a domain name and it obtains a real
  Let's Encrypt certificate with no further config. Leave it blank and
  it self-signs a certificate instead, so a bare LAN/server IP still
  works over `https://` — your browser will show a one-time certificate
  warning in that case, which is expected.

Either way, once it's running, visit the dashboard over `https://` (via
Caddy or your own proxy) rather than `http://<ip>:3000` directly — plain
HTTP won't let the session cookie persist.

### Updating the server

```bash
git pull origin main
docker compose pull
docker compose up -d
```

Your `COMPOSE_PROFILES` setting in `.env` (set once by `install.sh`) is
picked up automatically, so this brings Caddy back up too if you're using
it — no extra flags needed.

The dashboard shows the running version and flags when a newer release is
available.

## Releasing shipper binaries

Cross-platform shipper builds are published via GitHub Actions when a
version tag is pushed.

Before creating a release, keep `Cargo.toml` and `VERSION` synchronized
with the release version. For example, for version `vX.Y.Z`:

In `Cargo.toml`:

```toml
version = "X.Y.Z"
```

In `VERSION`:

```text
X.Y.Z
```

Commit and push the version change:

```bash
git add Cargo.toml VERSION
git commit -m "Bump version to X.Y.Z"
git push origin main
```

Then create and push the corresponding Git tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

GitHub Actions will build the shipper for Linux, Windows, and macOS and
attach the binaries to the GitHub Release.

Check the **Actions** tab for build status, then confirm the resulting
**Release** has these assets attached:

- `shipper-linux-x86_64`
- `shipper-windows-x86_64.exe`
- `shipper-macos-x86_64`

The install scripts download the appropriate shipper binary from the
latest GitHub Release, so verify that the required Release assets are
present before deploying the installer.

## Adding an agent

1. Log in as admin → **Agents** → **Generate Enrollment Token**.
2. On the target machine, run the install command shown (it's tailored to
   that machine's OS and points at your server automatically):
   - **Linux:** `curl -sL http://<server>:3000/install/linux.sh | bash`
   - **Windows:** `iwr http://<server>:3000/install/windows.ps1 | iex`
3. Back in **Agents**, select the new agent and add the paths you want
   watched (e.g. `/var/log/auth.log`). Changes take effect within ~30s,
   no restart needed.

> **Session model:** the dashboard uses secure, httpOnly cookies for login
> sessions — nothing sensitive is ever stored in browser localStorage.

> **macOS/Windows note:** these platforms don't expose security events as
> flat text files. The shipper includes dedicated watchers for the macOS
> unified log and the Windows Security event log; no manual path
> configuration is needed for those sources.

> **SELinux (Fedora/RHEL/Rocky/AlmaLinux):** the install script relabels
> the shipper binary automatically, but if the service still fails to
> start with a `203/EXEC` status in `systemctl status seclog-shipper`,
> check `ls -Z /opt/seclog-shipper/shipper` for a context like
> `user_tmp_t`. Fix it with:
> ```bash
> sudo semanage fcontext -a -t bin_t "/opt/seclog-shipper/shipper"
> sudo restorecon -v /opt/seclog-shipper/shipper
> sudo systemctl restart seclog-shipper
> ```
> (`semanage` is in the `policycoreutils-python-utils` package if it's
> not already installed: `sudo dnf install policycoreutils-python-utils`.)
> `restorecon` alone often isn't enough here — it only resets a file to
> whatever the policy database already maps that exact path to, and most
> systems have no existing rule for `/opt/seclog-shipper`. `semanage`
> registers that rule first, which is what `restorecon` then applies.

### Recommended Linux log paths

The shipper's parser looks for security-relevant events including SSH
authentication, sudo/su activity, account changes, firewall events, cron
changes, shell-history activity, and system/service events.

Recommended paths vary by distribution:

| Distribution | Recommended paths | What they cover |
|---|---|---|
| **Ubuntu / Debian** | `/var/log/auth.log` | SSH, sudo, su, authentication, account activity |
| | `/var/log/syslog` | General system/service and firewall messages |
| | `/var/log/kern.log` | Kernel and network-related events |
| **RHEL / CentOS / Rocky / AlmaLinux** | `/var/log/secure` | SSH, sudo, su, authentication, account activity |
| | `/var/log/messages` | General system/service and firewall messages |
| | `/var/log/audit/audit.log` | Linux audit events, when `auditd` is enabled |
| **Fedora** | `/var/log/secure` | SSH, sudo, su, authentication, account activity |
| | `/var/log/messages` | General system/service messages, when present |
| | `/var/log/audit/audit.log` | Linux audit events, when `auditd` is enabled |
| **Arch Linux** | `/var/log/auth.log`* | Authentication events if a syslog daemon is configured |
| | `/var/log/messages.log`* | General system messages if a syslog daemon is configured |
| **openSUSE / SLES** | `/var/log/messages` | General system and service messages |
| | `/var/log/audit/audit.log` | Linux audit events, when `auditd` is enabled |

\* Arch Linux does not normally provide these traditional log files by
default. It primarily uses `systemd-journald`. A syslog daemon such as
rsyslog or syslog-ng must be configured if you want traditional files for
the shipper to watch.

For most installations, start with the authentication log for the
distribution:

- **Ubuntu / Debian:** `/var/log/auth.log`
- **RHEL / CentOS / Rocky / AlmaLinux / Fedora:** `/var/log/secure`
- **Arch:** configure persistent journald or a syslog daemon first

For broader coverage, also add the applicable system, audit, and firewall
logs. The parser specifically recognizes events such as:

- SSH failed logins and invalid users
- SSH successful logins
- Changes to `authorized_keys`
- Repeated authentication failures
- Unauthorized sudo attempts
- Failed `sudo` and `su` attempts
- Root sessions
- User and group modifications
- Password changes
- Firewall `DENY` / `DROP` events
- `iptables`, `ufw`, and `firewalld` events
- Possible port scans
- Cron modifications
- Shell-history access
- Service starts
- Segmentation faults

### Example agent configurations

**Ubuntu / Debian:**

```text
/var/log/auth.log
/var/log/syslog
/var/log/kern.log
```

**RHEL / CentOS / Rocky / AlmaLinux:**

```text
/var/log/secure
/var/log/messages
/var/log/audit/audit.log
```

**Fedora:**

```text
/var/log/secure
/var/log/audit/audit.log
```

**Arch Linux:**
```text
/var/log/auth.log
/var/log/messages.log
```

> **Note for Arch Linux:** Only use the paths above if a syslog daemon is
> configured to write those files. Otherwise, Arch primarily uses
> systemd-journald, and the shipper should use a dedicated journald
> watcher for those events.

**openSUSE / SLES:**
```text
/var/log/messages
/var/log/audit/audit.log
```

> **Tip:** You do not need to configure every path. Start with the authentication log for your distribution, then add the system, audit, and firewall logs that are available on your machine.

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
- The session cookie uses the browser-enforced `__Host-` prefix, which
  requires `https://`. Accessing the dashboard over plain `http://` on a
  LAN/server IP will silently fail to persist the session — see
  [Server installation](#server-installation) for how `install.sh` sets
  up TLS (via Caddy or your own reverse proxy).

## Admin-created accounts

Admins can create accounts directly from **Settings → Security** instead
of relying on self-signup. New accounts get a random temporary password
(shown once, copyable) and must set a real password on first login.
