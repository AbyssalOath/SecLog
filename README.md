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

For how the pieces fit together in more detail, see
[ARCHITECTURE.md](ARCHITECTURE.md). Contributing a change?
[CONTRIBUTING.md](CONTRIBUTING.md). Found a security issue?
[SECURITY.md](SECURITY.md) — please don't file it as a public issue.
Release history lives in [CHANGELOG.md](CHANGELOG.md).

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

## Directory sync (LDAP / Active Directory)

Log in as admin → **Settings → Directory** to connect SecLog to an
LDAP or Active Directory server and see which domain-joined computers
don't have the shipper running yet.

This is **read-only discovery, not remote deployment**: SecLog binds
and searches for computer objects on a schedule; it never connects to,
logs into, or runs anything on a discovered machine. For each one that
isn't enrolled, the Settings → Directory page gives you a one-time
enrollment token and the same install one-liner shown on the Agents page — you
still run that on the target machine yourself (or through your
existing GPO/Intune/SCCM deployment tooling). A service account with
rights to remotely execute code across the domain is a much bigger
liability than a read-only LDAP bind, so SecLog deliberately doesn't
ask for one.

**Setup:**

1. Create a **read-only** AD/LDAP service account (needs only enough
   access to bind and search computer objects — nothing else).
2. Set `SECLOG_MASTER_KEY` in `.env` — `install.sh` generates one for
   you automatically, so this is usually already done. It's a 32-byte
   key, base64-encoded (`openssl rand -base64 32` if you ever need to
   generate your own). This exists because the LDAP bind password is
   the one secret in SecLog that has to be decrypted back to plaintext
   on every sync, unlike every other credential here (user passwords,
   sessions, agent API keys), which are one-way hashed and never
   recovered. Saving a bind password without this set fails with a
   clear error rather than ever storing it unencrypted.
3. In **Settings → Directory**, enter the server URI (`ldaps://` strongly
   preferred over plain `ldap://`), the service account's bind DN and
   password, and a base DN to search under. **Test Connection** before
   saving to catch a bad DN/password without waiting on the schedule.
4. Turn on **Enabled** and set a sync interval. SecLog will keep the
   discovered list up to date on that schedule from then on; **Sync
   Now** runs one immediately.

Enrollment status shown per host ("Likely enrolled" / "Not enrolled")
is a best-effort match against Agents by short hostname, not a
guarantee — AD typically reports a full FQDN while a shipper reports
whatever hostname its OS gives it, which isn't always the same string.
Treat it as a strong hint, and check Agents directly if it matters.

### Directory login

The same connection above can also let people sign in to the dashboard
with their domain username and password, instead of (or alongside) a
local SecLog account — turn on **Allow login with directory
credentials** in the Directory Login panel.

How it works: on login, if no local SecLog account matches the
username, SecLog searches the directory for it (`User base DN` +
`User filter`, e.g. `(&(objectClass=user)(sAMAccountName={username}))`
for AD), then binds as *that* entry using the password just typed in —
that bind is what actually proves the password, SecLog itself never
stores or sees it beyond that one request. On success, a local account
is created automatically (no admin action needed) with the role
determined by `Admin group DN`: members of that group (via `memberOf`)
get **admin**, everyone else gets **user**. Leave the admin group blank
and nobody ever becomes admin through directory login. Both role and
directory-account existence are re-checked live on **every** login, not
just the first — disable someone in AD or remove them from the admin
group, and it takes effect the next time they sign in, with nothing to
clean up in SecLog.

**A pre-existing local account always wins a username collision** —
if a local SecLog account and a directory entry share a username, the
directory is never even consulted for that username; only the local
password works. If you plan to rely on directory login, consider
turning off self-signup (Settings → General) so the two namespaces
can't collide by accident. The Settings → Security → Users table shows
each account's **Auth** column (Local / Directory) so you can tell
which is which.

This is the one place `ldaps://` matters even more than for Directory
sync above: real user passwords, not just the read-only service
account's, cross this connection on every login attempt.

### Deployment packages (GPO / Intune)

For enrolling many machines at once — an entire OU — instead of running
the one-time install command on each one by hand, the **Settings →
Directory** page's **Deployment Packages** panel generates a headless PowerShell
script backed by a **multi-use, time-limited** enrollment token: pick a
max use count and an expiry, optionally label it (e.g. the OU name, for
your own bookkeeping — SecLog can't verify a machine running the script
is actually in that OU), and it hands back a script plus separate
instructions for the two ways to run it unattended:

- **Group Policy:** add it as a Computer Startup Script (Computer
  Configuration → Policies → Windows Settings → Scripts → Startup) on a
  GPO linked to the target OU. Runs as `SYSTEM` the next time each
  machine boots.
- **Intune:** add it as a Platform Script (Devices → Scripts and
  remediations → Platform scripts), with "run using the logged-on
  credentials" set to No. Assign it to the target device group.

Both mechanisms do the same thing from SecLog's side — run an arbitrary
PowerShell script unattended as `SYSTEM` — so one script serves both;
there's no actual `.intunewin` package produced, since building one
requires Microsoft's own Windows-only `IntuneWinAppUtil.exe`, which
this server can't run.

Unlike the interactive script (which just tells you to set up
persistence afterward), this one finishes the job: it registers the
shipper as a Scheduled Task that starts at boot and restarts itself if
it ever exits, since the shipper binary isn't a native Windows service
(it doesn't speak the Service Control Manager's start/stop protocol —
`sc.exe start` on it would just fail with error 1053). It also
re-checks at the top and exits cleanly if that task already exists, so
a GPO startup script re-running on every boot doesn't repeatedly try to
reinstall an already-enrolled machine.

**The token is shown once**, embedded in the downloaded script — same
"write-only, shown once" shape as every other credential in SecLog. The
**Deployment Packages** table lists every package issued (label, uses,
expiry) with a **Revoke** action that invalidates it immediately for
any machine that hasn't run it yet, without deleting the row (kept for
audit history). This is separate from the single-use tokens the Agents
page and per-host Directory rows generate — those are unaffected and
still work exactly as before.

## Correlation rules

Settings → Alerts → **Correlation Rules** adds threshold detection on
top of the detection labels the parser already assigns (the same
`[Label]` you see prefixed on every Dashboard entry) — e.g. 5 "SSH
failed login" events from one host within 5 minutes. A rule always
references one of SecLog's existing detection labels, picked from a
dropdown, not a free-text pattern or query: correlation rules extend
the maintained rule table, they don't add a second, independently
risky way to define "suspicious." Checked every 60 seconds; a burst
alerts once, not on every check while it's still ongoing, and a later,
separate burst alerts again. Three defaults are seeded on first run
(repeated SSH failures, repeated SSH invalid-user attempts, repeated
unauthorized sudo) — fully editable and deletable like any rule you add
yourself.

## Syslog receiver

The **Syslog** page lets firewalls, switches, and anything else that
can't run the shipper send logs directly, over UDP and/or TCP port 514.
Both are off by default.

Raw syslog has no per-message authentication — true of every syslog
receiver (rsyslog, syslog-ng, Graylog's syslog input included), not a
SecLog-specific gap. The mitigation here is the same one those tools
actually rely on operationally: a source-IP/CIDR allowlist, fail-closed
— once enabled, nothing is accepted until you add at least one entry.
The allowlist applies immediately when saved; turning UDP/TCP
acceptance on or off takes a server restart, since that's an actual
network socket bind, not a soft setting.

RFC 3164 and RFC 5424 headers are recognized well enough to pull out
the device's hostname and its own reported timestamp (subject to the
same clock-skew check as shipper-reported events — see AU-8 below); a
line that doesn't match either shape is still ingested, just labeled
with the sending IP and no separate timestamp. Ingested lines run
through the exact same detection rules as anything the shipper sends.

If you're running this via the provided `docker-compose.yml`, port 514
(UDP and TCP) is already published on the `app` service — the receiver
still won't accept anything until you enable it and add an allowlist
entry above.

## Archival storage

Settings → General → **Archival Storage** lets logs that Retention is
about to delete get uploaded first, instead of only ever being
deleted. When enabled, a dated JSON Lines file (one log row per line)
is uploaded to the configured backend before each retention pass'
delete actually runs — if the upload fails, that cycle's delete is
skipped entirely and a `[SYSTEM]` alert fires, so a bad credential or
an unreachable target never silently loses data.

Two backends, pick one:

- **S3-compatible object storage** — AWS S3, MinIO, Backblaze B2,
  Wasabi, DigitalOcean Spaces, or anything else speaking the S3 API.
  Turn on **Path-style addressing** for MinIO and most self-hosted
  targets; leave it off for AWS S3 itself.
- **SFTP** — any SSH server. Password or private-key authentication,
  your choice; the remote host's SSH key is *not* verified against a
  known-hosts store in this version, so only point this at a host on a
  trusted network.

**Test Connection** uploads one small file through whichever backend is
configured, so you can confirm credentials/reachability without
waiting on a real retention cycle. Secrets (the S3 secret key, the SFTP
password/private key) are encrypted with `SECLOG_MASTER_KEY` — the same
mechanism and the same "write-only, shown once" contract already used
for the LDAP bind password, see Directory sync above.

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
- The Directory feature's LDAP bind password is the one credential in
  SecLog that isn't one-way hashed (it has to be recoverable to
  actually connect), so it's AES-256-GCM encrypted at rest with a
  server-side key (`SECLOG_MASTER_KEY`) that never touches the
  database. Directory sync itself is read-only against LDAP/AD — see
  [Directory sync](#directory-sync-ldap--active-directory).
- Directory login never stores or sees a directory user's real
  password — it's only ever used, once, to bind as that user and
  confirm it's correct. A pre-existing local account always takes
  priority over a same-named directory entry, and directory-backed
  accounts get a fixed placeholder in `password_hash` that can never
  match a real password — see
  [Directory login](#directory-login).
- Viewing ingested logs and the audit trail requires the `admin` role
  or the narrower `auditor` role — a `"user"`-role account can log in
  and manage its own password/MFA, but can't read audit data. See
  [Compliance notes (CJIS)](#compliance-notes-cjis).

## Compliance notes (CJIS)

A few defaults, access rules, and features exist specifically to
satisfy CJIS's AU-family audit controls, not just general good
practice — worth knowing about if you're running SecLog in a CJIS
context:

- **AU-2 / AU-3 / AU-3(1) (event logging & content):** beyond what the
  shipper collects from monitored machines, SecLog keeps its own audit
  trail — every login (success and failure, local or directory), every
  admin action (user/agent/path/settings/notification/directory
  changes), and every read of log data, each with actor, timestamp,
  resource, outcome, and source IP. Viewable at the **Audit Log** page.
  Secrets are never written to it — a directory config change records
  *that* the bind password changed, never the password itself.
- **AU-5 (response to logging failures):** failure conditions raise a
  `[SYSTEM]`-prefixed alert through the same channels configured under
  **Settings → Alerts**: an agent that's gone dark past a configurable
  threshold (**Settings → General → Agent Health**, default 120
  minutes), a failed retention run, log storage crossing 90% of the
  configured row cap, a failed audit-trail write, and a failed integrity
  checkpoint (see AU-9 below) — a broken audit or integrity pipeline is
  exactly the kind of failure this control exists to surface.
- **AU-6 (review):** any log row can be marked **Open**, **Reviewed**,
  or **False Positive** with an investigation note, from its status pill
  in the Dashboard's per-host detail view. Recorded with who reviewed it
  and when — marking a review is itself an audited action.
- **AU-8 (time stamps):** where a line's own timestamp can be recovered
  — auditd's embedded epoch time, a leading ISO8601/RFC3339 stamp (also
  covers macOS's `log stream` format and wevtutil's `Date:` field), or
  classic BSD syslog format — it's stored separately from `created_at`
  (purely when SecLog ingested the row), across all shipper paths
  (Linux file-tailing, Windows Security event log, macOS unified log).
  So a shipper catching up on a backlog after an outage doesn't make
  everything look like it happened at catch-up time. A line with no
  recognizable timestamp still ingests fine; that row just has no
  `event_time`, and falls back to ingestion time as the best available
  signal. Server and reported event time more than 15 minutes apart is
  logged; more than 60 minutes apart also raises a `[SYSTEM]` alert — a
  proxy for detecting NTP drift, since SecLog can't itself enforce time
  sync on a monitored machine.
- **AU-9 (restrict & protect audit information):**
  - *Access*: log viewing — including the audit trail — requires the
    `admin` role, or the narrower `auditor` role (create one from
    **Settings → Security → Users**), which can view and review log/
    audit data but administers nothing else: no agents, no directory,
    no settings, no user management.
  - *Integrity*: `audit_log` (admin actions, logins) is a real hash
    chain — every row cryptographically links to the one before it, so
    an altered or removed row is detectable from that point forward.
    **Verify Chain** on the Audit Log page re-derives every row's hash
    and confirms it. Shipper-ingested `logs` is too high-volume for a
    per-row chain (would serialize every write from every agent), so it
    uses hourly **checkpoints** instead — each covering the hashes of
    everything ingested since the last one. A checkpoint whose rows have
    since been purged by retention reports **Unverifiable** (expected,
    not tampering); one where the still-present rows don't match what
    was checkpointed reports **Broken**. Rows from before this feature
    existed can't be retroactively proven un-tampered — verification
    starts from the first hashed row, honestly, not pretended backward.
- **AU-11 (retention):** `log_retention_days` defaults to **365** on a
  fresh install (the CJIS minimum). This only applies to installs
  created after this default changed — if you installed earlier and
  need the 1-year minimum, update it yourself under **Settings →
  General**; SecLog won't silently change a value you may have
  deliberately set. `max_log_rows` (default 2,000,000) is a hard cap
  independent of age — the AU-5 capacity alert above tells you before it
  starts evicting rows you needed to keep, and now includes the table's
  actual on-disk byte size (read from MariaDB's own metadata — the app
  and database containers don't share a filesystem, so this is the
  accurate way to answer "how much room is this actually taking," not a
  raw host disk-free check from the wrong container).
- **Known limitation:** directory login (see above) only ever assigns
  `admin` or `user` based on AD group membership — a directory group
  can't provision someone straight into `auditor` yet; that role is
  local-admin-assigned only for now.

## Admin-created accounts

Admins can create accounts directly from **Settings → Security** instead
of relying on self-signup. New accounts get a random temporary password
(shown once, copyable) and must set a real password on first login.
