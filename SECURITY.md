# Security Policy

SecLog exists to help people notice intrusions on their own machines, so
its own security bugs matter more than most. Thank you for taking the
time to report one responsibly.

## Supported versions

SecLog is pre-1.0 and released continuously from `main`. Only the latest
tagged release is supported — please upgrade before reporting an issue
if you're running anything older (the dashboard flags when a newer
release is available, see `/version`).

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Use GitHub's private reporting flow instead:
[github.com/AbyssalOath/SecLog/security/advisories/new](https://github.com/AbyssalOath/SecLog/security/advisories/new).
This opens a private discussion with the maintainer that isn't visible
to other GitHub users until a fix is ready.

Please include:

- What you found and where (file/line or endpoint).
- Impact — what an attacker could actually do with it.
- Steps to reproduce, or a minimal PoC if practical.
- Whether it requires authentication (as a user, or as an enrolled
  agent) or is reachable pre-auth.

You should get an initial response within a few days. There's no formal
SLA or bounty program — this is a small, mostly single-maintainer
project — but genuine reports will be taken seriously, fixed, and
credited (unless you'd rather stay anonymous) once a release ships.

## What's in scope

- The server (`seclog` binary): authentication/session handling, MFA,
  agent enrollment and authentication, the HTTP API, the static
  dashboard.
- The shipper binary: how it obtains and stores its API key, how it
  authenticates to the server, and how it handles untrusted input (log
  file content, in particular anything that could turn a log *line* into
  something other than data — e.g. injection into the classification
  pipeline or the outbound request).
- The installer (`install.sh`) and the generated systemd
  unit/PowerShell install scripts served at `/install/linux.sh` and
  `/install/windows.ps1`.
- Docker/Compose configuration as shipped in this repo.

## What's out of scope

- Vulnerabilities that require an attacker to already have your admin
  session, your shipper's `.seclog_agent_key` file, or root/Administrator
  on a box you're monitoring — at that point the machine is already
  compromised.
- Findings that only reproduce against a self-modified deployment (e.g.
  `FRONTEND_ORIGIN` set to `*`, CORS disabled, TLS deliberately skipped).
- Denial of service via raw traffic volume against a box you don't
  control — reasonable-effort DoS *logic* bugs (e.g. an unauthenticated
  endpoint that triggers disproportionate server work) are in scope.
- Third-party dependencies — please report those upstream; we'll pick up
  the fix via a version bump once one's available, and we're happy to be
  pinged if it's exploitable through SecLog specifically.

## Current security posture

For what's already deliberately in place (password hashing, session
model, MFA, rate limiting, the agent auth model, cookie configuration),
see [README § Security notes](README.md#security-notes). That section
is the baseline reviewers and reporters should assume rather than flag
as novel — this file is about *reporting new problems*, not
re-documenting known design decisions.
