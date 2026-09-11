# Contributing to SecLog

Thanks for looking at contributing. This is a fairly small, opinionated
codebase — reading [ARCHITECTURE.md](ARCHITECTURE.md) first will save
you time before diving into `src/`.

## Getting set up

Requirements: a recent Rust toolchain (stable), and either Docker (for
MariaDB) or a MariaDB/MySQL instance you already have.

```bash
git clone https://github.com/AbyssalOath/SecLog.git
cd SecLog
```

The server (`src/main.rs`, via `dotenvy`) reads `DATABASE_URL` and
`FRONTEND_ORIGIN` from a `.env` file in the repo root, or from your
shell's environment — it won't start without both. `./install.sh`
generates a production `.env`; for local development, a quick MariaDB
you can point `DATABASE_URL` at:

```bash
docker run -d --name seclog-dev-db -p 3306:3306 \
  -e MARIADB_ROOT_PASSWORD=devpass -e MARIADB_DATABASE=seclog \
  -e MARIADB_USER=seclog -e MARIADB_PASSWORD=devpass mariadb:11

cat > .env << 'EOF'
DATABASE_URL=mysql://seclog:devpass@127.0.0.1:3306/seclog
FRONTEND_ORIGIN=http://localhost:3000
EOF
```

(`docker-compose.dev.yml` runs the same idea as a full app+DB stack
instead, if you'd rather containerize the server too — it's driven by
the `DEV_*` variables `install.sh` can add to `.env`.) Then:

```bash
cargo run --bin seclog     # server, on :3000
cargo run --bin shipper    # shipper, against a local test file
```

The shipper needs `SHIPPER_API_URL` (defaults to `http://localhost:3000`)
and, on first run only, `SECLOG_ENROLLMENT_TOKEN` — generate one from the
dashboard's **Agents** page, or via `POST /agents/enrollment-token` as an
admin.

## Before you open a PR

```bash
cargo build           # both binaries
cargo clippy --all-targets
```

There's no automated test suite yet — a PR that adds meaningful test
coverage for something previously untested is welcome on its own, not
just as a companion to a fix. In its absence, please describe how you
manually verified a change (server: which endpoints/flows you exercised;
shipper: which OS, which log format, what you watched happen end-to-end
in the dashboard).

## Code style

- Follow the existing style in the file you're editing over a
  general Rust style guide — this codebase favors explicit `match`
  over combinators in most handler code, and comments that explain
  *why*, not *what*. Look at a neighboring function before introducing
  a new pattern.
- Keep comments load-bearing: explain a non-obvious constraint, a
  workaround, or a decision someone could otherwise plausibly "fix"
  into a bug — not what a well-named function already says.
- `cargo clippy` should stay clean for anything you touch. Pre-existing
  warnings elsewhere aren't your problem to fix in an unrelated PR, but
  don't add new ones.

## Adding a detection rule (`src/parser.rs`)

Read the ordering comment at the top of `rules()` before adding
anything — rules are checked top to bottom and the first match wins, so
a new specific pattern placed after an existing broad one (e.g. the
`DENY|DROP` catch-all) will never actually fire. State which OS/log
source your rule targets and, ideally, a real (or realistic,
anonymized) sample line in the PR description.

## Adding a notification channel (`src/notify.rs`)

Each channel kind is: a config struct in `models.rs`
(`#[derive(Serialize, Deserialize)]`), a `send_<kind>` function in
`notify.rs` matching the existing ones' shape (parse config, build
payload, POST, map a non-2xx response to an `Err`), a new arm in
`dispatch()`, and adding the kind's string to the `valid_kinds` array in
`main.rs`'s `create_notification_channel_handler`. The frontend's
Settings → Alerts tab needs a matching form fragment.

## Database changes

Schema lives in `db.rs`'s `init_*_schema` functions, applied on every
server startup — there's no separate migration runner. New columns/
tables must be added the same idempotent way (`CREATE TABLE IF NOT
EXISTS`, `ADD COLUMN IF NOT EXISTS`), since these functions run
unconditionally against installs that may already have the old schema.
If you're changing the *meaning* of existing data (not just adding a
column), see `db::init_schema`'s `level` → `severity` migration for the
pattern: detect the old shape, migrate it once, log what happened.

## Environment variables

Nobody running `install.sh` should ever have to hand-edit `.env`. If
your change adds a new environment variable that the server reads
(directly via `env::var`, or indirectly because it's now in
`docker-compose.yml`'s `environment:` block):

1. Add it to `docker-compose.yml` (and `docker-compose.dev.yml`, if the
   dev stack needs it too).
2. Add a block to `install.sh` that generates it (a secret — follow the
   `SECLOG_MASTER_KEY`/`DB_PASS` pattern, `openssl rand`) or prompts for
   it (anything requiring a human decision — follow the
   `FRONTEND_ORIGIN`/Caddy-choice pattern, `read -rp`). Same idempotent
   shape as every existing block: check whether it's already in `.env`
   first, only act if it's missing, so re-running `install.sh` on an
   existing install is always safe.
3. If it's optional (most things past the original `DATABASE_URL`/
   `FRONTEND_ORIGIN` pair should be), read it with `env::var(...).ok()`
   or similar in Rust, not `.expect(...)` — an existing deployment that
   never touches your new feature shouldn't fail to boot over it. See
   `crypto::MasterKey::from_env` for the pattern.

`install.sh` has a safety-net check (search it for "Safety net") that
warns if `docker-compose.yml`/`docker-compose.dev.yml` reference a
variable `.env` doesn't have — it exists to catch step 2 being missed,
not to replace it. A warning during someone's install is a much worse
experience than the gap never existing.

## Shipper changes

The shipper runs unattended, on machines you may not be able to easily
SSH into, printing to whatever `journalctl`/Event Viewer/Console.app
shows. Prefer failure modes that are loud in logs and safe in behavior
(retry, reconnect, skip-and-continue) over ones that silently drop data
or crash the process. If you touch the file-tailing logic in
`watch_file`, pay particular attention to exact byte-position accounting
— an off-by-one there either re-ships duplicate content or silently
skips a byte of the next line, and it won't show up until someone's
staring at a gap in their logs (see the `CHANGELOG.md` entry on exactly
this).

## Commit messages / PRs

Keep the "why" in the message, not just the "what" — the diff already
shows what changed. Small, focused PRs over one PR touching the server,
shipper, and frontend at once, unless the change genuinely can't be
split (e.g. a wire-format change to `models.rs` that both sides must
adopt together).

## License

SecLog is licensed under AGPL-3.0 (see [LICENSE](LICENSE)). By
contributing, you agree your contribution is licensed under the same
terms.
