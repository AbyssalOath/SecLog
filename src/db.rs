use crate::auth;
use crate::models::LogRow;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use chrono::{DateTime, SubsecRound, Utc, Duration};

// A type aloas -- just a shorter name for a long type, purely for readability.
pub type DbPool = MySqlPool;

pub async fn create_pool(db_url: &str) -> Result<DbPool, sqlx::Error> {
    MySqlPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
}

pub async fn init_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            severity VARCHAR(10) NOT NULL,
            user VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            host VARCHAR(255) NOT NULL DEFAULT 'unknown',
            line_hash CHAR(64) NOT NULL,
            UNIQUE KEY unique_line (line_hash)
        )"
    )
    .execute(pool)
    .await?;

    // Migration: older installs have a `level` column with old values
    // (Info/Warn/Error). Detect it via information_schema and migrate
    // once -- this only runs on databases that predate this change.
    let level_exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema = DATABASE() AND table_name = 'logs' AND column_name = 'level'"
    )
    .fetch_one(pool)
    .await?;

    if level_exists.0 > 0 {
        sqlx::query("ALTER TABLE logs CHANGE COLUMN level severity VARCHAR(10) NOT NULL")
            .execute(pool)
            .await?;

        sqlx::query("UPDATE logs SET severity = 'Low' WHERE severity = 'Info'").execute(pool).await?;
        sqlx::query("UPDATE logs SET severity = 'Medium' WHERE severity = 'Warn'").execute(pool).await?;
        sqlx::query("UPDATE logs SET severity = 'High' WHERE severity = 'Error'").execute(pool).await?;

        println!("Migrated logs.level -> logs.severity, remapped old values");
    }

    // Idempotent -- safe to run every startup even on an existing table
    // (covers installs from before `host` existed at all).
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS host VARCHAR(255) NOT NULL DEFAULT 'unknown'")
        .execute(pool)
        .await?;

    // Same idea, for installs that predate retention support -- needed so
    // delete_logs_older_than has something to compare against.
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP")
        .execute(pool)
        .await?;
 
    // Index for the dashboard's host-summary GROUP BY and per-host
    // pagination -- without this, both scale linearly with total table
    // size instead of the size of one host's rows.
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host)")
        .execute(pool)
        .await
        .ok(); // MariaDB lacks IF NOT EXISTS for indexes on some versions; ignore "already exists"

    // CJIS AU-8: the event's OWN timestamp, recovered from the source
    // line where possible (parser::extract_event_time) -- distinct from
    // `created_at`, which is purely when SecLog happened to insert the
    // row. NULL means no recognized timestamp was found in that line.
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS event_time TIMESTAMP NULL")
        .execute(pool)
        .await?;

    // CJIS AU-6: review/investigation state. No FK on reviewed_by --
    // same reasoning as audit_log.actor_user_id below: deleting a user
    // must never cascade-delete or block on records that reference them.
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS review_status VARCHAR(20) NOT NULL DEFAULT 'open'")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS reviewed_by INT NULL")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP NULL")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE logs ADD COLUMN IF NOT EXISTS review_note TEXT NULL")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn init_users_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE")
        .execute(pool)
        .await?;

    // 'local' (a password SecLog itself verifies) or 'ldap' (verified
    // live against the directory on every login -- see directory.rs's
    // authenticate_user and login() in main.rs). Every row that already
    // existed before this column was added is 'local', which is exactly
    // right: it's what they always were.
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source VARCHAR(10) NOT NULL DEFAULT 'local'")
        .execute(pool)
        .await?;

    Ok(())
}

// Returns true of a new row was actually inserted, false if it was a duplicate.
#[allow(clippy::too_many_arguments)]
pub async fn insert_log(
    pool: &DbPool,
    severity: &str,
    user: &str,
    message: &str,
    host: &str,
    hash: &str,
    event_time: Option<DateTime<Utc>>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT IGNORE INTO logs (severity, user, message, host, line_hash, event_time)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(severity)
    .bind(user)
    .bind(message)
    .bind(host)
    .bind(hash)
    .bind(event_time)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_all_logs(pool: &DbPool) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, severity, user, message, host FROM logs")
        .fetch_all(pool)
        .await
}

// One row per distinct host, with a breakdown by severity. This is what
// the dashboard's host-summary view is built from -- deliberately never
// pulls message text, so this stays cheap even with millions of rows.
pub async fn get_host_summary(pool: &DbPool) -> Result<Vec<crate::models::HostSummaryRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT host,
                COUNT(*) AS total,
                CAST(SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS SIGNED) AS critical,
                CAST(SUM(CASE WHEN severity = 'High'     THEN 1 ELSE 0 END) AS SIGNED) AS high,
                CAST(SUM(CASE WHEN severity = 'Medium'   THEN 1 ELSE 0 END) AS SIGNED) AS medium,
                CAST(SUM(CASE WHEN severity = 'Low'      THEN 1 ELSE 0 END) AS SIGNED) AS low
         FROM logs
         GROUP BY host
         ORDER BY critical DESC, high DESC, medium DESC, total DESC",
    )
    .fetch_all(pool)
    .await
}

// Paginated, most-severe-first log listing for a single host -- what the
// dashboard's drill-down view fetches a page at a time, instead of ever
// loading a host's full history into the browser at once. LEFT JOINs
// users for reviewed_by's display name (CJIS AU-6 wants review
// "documented," and a raw user_id isn't very documenting) -- LEFT, not
// INNER, so a row reviewed by a since-deleted user still shows up.
pub async fn get_logs_for_host(
    pool: &DbPool,
    host: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT logs.id, logs.severity, logs.user, logs.message, logs.host,
                logs.event_time, logs.review_status, logs.reviewed_at, logs.review_note,
                reviewer.username AS reviewed_by_username
         FROM logs
         LEFT JOIN users AS reviewer ON logs.reviewed_by = reviewer.id
         WHERE logs.host = ?
         ORDER BY FIELD(logs.severity, 'Critical', 'High', 'Medium', 'Low'), logs.id DESC
         LIMIT ? OFFSET ?",
    )
    .bind(host)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn count_logs_for_host(pool: &DbPool, host: &str) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM logs WHERE host = ?")
        .bind(host)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

// Total row count across every host -- used by the retention loop to
// check utilization against max_log_rows (CJIS AU-11's "periodically
// review storage availability"), not by anything host-scoped.
pub async fn count_all_logs(pool: &DbPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM logs")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

// CJIS AU-6: records a review/investigation outcome on one log row.
// `status` is validated by the caller (set_log_review_handler in
// main.rs), not here -- db.rs stays a thin SQL layer.
pub async fn set_log_review(
    pool: &DbPool,
    log_id: i32,
    reviewer_user_id: i32,
    status: &str,
    note: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE logs SET review_status = ?, reviewed_by = ?, reviewed_at = NOW(), review_note = ?
         WHERE id = ?",
    )
    .bind(status)
    .bind(reviewer_user_id)
    .bind(note)
    .bind(log_id)
    .execute(pool)
    .await?;
    Ok(())
}

// --- Tamper-evidence for `logs` (CJIS AU-9) ---
//
// `logs` gets no per-row hash chain -- unlike audit_log, it's the
// system's actual write-throughput target (one insert per shipper per
// line; the 600k-row-crash and row-cap work elsewhere in this file
// exist because of exactly this table's volume). Serializing every
// insert on "read the previous row's hash" would bottleneck the
// system's hottest path. Instead, a periodic (hourly, see main.rs)
// CHECKPOINT hashes a whole range of already-inserted rows at once,
// using each row's existing line_hash (see parser::hash_line) --
// tampering with, or unexpectedly losing, any row in an already-
// checkpointed range changes the recomputed hash and is caught the
// next time that checkpoint's status is read.
pub async fn init_log_checkpoints_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS log_checkpoints (
            id INT AUTO_INCREMENT PRIMARY KEY,
            range_start_id INT NOT NULL,
            range_end_id INT NOT NULL,
            row_count INT NOT NULL,
            checkpoint_hash CHAR(64) NOT NULL,
            computed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

// Hashes every `logs` row with id in (last checkpoint's range_end_id,
// current MAX(id)] and stores the result. Returns None when there's
// nothing new to checkpoint (no rows at all, or none since the last
// checkpoint) -- not an error, just nothing to do this cycle.
pub async fn create_log_checkpoint(pool: &DbPool) -> Result<Option<(i32, i32, i64)>, sqlx::Error> {
    let last_end: Option<i32> = sqlx::query_scalar("SELECT MAX(range_end_id) FROM log_checkpoints")
        .fetch_one(pool)
        .await?;
    let range_start = last_end.unwrap_or(0) + 1;

    let max_id: Option<i32> = sqlx::query_scalar("SELECT MAX(id) FROM logs").fetch_one(pool).await?;
    let Some(max_id) = max_id else {
        return Ok(None);
    };
    if max_id < range_start {
        return Ok(None);
    }

    let hashes: Vec<String> =
        sqlx::query_scalar("SELECT line_hash FROM logs WHERE id >= ? AND id <= ? ORDER BY id ASC")
            .bind(range_start)
            .bind(max_id)
            .fetch_all(pool)
            .await?;
    let row_count = hashes.len() as i64;
    let checkpoint_hash = crate::parser::hash_line(&hashes.join("\u{1f}"));

    sqlx::query(
        "INSERT INTO log_checkpoints (range_start_id, range_end_id, row_count, checkpoint_hash)
         VALUES (?, ?, ?, ?)",
    )
    .bind(range_start)
    .bind(max_id)
    .bind(row_count)
    .bind(&checkpoint_hash)
    .execute(pool)
    .await?;

    Ok(Some((range_start, max_id, row_count)))
}

#[derive(Debug, serde::Serialize)]
pub struct CheckpointStatus {
    pub id: i32,
    pub range_start_id: i32,
    pub range_end_id: i32,
    pub row_count: i64,
    pub computed_at: DateTime<Utc>,
    // "verified" (still matches), "broken" (content differs from what
    // was checkpointed), or "unverifiable" (some rows in this range are
    // gone -- normal retention, not evidence of tampering by itself).
    pub status: String,
}

// Re-verifies every stored checkpoint against the CURRENT contents of
// `logs`. A checkpoint whose range has been fully or partially purged
// by retention reports "unverifiable," never "broken" -- those are
// deliberately different signals, so routine retention is never mistaken
// for tampering. Bounded by `limit` (checkpoints are hourly, so this
// stays small in practice) -- re-hashes each checkpoint's range on every
// call, which is fine at this cadence but not something to call in a tight loop.
pub async fn list_log_checkpoints_with_status(
    pool: &DbPool,
    limit: i64,
) -> Result<Vec<CheckpointStatus>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: i32,
        range_start_id: i32,
        range_end_id: i32,
        row_count: i64,
        checkpoint_hash: String,
        computed_at: DateTime<Utc>,
    }

    let checkpoints: Vec<Row> = sqlx::query_as(
        "SELECT id, range_start_id, range_end_id, row_count, checkpoint_hash, computed_at
         FROM log_checkpoints ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut results = Vec::with_capacity(checkpoints.len());
    for cp in checkpoints {
        let hashes: Vec<String> =
            sqlx::query_scalar("SELECT line_hash FROM logs WHERE id >= ? AND id <= ? ORDER BY id ASC")
                .bind(cp.range_start_id)
                .bind(cp.range_end_id)
                .fetch_all(pool)
                .await?;

        let status = match (hashes.len() as i64).cmp(&cp.row_count) {
            std::cmp::Ordering::Less => "unverifiable",
            std::cmp::Ordering::Equal => {
                let recomputed = crate::parser::hash_line(&hashes.join("\u{1f}"));
                if recomputed == cp.checkpoint_hash { "verified" } else { "broken" }
            }
            // More rows than were checkpointed shouldn't happen -- ids
            // in a fixed range never grow after the fact -- but treat
            // it as suspicious rather than silently ignoring it.
            std::cmp::Ordering::Greater => "broken",
        };

        results.push(CheckpointStatus {
            id: cp.id,
            range_start_id: cp.range_start_id,
            range_end_id: cp.range_end_id,
            row_count: cp.row_count,
            computed_at: cp.computed_at,
            status: status.to_string(),
        });
    }

    Ok(results)
}

// CJIS AU-11: real on-disk byte size of a table, straight from
// MariaDB's own metadata -- no filesystem access needed (and none
// available anyway: the `app` container doesn't share a volume with
// `mariadb`, so a raw disk-free check from here would be checking the
// wrong, irrelevant filesystem). Returns 0 if the table doesn't exist
// rather than erroring, since this is purely informational.
pub async fn get_table_size_bytes(pool: &DbPool, table_name: &str) -> Result<i64, sqlx::Error> {
    let row: Option<(Option<i64>,)> = sqlx::query_as(
        "SELECT CAST(data_length + index_length AS SIGNED)
         FROM information_schema.tables
         WHERE table_schema = DATABASE() AND table_name = ?",
    )
    .bind(table_name)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(v,)| v).unwrap_or(0))
}

// Storage mitigation, part 1: age-based retention. Runs on a schedule
// from main() using the configurable log_retention_days setting.
pub async fn delete_logs_older_than(pool: &DbPool, days: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM logs WHERE created_at < (NOW() - INTERVAL ? DAY)")
        .bind(days)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

// Storage mitigation, part 2: a hard row-count ceiling, independent of
// age. This is the backstop for exactly the scenario that caused this --
// a bug (or a genuinely noisy source) producing rows faster than any
// reasonable retention window would clear them. Deletes the oldest rows
// once the table exceeds max_rows, keeping the most recent max_rows.
pub async fn enforce_max_log_rows(pool: &DbPool, max_rows: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM logs WHERE id <= (
             SELECT id FROM (
                 SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?
             ) AS cutoff
         )",
    )
    .bind(max_rows)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// Returns true if the user was created, false if the username was taken.
pub async fn create_user(
    pool: &DbPool,
    username: &str,
    password_hash: &str,
) -> Result<Option<i32>, sqlx::Error> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    let is_bootstrap = count.0 == 0;
    let role = if is_bootstrap { "admin" } else { "user" };

    let result = sqlx::query(
        "INSERT IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role)
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        if is_bootstrap {
            set_self_signup_enabled(pool, false).await?;
        }
        Ok(Some(result.last_insert_id() as i32))
    } else {
        Ok(None)
    }
}

pub async fn create_user_with_role(
    pool: &DbPool,
    username: &str,
    password_hash: &str,
    role: &str,
) -> Result<Option<i32>, sqlx::Error> {
    let result = sqlx::query(
        "INSERT IGNORE INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, TRUE)",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role)
    .execute(pool)
    .await?;

    if result.rows_affected() > 0 {
        Ok(Some(result.last_insert_id() as i32))
    } else {
        Ok(None)
    }
}

// Fetches a user's stored hash by username, for login verification.
// Returns None if no such user exists -- Option, not Result, becuase
// "user not found" isn't an error, it's a valid outcome we need to handle.
pub async fn get_password_hash(
    pool: &DbPool,
    username: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(pool)
            .await?;

    Ok(row.map(|(hash,)| hash))
}

pub async fn init_sessions_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token CHAR(64) PRIMARY KEY,
            user_id INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_session(
    pool: &DbPool,
    token: &str,
    user_id: i32,
) -> Result<(), sqlx::Error> {
    let expires_at = Utc::now() + Duration::hours(24);

    let token_hash = auth::hash_token(token);

    sqlx::query(
        "INSERT INTO sessions (token, user_id, expires_at)
         VALUES (?, ?, ?)"
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

// Given a token, returns the associated user's id, username, and role --
// but ONLY if the session exists AND hasn't expired. This is the function
// every protected endpoint will ultimately rely on.
pub async fn get_session_user(
    pool: &DbPool,
    token: &str,
) -> Result<Option<(i32, String, String, bool)>, sqlx::Error> {
    let token_hash = auth::hash_token(token);

    sqlx::query_as(
        "SELECT users.id, users.username, users.role, users.must_change_password
         FROM sessions
         JOIN users ON sessions.user_id = users.id
         WHERE sessions.token = ? AND sessions.expires_at > NOW()",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserLoginRow {
    pub id: i32,
    pub password_hash: String,
    pub must_change_password: bool,
    pub mfa_enabled: bool,
    pub auth_source: String,
}

pub async fn get_user_for_login(
    pool: &DbPool,
    username: &str,
) -> Result<Option<UserLoginRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, password_hash, must_change_password, mfa_enabled, auth_source FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

// JIT-provisions a directory-backed account on first successful login
// (see login() in main.rs) -- a plain INSERT, not an upsert. The caller
// only reaches here after confirming via get_user_for_login that no row
// exists for this username yet, so this is a fresh row every time it's
// actually called; the UNIQUE constraint on username makes the rare
// concurrent-signup race fail the INSERT (and thus the login) instead
// of silently colliding with whatever landed first.
pub async fn create_ldap_user(pool: &DbPool, username: &str, role: &str) -> Result<i32, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, role, auth_source, must_change_password)
         VALUES (?, ?, ?, 'ldap', FALSE)",
    )
    .bind(username)
    .bind(auth::LDAP_MANAGED_PASSWORD_SENTINEL)
    .bind(role)
    .execute(pool)
    .await?;
    Ok(result.last_insert_id() as i32)
}

// Re-synces an LDAP-backed account's role from the directory on every
// login (see login() in main.rs) -- the `auth_source = 'ldap'` guard
// means this can never touch a local account's role, even if a future
// bug passed it the wrong user_id.
pub async fn update_ldap_user_role(pool: &DbPool, user_id: i32, role: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET role = ? WHERE id = ? AND auth_source = 'ldap'")
        .bind(role)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct UserRow {
    pub id: i32,
    pub username: String,
    pub role: String,
    pub auth_source: String,
}

pub async fn get_all_users(pool: &DbPool) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, role, auth_source FROM users")
        .fetch_all(pool)
        .await
}

// mfa_secret/mfa_enabled live on `users` directly (one TOTP secret per
// account, same lifecycle as the password). mfa_pending is separate from
// `sessions` on purpose -- a pending row proves "password checked out",
// not "logged in", and must never be usable as a session token itself.
pub async fn init_mfa_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64) NULL")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mfa_pending (
            token CHAR(64) PRIMARY KEY,
            user_id INT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn init_settings_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS settings (
            id INT PRIMARY KEY DEFAULT 1,
            self_signup_enabled BOOLEAN NOT NULL DEFAULT TRUE
        )",
    )
    .execute(pool)
    .await?;

    // Ensure exactly one settings row always exists, so reads never fail.
    sqlx::query("INSERT IGNORE INTO settings (id, self_signup_enabled) VALUES (1, TRUE)")
        .execute(pool)
        .await?;

    // Retention defaults: 365 days (the CJIS AU-11 minimum -- this used
    // to default to 30, which was non-compliant out of the box for any
    // deployment subject to that policy; see README), capped at 2 million
    // rows regardless of age. The row cap is the important one for a
    // runaway-source scenario like a feedback loop -- it can fill a disk
    // in hours, well inside any reasonable day-based window. Only applies
    // to fresh installs -- ADD COLUMN IF NOT EXISTS is a no-op against a
    // database that already has this column, so an existing install that
    // needs the new minimum has to update it via Settings once.
    sqlx::query("ALTER TABLE settings ADD COLUMN IF NOT EXISTS log_retention_days INT NOT NULL DEFAULT 365")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE settings ADD COLUMN IF NOT EXISTS max_log_rows BIGINT NOT NULL DEFAULT 2000000")
        .execute(pool)
        .await?;

    // CJIS AU-5: how long an agent can go without checking in before
    // it's treated as "gone dark" and alerted on -- see
    // find_newly_stale_agents and the staleness loop in main().
    sqlx::query("ALTER TABLE settings ADD COLUMN IF NOT EXISTS stale_agent_minutes INT NOT NULL DEFAULT 120")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_self_signup_enabled(pool: &DbPool) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT self_signup_enabled FROM settings WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn set_self_signup_enabled(pool: &DbPool, enabled:bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE settings SET self_signup_enabled = ? WHERE id = 1")
        .bind(enabled)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_retention_settings(pool: &DbPool) -> Result<(i64, i64), sqlx::Error> {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT log_retention_days, max_log_rows FROM settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

pub async fn set_retention_settings(
    pool: &DbPool,
    log_retention_days: i64,
    max_log_rows: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE settings SET log_retention_days = ?, max_log_rows = ? WHERE id = 1")
        .bind(log_retention_days)
        .bind(max_log_rows)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_stale_agent_minutes(pool: &DbPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT stale_agent_minutes FROM settings WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

pub async fn set_stale_agent_minutes(pool: &DbPool, minutes: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE settings SET stale_agent_minutes = ? WHERE id = 1")
        .bind(minutes)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_expired_sessions(pool: &DbPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn delete_session(
    pool: &DbPool,
    token: &str,
) -> Result<(), sqlx::Error> {
    let token_hash = auth::hash_token(token);

    sqlx::query("DELETE FROM sessions WHERE token = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;

    Ok(())
}

// Stores a freshly generated secret as "pending" -- mfa_enabled stays
// FALSE until confirm_mfa_enabled proves the user's app can actually
// generate a matching code. Prevents locking someone out of their own
// account by flipping mfa_enabled before setup is verified.
pub async fn set_pending_mfa_secret(
    pool: &DbPool,
    user_id: i32,
    secret_hex: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET mfa_secret = ?, mfa_enabled = FALSE WHERE id = ?")
        .bind(secret_hex)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn confirm_mfa_enabled(pool: &DbPool, user_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET mfa_enabled = TRUE WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn disable_mfa(pool: &DbPool, user_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_mfa_secret(pool: &DbPool, user_id: i32) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT mfa_secret FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(s,)| s))
}

pub async fn get_mfa_enabled(pool: &DbPool, user_id: i32) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT mfa_enabled FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

// Bridges "password just verified" and "TOTP just verified" during a
// two-step login. Deliberately hashed and short-lived like a session
// token, but stored separately -- it must never be usable as a session
// itself, only as proof the first factor already passed for this user.
pub async fn create_mfa_pending(
    pool: &DbPool,
    token: &str,
    user_id: i32,
) -> Result<(), sqlx::Error> {
    let expires_at = Utc::now() + Duration::minutes(5);
    let token_hash = auth::hash_token(token);

    sqlx::query("INSERT INTO mfa_pending (token, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

// Looks up (without consuming) the user behind a pending-MFA token, if it
// exists and hasn't expired. Deliberately non-destructive -- a mistyped
// TOTP code shouldn't burn the token, since the person still has up to
// the 5-minute window to try again. Only delete_mfa_pending (called on a
// verified code) actually consumes it.
pub async fn get_mfa_pending(
    pool: &DbPool,
    token: &str,
) -> Result<Option<(i32, String, bool)>, sqlx::Error> {
    let token_hash = auth::hash_token(token);

    sqlx::query_as(
        "SELECT mfa_pending.user_id, users.username, users.must_change_password
         FROM mfa_pending
         JOIN users ON mfa_pending.user_id = users.id
         WHERE mfa_pending.token = ? AND mfa_pending.expires_at > NOW()",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

// One-shot consumption -- call this only once the TOTP code has actually
// been verified, so the pending token (and thus this login attempt)
// can't be reused for a second session.
pub async fn delete_mfa_pending(pool: &DbPool, token: &str) -> Result<(), sqlx::Error> {
    let token_hash = auth::hash_token(token);
    sqlx::query("DELETE FROM mfa_pending WHERE token = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_expired_mfa_pending(pool: &DbPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM mfa_pending WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn init_agents_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agents (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            api_key CHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP NULL
        )",
    )
    .execute(pool)
    .await?;

    // CJIS AU-5: tracks whether the "this agent has gone dark" alert has
    // already fired for the CURRENT staleness episode, so the
    // staleness-check loop in main.rs fires once per episode instead of
    // on every sweep. Cleared by touch_agent_last_seen, so a recovered
    // agent that later goes dark again alerts a second, independent time.
    sqlx::query("ALTER TABLE agents ADD COLUMN IF NOT EXISTS stale_alert_sent BOOLEAN NOT NULL DEFAULT FALSE")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn init_watched_paths_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS watched_paths (
            id INT AUTO_INCREMENT PRIMARY KEY,
            agent_id INT NOT NULL,
            path VARCHAR(1024) NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct AgentRow {
    pub id: i32,
    pub hostname: String,
    pub last_seen: Option<chrono::DateTime<Utc>>,
}

pub async fn create_agent(
    pool: &DbPool,
    hostname: &str,
    api_key: &str,
) -> Result<i32, sqlx::Error> {
    let api_key_hash = auth::hash_token(api_key);

    let result = sqlx::query(
        "INSERT INTO agents (hostname, api_key) VALUES (?, ?)"
    )
    .bind(hostname)
    .bind(api_key_hash)
    .execute(pool)
    .await?;

    Ok(result.last_insert_id() as i32)
}

// Looks up an agent by its API key -- this is the core check AgentAuth
// relies on for every authenticated request from a shipper.
pub async fn get_agent_by_key(
    pool: &DbPool,
    api_key: &str,
) -> Result<Option<(i32, String)>, sqlx::Error> {
    let api_key_hash = auth::hash_token(api_key);

    sqlx::query_as(
        "SELECT id, hostname FROM agents WHERE api_key = ?"
    )
    .bind(api_key_hash)
    .fetch_optional(pool)
    .await
}

pub async fn touch_agent_last_seen(pool: &DbPool, agent_id: i32) -> Result<(), sqlx::Error> {
    // Clearing stale_alert_sent here (not just bumping last_seen) is
    // what makes a recovered-then-relapsed agent alert again -- see the
    // column's comment in init_agents_schema.
    sqlx::query("UPDATE agents SET last_seen = NOW(), stale_alert_sent = FALSE WHERE id = ?")
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

// CJIS AU-5: agents that were seen before but have gone quiet past the
// configured threshold, and haven't already been alerted on for this
// episode. Agents that have NEVER checked in (last_seen IS NULL) are
// deliberately excluded -- that's the normal state right after
// enrollment, not a failure.
pub async fn find_newly_stale_agents(pool: &DbPool, threshold_minutes: i64) -> Result<Vec<AgentRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, hostname, last_seen FROM agents
         WHERE last_seen IS NOT NULL
           AND last_seen < (NOW() - INTERVAL ? MINUTE)
           AND stale_alert_sent = FALSE",
    )
    .bind(threshold_minutes)
    .fetch_all(pool)
    .await
}

pub async fn mark_agent_stale_alerted(pool: &DbPool, agent_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agents SET stale_alert_sent = TRUE WHERE id = ?")
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct WatchedPathRow {
    pub id: i32,
    pub path: String,
    pub enabled: bool,
}

pub async fn add_watched_path(
    pool: &DbPool,
    agent_id: i32,
    path: &str,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query("INSERT INTO watched_paths (agent_id, path) VALUES (?, ?)")
        .bind(agent_id)
        .bind(path)
        .execute(pool)
        .await?;
    Ok(result.last_insert_id() as i32)
}

pub async fn get_watched_paths(
    pool: &DbPool,
    agent_id: i32,
) -> Result<Vec<WatchedPathRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, path, enabled FROM watched_paths WHERE agent_id =?")
        .bind(agent_id)
        .fetch_all(pool)
        .await
}

// Only the ENABLED paths -- this is what the agent's config-fetch actually
// needs, versus the admin UI which needs to see disabled ones too (so it
// can offer to re-enable them).
pub async fn get_enabled_paths(
    pool: &DbPool,
    agent_id: i32,
) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT path FROM watched_paths WHERE agent_id = ? AND enabled = TRUE",
    )
    .bind(agent_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(p,)| p).collect())
}

pub async fn set_path_enabled(
    pool: &DbPool,
    path_id: i32,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE watched_paths SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(path_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_watched_path(pool: &DbPool, path_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM watched_paths WHERE id = ?")
        .bind(path_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_all_agents(pool: &DbPool) -> Result<Vec<AgentRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, hostname, last_seen FROM agents")
        .fetch_all(pool)
        .await
}

pub async fn update_password(pool: &DbPool, user_id: i32, new_hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash = ?, must_change_password = FALSE WHERE id = ?")
        .bind(new_hash)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

// Sessions reference users via a FOREIGN KEY -- must clear those first,
// or the DELETE on users would fail with a constraint violation.
pub async fn delete_user(pool: &DbPool, user_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?").bind(user_id).execute(pool).await?;
    sqlx::query("DELETE FROM users WHERE id = ?").bind(user_id).execute(pool).await?;
    Ok(())
}

pub async fn delete_agent(pool: &DbPool, agent_id: i32) -> Result<(), sqlx::Error> {
    // watched_paths references agents via a FOREIGN KEY -- clear those
    // first, or the DELETE on agents would fail with a constraint violation.
    sqlx::query("DELETE FROM watched_paths WHERE agent_id = ?")
        .bind(agent_id)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM agents WHERE id = ?")
        .bind(agent_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn init_enrollment_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS enrollment_tokens (
            token CHAR(64) PRIMARY KEY,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP NULL
        )",
    )
    .execute(pool)
    .await?;

    // Generalizes this table to also back multi-use, time-limited
    // "deployment package" tokens (see directory.rs's Windows
    // unattended install script) without disturbing today's single-use
    // ones -- every existing/new admin-issued token via
    // create_enrollment_token still gets max_uses=1, no expiry, exactly
    // today's behavior. `id` is a clean integer handle for the admin
    // UI to reference/revoke a token by, without needing its hash (the
    // existing PK) in a URL path.
    sqlx::query("ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS id INT AUTO_INCREMENT UNIQUE")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS max_uses INT NOT NULL DEFAULT 1")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS use_count INT NOT NULL DEFAULT 0")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP NULL")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS label VARCHAR(255) NULL")
        .execute(pool)
        .await?;

    // One-time backfill: a token that was already used under the old
    // used_at-only model needs use_count=1 too, or the new
    // use_count < max_uses check would treat it as fresh again. Safe to
    // run every startup -- only matches rows the migration hasn't
    // already fixed.
    sqlx::query("UPDATE enrollment_tokens SET use_count = 1 WHERE used_at IS NOT NULL AND use_count = 0")
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn create_enrollment_token(
    pool: &DbPool,
    token: &str,
) -> Result<(), sqlx::Error> {
    let token_hash = auth::hash_token(token);

    // max_uses/use_count/expires_at/label all take their column
    // defaults (1/0/NULL/NULL) -- today's single-use, no-expiry,
    // unlabeled token, unchanged.
    sqlx::query("INSERT INTO enrollment_tokens (token) VALUES (?)")
        .bind(token_hash)
        .execute(pool)
        .await?;

    Ok(())
}

// Backs the Directory page's "Deployment Packages" panel -- a token
// that can enroll up to `max_uses` machines within `expires_days`,
// labeled (not enforced -- see the comment on the caller) with
// whatever the admin picked, e.g. an OU name. Returns the new token's
// row id so the caller can hand it back for immediate display.
pub async fn create_bulk_enrollment_token(
    pool: &DbPool,
    token: &str,
    max_uses: i64,
    expires_days: i64,
    label: Option<&str>,
) -> Result<i32, sqlx::Error> {
    let token_hash = auth::hash_token(token);

    let result = sqlx::query(
        "INSERT INTO enrollment_tokens (token, max_uses, expires_at, label)
         VALUES (?, ?, NOW() + INTERVAL ? DAY, ?)",
    )
    .bind(token_hash)
    .bind(max_uses)
    .bind(expires_days)
    .bind(label)
    .execute(pool)
    .await?;

    Ok(result.last_insert_id() as i32)
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct EnrollmentTokenRow {
    pub id: i32,
    pub label: Option<String>,
    pub max_uses: i64,
    pub use_count: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// Every token that has an id -- i.e. every token created since the
// max_uses/label columns existed. Pre-migration single-use tokens
// (id NULL, since AUTO_INCREMENT only backfills NEW rows, not existing
// ones) predate any admin-facing token *management* UI and were always
// single-use/unlabeled anyway, so there's nothing meaningful to show
// for them here.
pub async fn list_enrollment_tokens(pool: &DbPool) -> Result<Vec<EnrollmentTokenRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, label, max_uses, use_count, created_at, expires_at
         FROM enrollment_tokens
         WHERE id IS NOT NULL
         ORDER BY id DESC",
    )
    .fetch_all(pool)
    .await
}

// Kills a token immediately without deleting its row -- keeps it in
// list_enrollment_tokens for the admin's own history instead of making
// it vanish. LEAST(...) so revoking an already-expired (or already-
// revoked) token is a harmless no-op, never an accidental extension.
pub async fn revoke_enrollment_token(pool: &DbPool, id: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE enrollment_tokens
         SET expires_at = LEAST(COALESCE(expires_at, NOW()), NOW())
         WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

// Returns true if the token existed, wasn't expired, and had uses
// remaining (and atomically records this use via the UPDATE's row
// count). Single condition covers both single-use tokens
// (max_uses=1, today's exact behavior) and multi-use "deployment
// package" tokens uniformly -- MySQL/MariaDB evaluates the WHERE
// against the row's locked current state, so concurrent enrollments
// against the same bulk token can't both succeed past max_uses.
pub async fn consume_enrollment_token(
    pool: &DbPool,
    token: &str,
) -> Result<bool, sqlx::Error> {
    let token_hash = auth::hash_token(token);

    let result = sqlx::query(
        "UPDATE enrollment_tokens
         SET use_count = use_count + 1, used_at = NOW()
         WHERE token = ? AND use_count < max_uses AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn init_notifications_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notification_channels (
            id INT AUTO_INCREMENT PRIMARY KEY,
            kind VARCHAR(20) NOT NULL,
            name VARCHAR(255) NOT NULL,
            config TEXT NOT NULL,
            min_severity VARCHAR(10) NOT NULL DEFAULT 'Medium',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_notification_channel(
    pool: &DbPool,
    kind: &str,
    name: &str,
    config_json: &str,
    min_severity: &str,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO notification_channels (kind, name, config, min_severity) VALUES (?, ?, ?, ?)",
    )
    .bind(kind)
    .bind(name)
    .bind(config_json)
    .bind(min_severity)
    .execute(pool)
    .await?;
    Ok(result.last_insert_id() as i32)
}

pub async fn list_notification_channels(
    pool: &DbPool,
) -> Result<Vec<crate::models::NotificationChannel>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, kind, name, config, min_severity, enabled FROM notification_channels ORDER BY id",
    )
    .fetch_all(pool)
    .await
}

pub async fn delete_notification_channel(pool: &DbPool, id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM notification_channels WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_channel_enabled(pool: &DbPool, id: i32, enabled: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE notification_channels SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_channel_by_id(
    pool: &DbPool,
    id: i32,
) -> Result<Option<crate::models::NotificationChannel>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, kind, name, config, min_severity, enabled FROM notification_channels WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

// Returns every enabled channel whose min_severity is at or below the
// given severity -- i.e. "would this channel want to hear about an event
// of this severity." Ranking done in Rust (not SQL) since it's the same
// small fixed scale used everywhere else in this codebase (parser.rs's
// Severity enum, the dashboard's SEVERITY_RANK on the frontend).
pub async fn get_enabled_channels_for_severity(
    pool: &DbPool,
    severity: &str,
) -> Result<Vec<crate::models::NotificationChannel>, sqlx::Error> {
    fn rank(s: &str) -> u8 {
        match s {
            "Critical" => 3,
            "High" => 2,
            "Medium" => 1,
            _ => 0, // Low, and anything unrecognized
        }
    }

    let all: Vec<crate::models::NotificationChannel> = sqlx::query_as(
        "SELECT id, kind, name, config, min_severity, enabled FROM notification_channels WHERE enabled = TRUE",
    )
    .fetch_all(pool)
    .await?;

    let event_rank = rank(severity);
    Ok(all
        .into_iter()
        .filter(|c| event_rank >= rank(&c.min_severity))
        .collect())
}

// --- Directory (LDAP/Active Directory) sync ---
//
// Same single-row pattern as `settings`: exactly one config row always
// exists, so reads never fail. `bind_password_encrypted` holds the
// AES-GCM-encrypted bind password (see crypto.rs) -- this table never
// stores it in plaintext, and nothing in db.rs ever decrypts it; that
// happens in directory.rs, the one place that actually needs the
// plaintext to open a connection.
pub async fn init_directory_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS ldap_config (
            id INT PRIMARY KEY DEFAULT 1,
            enabled BOOLEAN NOT NULL DEFAULT FALSE,
            server_uri VARCHAR(512) NOT NULL DEFAULT '',
            bind_dn VARCHAR(512) NOT NULL DEFAULT '',
            bind_password_encrypted TEXT NULL,
            base_dn VARCHAR(512) NOT NULL DEFAULT '',
            computer_filter VARCHAR(512) NOT NULL DEFAULT '(objectClass=computer)',
            sync_interval_minutes INT NOT NULL DEFAULT 60,
            last_sync_at TIMESTAMP NULL,
            last_sync_status VARCHAR(20) NULL,
            last_sync_count INT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT IGNORE INTO ldap_config (id) VALUES (1)")
        .execute(pool)
        .await?;

    // Directory-backed dashboard login (Phase 2) -- reuses the same
    // connection config above rather than a second config surface, it's
    // still "how SecLog talks to the directory," just a second consumer
    // of it. `{username}` in user_filter_template gets substituted with
    // ldap3::ldap_escape()'d input at login time -- see
    // directory::authenticate_user. admin_group_dn stays NULL by
    // default so nobody is ever auto-admin without an explicit,
    // deliberate setting.
    sqlx::query("ALTER TABLE ldap_config ADD COLUMN IF NOT EXISTS login_enabled BOOLEAN NOT NULL DEFAULT FALSE")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE ldap_config ADD COLUMN IF NOT EXISTS user_base_dn VARCHAR(512) NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    sqlx::query(
        "ALTER TABLE ldap_config ADD COLUMN IF NOT EXISTS user_filter_template VARCHAR(512) NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))'"
    )
    .execute(pool)
    .await?;
    sqlx::query("ALTER TABLE ldap_config ADD COLUMN IF NOT EXISTS admin_group_dn VARCHAR(512) NULL")
        .execute(pool)
        .await?;

    // hostname, not distinguished_name, is the human-meaningful identity
    // here, but the DN is what's actually stable and unique in AD (a
    // computer can be renamed; its DN changes only if it's moved to a
    // different OU). VARCHAR(1024) exceeds InnoDB's default max key
    // length for a full unique index, hence the prefix.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS discovered_hosts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            hostname VARCHAR(255) NOT NULL,
            distinguished_name VARCHAR(1024) NOT NULL,
            operating_system VARCHAR(255) NULL,
            organizational_unit VARCHAR(512) NULL,
            ad_last_logon TIMESTAMP NULL,
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_in_ad TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_dn (distinguished_name(255))
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct LdapConfigRow {
    pub enabled: bool,
    pub server_uri: String,
    pub bind_dn: String,
    pub bind_password_encrypted: Option<String>,
    pub base_dn: String,
    pub computer_filter: String,
    pub sync_interval_minutes: i64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_count: Option<i64>,
    pub login_enabled: bool,
    pub user_base_dn: String,
    pub user_filter_template: String,
    pub admin_group_dn: Option<String>,
}

pub async fn get_ldap_config(pool: &DbPool) -> Result<LdapConfigRow, sqlx::Error> {
    sqlx::query_as(
        "SELECT enabled, server_uri, bind_dn, bind_password_encrypted, base_dn,
                computer_filter, sync_interval_minutes, last_sync_at, last_sync_status,
                last_sync_count, login_enabled, user_base_dn, user_filter_template,
                admin_group_dn
         FROM ldap_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await
}

// Bundles set_ldap_config's fields -- plain positional args stopped
// being readable once the login-related columns joined the original
// connection ones.
pub struct LdapConfigUpdate<'a> {
    pub enabled: bool,
    pub server_uri: &'a str,
    pub bind_dn: &'a str,
    // None leaves the currently-stored password untouched (the "shown
    // once" UX -- an admin re-saving the connection settings shouldn't
    // have to re-enter it every time).
    pub new_bind_password_encrypted: Option<&'a str>,
    pub base_dn: &'a str,
    pub computer_filter: &'a str,
    pub sync_interval_minutes: i64,
    pub login_enabled: bool,
    pub user_base_dn: &'a str,
    pub user_filter_template: &'a str,
    pub admin_group_dn: Option<&'a str>,
}

pub async fn set_ldap_config(pool: &DbPool, u: LdapConfigUpdate<'_>) -> Result<(), sqlx::Error> {
    if let Some(encrypted) = u.new_bind_password_encrypted {
        sqlx::query(
            "UPDATE ldap_config
             SET enabled = ?, server_uri = ?, bind_dn = ?, bind_password_encrypted = ?,
                 base_dn = ?, computer_filter = ?, sync_interval_minutes = ?,
                 login_enabled = ?, user_base_dn = ?, user_filter_template = ?, admin_group_dn = ?
             WHERE id = 1",
        )
        .bind(u.enabled)
        .bind(u.server_uri)
        .bind(u.bind_dn)
        .bind(encrypted)
        .bind(u.base_dn)
        .bind(u.computer_filter)
        .bind(u.sync_interval_minutes)
        .bind(u.login_enabled)
        .bind(u.user_base_dn)
        .bind(u.user_filter_template)
        .bind(u.admin_group_dn)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            "UPDATE ldap_config
             SET enabled = ?, server_uri = ?, bind_dn = ?,
                 base_dn = ?, computer_filter = ?, sync_interval_minutes = ?,
                 login_enabled = ?, user_base_dn = ?, user_filter_template = ?, admin_group_dn = ?
             WHERE id = 1",
        )
        .bind(u.enabled)
        .bind(u.server_uri)
        .bind(u.bind_dn)
        .bind(u.base_dn)
        .bind(u.computer_filter)
        .bind(u.sync_interval_minutes)
        .bind(u.login_enabled)
        .bind(u.user_base_dn)
        .bind(u.user_filter_template)
        .bind(u.admin_group_dn)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn record_ldap_sync_result(
    pool: &DbPool,
    status: &str,
    count: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE ldap_config SET last_sync_at = NOW(), last_sync_status = ?, last_sync_count = ? WHERE id = 1",
    )
    .bind(status)
    .bind(count)
    .execute(pool)
    .await?;
    Ok(())
}

// Insert-or-refresh: a host still present in AD gets its details and
// last_seen_in_ad bumped; first_seen_at is only ever set once, on the
// original INSERT (it's absent from the UPDATE clause).
pub async fn upsert_discovered_host(
    pool: &DbPool,
    hostname: &str,
    distinguished_name: &str,
    operating_system: Option<&str>,
    organizational_unit: Option<&str>,
    ad_last_logon: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO discovered_hosts
            (hostname, distinguished_name, operating_system, organizational_unit, ad_last_logon, last_seen_in_ad)
         VALUES (?, ?, ?, ?, ?, NOW())
         ON DUPLICATE KEY UPDATE
            hostname = VALUES(hostname),
            operating_system = VALUES(operating_system),
            organizational_unit = VALUES(organizational_unit),
            ad_last_logon = VALUES(ad_last_logon),
            last_seen_in_ad = NOW()",
    )
    .bind(hostname)
    .bind(distinguished_name)
    .bind(operating_system)
    .bind(organizational_unit)
    .bind(ad_last_logon)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct DiscoveredHostRow {
    pub id: i32,
    pub hostname: String,
    pub distinguished_name: String,
    pub operating_system: Option<String>,
    pub organizational_unit: Option<String>,
    pub ad_last_logon: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_in_ad: DateTime<Utc>,
    pub agent_id: Option<i32>,
}

// LEFT JOINs against `agents` on a best-effort, case-insensitive match
// between each side's SHORT hostname (SUBSTRING_INDEX(..., '.', 1) --
// everything before the first '.', a no-op on a string with no dot).
// AD's dNSHostName is typically an FQDN; the shipper's self-detected
// hostname often isn't. This is a heuristic, not a guarantee -- the API
// layer surfaces it as "likely enrolled," never as certainty.
pub async fn list_discovered_hosts(pool: &DbPool) -> Result<Vec<DiscoveredHostRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT dh.id, dh.hostname, dh.distinguished_name, dh.operating_system,
                dh.organizational_unit, dh.ad_last_logon, dh.first_seen_at, dh.last_seen_in_ad,
                a.id AS agent_id
         FROM discovered_hosts dh
         LEFT JOIN agents a
           ON LOWER(SUBSTRING_INDEX(dh.hostname, '.', 1)) = LOWER(SUBSTRING_INDEX(a.hostname, '.', 1))
         ORDER BY dh.hostname",
    )
    .fetch_all(pool)
    .await
}

// --- Audit trail (CJIS AU-2, AU-3, AU-3(1)) ---
//
// A record of what SecLog's own users and admins did -- distinct from
// `logs`, which records what the SHIPPER saw on monitored machines.
// No FK on actor_user_id: deleting a user must never cascade-delete or
// block on their audit history, which is why actor_username is also
// denormalized here rather than joined at read time -- the record has
// to stay meaningful after the account itself is gone.
pub async fn init_audit_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            actor_user_id INT NULL,
            actor_username VARCHAR(255) NOT NULL,
            action VARCHAR(64) NOT NULL,
            resource VARCHAR(255) NULL,
            outcome VARCHAR(10) NOT NULL,
            source_ip VARCHAR(64) NOT NULL,
            details TEXT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at ON audit_log (occurred_at)")
        .execute(pool)
        .await
        .ok(); // see idx_logs_host above -- IF NOT EXISTS on an index isn't universal, ignore "already exists"

    // Tamper-evidence: a linear hash chain, viable here specifically
    // because this table is low-volume (human-driven writes only) and
    // nothing ever deletes from it -- see record_audit_event and
    // verify_audit_log_chain below. Rows written before this column
    // existed default to '' ("pre-chain, unverifiable" -- not a break);
    // see the comment on verify_audit_log_chain.
    sqlx::query("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash CHAR(64) NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS row_hash CHAR(64) NOT NULL DEFAULT ''")
        .execute(pool)
        .await?;

    Ok(())
}

// Genesis value for the very first row of the audit_log hash chain --
// an arbitrary but fixed 64 hex-zero string, distinguishable from any
// real SHA-256 digest only in that it's never actually produced by one
// (astronomically unlikely by design, not by construction -- same
// caveat as any hash-based scheme).
fn audit_chain_genesis() -> String {
    "0".repeat(64)
}

// Deterministic, delimited serialization of one audit_log row's
// content for hashing -- deliberately delimited (not naive
// concatenation), since e.g. "ab"+"c" and "a"+"bc" must never hash the
// same. \x1f (ASCII unit separator) is vanishingly unlikely to appear
// in any of these fields naturally.
#[allow(clippy::too_many_arguments)]
fn audit_hash_input(
    prev_hash: &str,
    occurred_at: DateTime<Utc>,
    actor_user_id: Option<i32>,
    actor_username: &str,
    action: &str,
    resource: Option<&str>,
    outcome: &str,
    source_ip: &str,
    details: Option<&str>,
) -> String {
    const SEP: char = '\u{1f}';
    format!(
        "{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}",
        prev_hash,
        occurred_at.to_rfc3339(),
        actor_user_id.map(|v| v.to_string()).unwrap_or_default(),
        actor_username,
        action,
        resource.unwrap_or(""),
        outcome,
        source_ip,
        details.unwrap_or(""),
    )
}

// Fire-and-forget from the CALLER's perspective (never blocks or fails
// the action it's recording -- SecLog has to stay usable even if this
// one table has a problem) but not silent: a write failure here fires a
// [SYSTEM] alert via notify::trigger_alert, because a broken audit
// pipeline is exactly the kind of failure CJIS AU-5 exists to surface.
// `actor` is None for an attempt against a username that doesn't exist
// at all (a failed login where even the username lookup came back
// empty) -- `actor_username` still records what was typed, since a
// failed-login audit trail is precisely how you'd notice someone
// brute-forcing usernames.
#[allow(clippy::too_many_arguments)]
pub async fn record_audit_event(
    pool: &DbPool,
    actor_user_id: Option<i32>,
    actor_username: &str,
    action: &str,
    resource: Option<&str>,
    outcome: &str,
    source_ip: &str,
    details: Option<&str>,
) {
    // occurred_at is computed here (not left to the column's
    // DEFAULT CURRENT_TIMESTAMP) so the exact value that goes into the
    // hash is the same value that ends up stored -- letting the DB pick
    // it would mean the hash could never be re-derived from the stored
    // row alone. Truncated to whole seconds for the same reason: the
    // `TIMESTAMP` column itself has no fractional-second precision, so
    // without this the microsecond-precision value hashed here would
    // never match what's actually readable back from the row later --
    // every single row would show up as "broken" on verification, not
    // because anything was tampered with, but because the hash was
    // computed from a value more precise than the column can store.
    let occurred_at = Utc::now().trunc_subsecs(0);

    let result: Result<(), sqlx::Error> = async {
        let mut tx = pool.begin().await?;

        // Locks the current chain tip so concurrent writers serialize
        // on THIS table specifically -- fine here because writes are
        // human-driven (logins, admin actions) and comparatively rare.
        // `logs` deliberately does NOT do this; see log_checkpoints for
        // why a linear per-row chain doesn't fit a shipper-fed table.
        let prev_hash: Option<String> =
            sqlx::query_scalar("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE")
                .fetch_optional(&mut *tx)
                .await?;
        let prev_hash = prev_hash.unwrap_or_else(audit_chain_genesis);

        let row_hash = crate::parser::hash_line(&audit_hash_input(
            &prev_hash, occurred_at, actor_user_id, actor_username, action, resource, outcome, source_ip, details,
        ));

        sqlx::query(
            "INSERT INTO audit_log
                (occurred_at, actor_user_id, actor_username, action, resource, outcome, source_ip, details, prev_hash, row_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(occurred_at)
        .bind(actor_user_id)
        .bind(actor_username)
        .bind(action)
        .bind(resource)
        .bind(outcome)
        .bind(source_ip)
        .bind(details)
        .bind(&prev_hash)
        .bind(&row_hash)
        .execute(&mut *tx)
        .await?;

        tx.commit().await
    }
    .await;

    if let Err(e) = result {
        eprintln!("AUDIT LOG WRITE FAILED: action={} actor={} error={}", action, actor_username, e);
        let pool = pool.clone();
        let action = action.to_string();
        tokio::spawn(async move {
            crate::notify::trigger_alert(
                &pool,
                "Critical",
                &format!("[SYSTEM] Audit log write failed for action '{}' -- see server logs", action),
                "seclog-server",
            )
            .await;
        });
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct AuditLogRow {
    pub id: i32,
    pub occurred_at: DateTime<Utc>,
    pub actor_user_id: Option<i32>,
    pub actor_username: String,
    pub action: String,
    pub resource: Option<String>,
    pub outcome: String,
    pub source_ip: String,
    pub details: Option<String>,
}

pub async fn list_audit_log(pool: &DbPool, limit: i64, offset: i64) -> Result<Vec<AuditLogRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, occurred_at, actor_user_id, actor_username, action, resource, outcome, source_ip, details
         FROM audit_log
         ORDER BY id DESC
         LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

pub async fn count_audit_log(pool: &DbPool) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log").fetch_one(pool).await?;
    Ok(row.0)
}

// Used to default verify_audit_log_chain's starting point to "the most
// recent N rows" -- explicit MAX(id) rather than leaning on
// count_audit_log() happening to equal it (true today, since nothing
// deletes from this table, but not a relationship worth depending on).
pub async fn max_audit_log_id(pool: &DbPool) -> Result<i32, sqlx::Error> {
    let id: Option<i32> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log").fetch_one(pool).await?;
    Ok(id.unwrap_or(0))
}

#[derive(sqlx::FromRow)]
struct AuditChainRow {
    id: i32,
    occurred_at: DateTime<Utc>,
    actor_user_id: Option<i32>,
    actor_username: String,
    action: String,
    resource: Option<String>,
    outcome: String,
    source_ip: String,
    details: Option<String>,
    prev_hash: String,
    row_hash: String,
}

#[derive(Debug, serde::Serialize)]
pub struct AuditChainVerification {
    pub checked_from_id: i32,
    pub verified_count: i64,
    pub intact: bool,
    pub first_broken_id: Option<i32>,
    pub reason: Option<String>,
}

// Walks audit_log from `since_id` forward (up to `limit` rows),
// recomputing each row's hash from its own stored fields plus the
// previous row's stored hash, and checking id sequentiality (valid to
// assert strictly here, unlike on `logs`, since nothing ever deletes
// from this table). Rows with row_hash = '' predate this feature and
// are skipped, not treated as breaks -- their content was never hashed
// at write time, so there's nothing to verify, and no way to pretend
// otherwise. Bounded by `limit` rather than walking the whole table by
// default, same anti-"fetch everything" discipline as the rest of this
// codebase; the caller (main.rs) decides the default window.
pub async fn verify_audit_log_chain(
    pool: &DbPool,
    since_id: i32,
    limit: i64,
) -> Result<AuditChainVerification, sqlx::Error> {
    let rows: Vec<AuditChainRow> = sqlx::query_as(
        "SELECT id, occurred_at, actor_user_id, actor_username, action, resource, outcome, source_ip, details, prev_hash, row_hash
         FROM audit_log
         WHERE id >= ? AND row_hash != ''
         ORDER BY id ASC
         LIMIT ?",
    )
    .bind(since_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut expected_prev: Option<String> = None; // None until the first row in this window is seen
    let mut last_id: Option<i32> = None;
    let mut verified_count: i64 = 0;

    for row in rows {
        if let Some(last) = last_id
            && row.id != last + 1
        {
            return Ok(AuditChainVerification {
                checked_from_id: since_id,
                verified_count,
                intact: false,
                first_broken_id: Some(row.id),
                reason: Some(format!("id gap: expected {}, found {}", last + 1, row.id)),
            });
        }

        if let Some(expected) = &expected_prev
            && &row.prev_hash != expected
        {
            return Ok(AuditChainVerification {
                checked_from_id: since_id,
                verified_count,
                intact: false,
                first_broken_id: Some(row.id),
                reason: Some("prev_hash does not match the previous row's stored hash".to_string()),
            });
        }

        let recomputed = crate::parser::hash_line(&audit_hash_input(
            &row.prev_hash,
            row.occurred_at,
            row.actor_user_id,
            &row.actor_username,
            &row.action,
            row.resource.as_deref(),
            &row.outcome,
            &row.source_ip,
            row.details.as_deref(),
        ));
        if recomputed != row.row_hash {
            return Ok(AuditChainVerification {
                checked_from_id: since_id,
                verified_count,
                intact: false,
                first_broken_id: Some(row.id),
                reason: Some("row content does not match its stored hash".to_string()),
            });
        }

        expected_prev = Some(row.row_hash);
        last_id = Some(row.id);
        verified_count += 1;
    }

    Ok(AuditChainVerification {
        checked_from_id: since_id,
        verified_count,
        intact: true,
        first_broken_id: None,
        reason: None,
    })
}

// --- Correlation rules ---
// Threshold detection over the SAME labeled rule table parser.rs
// already maintains ([Label] prefixes on logs.message) -- an admin
// picks an existing label + how many + how fast, they don't write a
// new pattern. See parser::known_labels() and README/ARCHITECTURE for
// why this deliberately isn't a free-text rule engine.

pub async fn init_correlation_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS correlation_rules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            match_label VARCHAR(255) NOT NULL,
            group_by VARCHAR(10) NOT NULL DEFAULT 'host',
            threshold_count INT NOT NULL,
            window_minutes INT NOT NULL,
            alert_severity VARCHAR(10) NOT NULL DEFAULT 'High',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_name (name)
        )",
    )
    .execute(pool)
    .await?;

    // Seeded defaults, editable/deletable afterward like any other row --
    // INSERT IGNORE against the name-uniqueness above makes this safe to
    // run on every startup (only inserts what's missing).
    let defaults: [(&str, &str, &str, i64, i64, &str); 3] = [
        ("Repeated SSH failed logins", "SSH failed login", "host", 5, 5, "High"),
        ("Repeated SSH invalid user attempts", "SSH invalid user attempt", "host", 5, 5, "High"),
        ("Repeated unauthorized sudo attempts", "Unauthorized sudo attempt", "user", 3, 10, "High"),
    ];
    for (name, label, group_by, threshold, window, severity) in defaults {
        sqlx::query(
            "INSERT IGNORE INTO correlation_rules
                (name, match_label, group_by, threshold_count, window_minutes, alert_severity)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(name)
        .bind(label)
        .bind(group_by)
        .bind(threshold)
        .bind(window)
        .bind(severity)
        .execute(pool)
        .await?;
    }

    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct CorrelationRuleRow {
    pub id: i32,
    pub name: String,
    pub match_label: String,
    pub group_by: String,
    pub threshold_count: i64,
    pub window_minutes: i64,
    pub alert_severity: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

pub async fn list_correlation_rules(pool: &DbPool) -> Result<Vec<CorrelationRuleRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, name, match_label, group_by, threshold_count, window_minutes, alert_severity, enabled, created_at FROM correlation_rules ORDER BY id")
        .fetch_all(pool)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_correlation_rule(
    pool: &DbPool,
    name: &str,
    match_label: &str,
    group_by: &str,
    threshold_count: i64,
    window_minutes: i64,
    alert_severity: &str,
) -> Result<i32, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO correlation_rules (name, match_label, group_by, threshold_count, window_minutes, alert_severity)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(match_label)
    .bind(group_by)
    .bind(threshold_count)
    .bind(window_minutes)
    .bind(alert_severity)
    .execute(pool)
    .await?;
    Ok(result.last_insert_id() as i32)
}

#[allow(clippy::too_many_arguments)]
pub async fn update_correlation_rule(
    pool: &DbPool,
    id: i32,
    name: &str,
    match_label: &str,
    group_by: &str,
    threshold_count: i64,
    window_minutes: i64,
    alert_severity: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE correlation_rules
         SET name = ?, match_label = ?, group_by = ?, threshold_count = ?,
             window_minutes = ?, alert_severity = ?, enabled = ?
         WHERE id = ?",
    )
    .bind(name)
    .bind(match_label)
    .bind(group_by)
    .bind(threshold_count)
    .bind(window_minutes)
    .bind(alert_severity)
    .bind(enabled)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_correlation_rule(pool: &DbPool, id: i32) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM correlation_rules WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct CorrelationHit {
    pub group_value: String,
    pub count: i64,
}

// group_by is validated to exactly "host" or "user" at the handler
// layer (create/update_correlation_rule's callers) before it's ever
// stored, so branching on it here to pick a column name -- rather than
// binding it as a value, which SQL doesn't allow for identifiers -- is
// safe: `column` only ever comes from this fixed Rust match, never
// directly from the stored string.
pub async fn correlation_rule_hits(pool: &DbPool, rule: &CorrelationRuleRow) -> Result<Vec<CorrelationHit>, sqlx::Error> {
    let column = match rule.group_by.as_str() {
        "user" => "user",
        _ => "host",
    };
    let sql = format!(
        "SELECT {column} AS group_value, COUNT(*) AS count FROM logs \
         WHERE message LIKE CONCAT('[', ?, ']%') AND created_at > (NOW() - INTERVAL ? MINUTE) \
         GROUP BY {column} HAVING COUNT(*) >= ?"
    );
    // `column` is never user-controlled at this point (see the comment
    // above) -- only the ? placeholders below carry actual data, so
    // this dynamic string is safe despite sqlx's blanket lint on
    // non-'static SQL strings.
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(&rule.match_label)
        .bind(rule.window_minutes)
        .bind(rule.threshold_count)
        .fetch_all(pool)
        .await
}

// --- Syslog receiver ---
// See src/syslog.rs for the listeners themselves and the security
// posture (fail-closed CIDR allowlist) this config backs.

pub async fn init_syslog_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS syslog_config (
            id INT PRIMARY KEY DEFAULT 1,
            enabled_udp BOOLEAN NOT NULL DEFAULT FALSE,
            enabled_tcp BOOLEAN NOT NULL DEFAULT FALSE,
            allowed_cidrs TEXT NOT NULL DEFAULT '',
            last_message_at TIMESTAMP NULL,
            last_message_host VARCHAR(255) NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT IGNORE INTO syslog_config (id) VALUES (1)")
        .execute(pool)
        .await?;

    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct SyslogConfigRow {
    pub enabled_udp: bool,
    pub enabled_tcp: bool,
    pub allowed_cidrs: String,
    pub last_message_at: Option<DateTime<Utc>>,
    pub last_message_host: Option<String>,
}

pub async fn get_syslog_config(pool: &DbPool) -> Result<SyslogConfigRow, sqlx::Error> {
    sqlx::query_as(
        "SELECT enabled_udp, enabled_tcp, allowed_cidrs, last_message_at, last_message_host
         FROM syslog_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await
}

pub async fn update_syslog_config(
    pool: &DbPool,
    enabled_udp: bool,
    enabled_tcp: bool,
    allowed_cidrs: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE syslog_config SET enabled_udp = ?, enabled_tcp = ?, allowed_cidrs = ? WHERE id = 1")
        .bind(enabled_udp)
        .bind(enabled_tcp)
        .bind(allowed_cidrs)
        .execute(pool)
        .await?;
    Ok(())
}

// Fire-and-forget observability -- lets the admin confirm from the
// Syslog page that something is actually arriving, without needing to
// go look at the Dashboard. Never fails loudly to the listener loop
// that calls it (see src/syslog.rs) -- losing this stat is not worth
// dropping the message that triggered it.
pub async fn touch_syslog_last_message(pool: &DbPool, host: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE syslog_config SET last_message_at = NOW(), last_message_host = ? WHERE id = 1")
        .bind(host)
        .execute(pool)
        .await?;
    Ok(())
}

// --- External archival storage (S3-compatible / SFTP) ---
// See src/archive.rs for the actual upload logic; this is just config
// storage plus the SELECT-before-DELETE queries the retention loop
// uses when archiving is enabled.

pub async fn init_archive_schema(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS archive_config (
            id INT PRIMARY KEY DEFAULT 1,
            backend VARCHAR(10) NOT NULL DEFAULT 'none',
            enabled BOOLEAN NOT NULL DEFAULT FALSE,
            s3_endpoint VARCHAR(512) NOT NULL DEFAULT '',
            s3_bucket VARCHAR(255) NOT NULL DEFAULT '',
            s3_region VARCHAR(100) NOT NULL DEFAULT 'us-east-1',
            s3_access_key VARCHAR(255) NOT NULL DEFAULT '',
            s3_secret_key_encrypted TEXT NULL,
            s3_path_style BOOLEAN NOT NULL DEFAULT TRUE,
            sftp_host VARCHAR(255) NOT NULL DEFAULT '',
            sftp_port INT NOT NULL DEFAULT 22,
            sftp_username VARCHAR(255) NOT NULL DEFAULT '',
            sftp_password_encrypted TEXT NULL,
            sftp_private_key_encrypted TEXT NULL,
            sftp_remote_path VARCHAR(512) NOT NULL DEFAULT '',
            last_archive_at TIMESTAMP NULL,
            last_archive_status VARCHAR(20) NULL,
            last_archive_count INT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT IGNORE INTO archive_config (id) VALUES (1)")
        .execute(pool)
        .await?;

    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct ArchiveConfigRow {
    pub backend: String,
    pub enabled: bool,
    pub s3_endpoint: String,
    pub s3_bucket: String,
    pub s3_region: String,
    pub s3_access_key: String,
    pub s3_secret_key_encrypted: Option<String>,
    pub s3_path_style: bool,
    pub sftp_host: String,
    pub sftp_port: i64,
    pub sftp_username: String,
    pub sftp_password_encrypted: Option<String>,
    pub sftp_private_key_encrypted: Option<String>,
    pub sftp_remote_path: String,
    pub last_archive_at: Option<DateTime<Utc>>,
    pub last_archive_status: Option<String>,
    pub last_archive_count: Option<i64>,
}

pub async fn get_archive_config(pool: &DbPool) -> Result<ArchiveConfigRow, sqlx::Error> {
    sqlx::query_as(
        "SELECT backend, enabled, s3_endpoint, s3_bucket, s3_region, s3_access_key,
                s3_secret_key_encrypted, s3_path_style, sftp_host, sftp_port, sftp_username,
                sftp_password_encrypted, sftp_private_key_encrypted, sftp_remote_path,
                last_archive_at, last_archive_status, last_archive_count
         FROM archive_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await
}

// Each of the three secret fields independently follows the same
// "write-only, shown once, blank leaves it unchanged" contract already
// established for the LDAP bind password (see LdapConfigUpdate) --
// None here means "don't touch what's already stored."
pub struct ArchiveConfigUpdate<'a> {
    pub backend: &'a str,
    pub enabled: bool,
    pub s3_endpoint: &'a str,
    pub s3_bucket: &'a str,
    pub s3_region: &'a str,
    pub s3_access_key: &'a str,
    pub new_s3_secret_key_encrypted: Option<&'a str>,
    pub s3_path_style: bool,
    pub sftp_host: &'a str,
    pub sftp_port: i64,
    pub sftp_username: &'a str,
    pub new_sftp_password_encrypted: Option<&'a str>,
    pub new_sftp_private_key_encrypted: Option<&'a str>,
    pub sftp_remote_path: &'a str,
}

pub async fn update_archive_config(pool: &DbPool, u: ArchiveConfigUpdate<'_>) -> Result<(), sqlx::Error> {
    // Built as one fixed UPDATE with COALESCE-by-parameter would need
    // four query variants (2^ combinations of the two truly independent
    // secrets minus the S3 one) -- simpler and just as safe to always
    // set the non-secret columns, then conditionally touch each secret
    // column only when a new value was actually provided.
    sqlx::query(
        "UPDATE archive_config
         SET backend = ?, enabled = ?, s3_endpoint = ?, s3_bucket = ?, s3_region = ?,
             s3_access_key = ?, s3_path_style = ?, sftp_host = ?, sftp_port = ?,
             sftp_username = ?, sftp_remote_path = ?
         WHERE id = 1",
    )
    .bind(u.backend)
    .bind(u.enabled)
    .bind(u.s3_endpoint)
    .bind(u.s3_bucket)
    .bind(u.s3_region)
    .bind(u.s3_access_key)
    .bind(u.s3_path_style)
    .bind(u.sftp_host)
    .bind(u.sftp_port)
    .bind(u.sftp_username)
    .bind(u.sftp_remote_path)
    .execute(pool)
    .await?;

    if let Some(encrypted) = u.new_s3_secret_key_encrypted {
        sqlx::query("UPDATE archive_config SET s3_secret_key_encrypted = ? WHERE id = 1")
            .bind(encrypted)
            .execute(pool)
            .await?;
    }
    if let Some(encrypted) = u.new_sftp_password_encrypted {
        sqlx::query("UPDATE archive_config SET sftp_password_encrypted = ? WHERE id = 1")
            .bind(encrypted)
            .execute(pool)
            .await?;
    }
    if let Some(encrypted) = u.new_sftp_private_key_encrypted {
        sqlx::query("UPDATE archive_config SET sftp_private_key_encrypted = ? WHERE id = 1")
            .bind(encrypted)
            .execute(pool)
            .await?;
    }

    Ok(())
}

pub async fn record_archive_result(pool: &DbPool, status: &str, count: Option<i64>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE archive_config SET last_archive_at = NOW(), last_archive_status = ?, last_archive_count = ? WHERE id = 1")
        .bind(status)
        .bind(count)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct ArchiveLogRow {
    pub id: i32,
    pub severity: String,
    pub user: String,
    pub message: String,
    pub host: String,
    pub event_time: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub review_status: String,
    pub reviewed_by_username: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_note: Option<String>,
}

// Mirrors delete_logs_older_than's WHERE clause exactly -- the rows
// this returns are precisely the rows that call would delete, so
// archiving these first and only then calling it is safe.
pub async fn select_logs_older_than(pool: &DbPool, days: i64) -> Result<Vec<ArchiveLogRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT logs.id, logs.severity, logs.user, logs.message, logs.host, logs.event_time,
                logs.created_at, logs.review_status, logs.reviewed_at, logs.review_note,
                reviewer.username AS reviewed_by_username
         FROM logs
         LEFT JOIN users AS reviewer ON logs.reviewed_by = reviewer.id
         WHERE logs.created_at < (NOW() - INTERVAL ? DAY)
         ORDER BY logs.id",
    )
    .bind(days)
    .fetch_all(pool)
    .await
}

// Mirrors enforce_max_log_rows's cutoff-id subquery exactly, for the
// same reason as select_logs_older_than above.
pub async fn select_logs_beyond_row_cap(pool: &DbPool, max_rows: i64) -> Result<Vec<ArchiveLogRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT logs.id, logs.severity, logs.user, logs.message, logs.host, logs.event_time,
                logs.created_at, logs.review_status, logs.reviewed_at, logs.review_note,
                reviewer.username AS reviewed_by_username
         FROM logs
         LEFT JOIN users AS reviewer ON logs.reviewed_by = reviewer.id
         WHERE logs.id <= (
             SELECT id FROM (
                 SELECT id FROM logs ORDER BY id DESC LIMIT 1 OFFSET ?
             ) AS cutoff
         )
         ORDER BY logs.id",
    )
    .bind(max_rows)
    .fetch_all(pool)
    .await
}
