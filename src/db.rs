use crate::auth;
use crate::models::LogRow;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use chrono::{Utc, Duration};

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

    Ok(())
}

// Returns true of a new row was actually inserted, false if it was a duplicate.
pub async fn insert_log(
    pool: &DbPool,
    severity: &str,
    user: &str,
    message: &str,
    host: &str,
    hash: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT IGNORE INTO logs (severity, user, message, host, line_hash)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(severity)
    .bind(user)
    .bind(message)
    .bind(host)
    .bind(hash)
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
// loading a host's full history into the browser at once.
pub async fn get_logs_for_host(
    pool: &DbPool,
    host: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LogRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, severity, user, message, host FROM logs
         WHERE host = ?
         ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low'), id DESC
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

pub async fn get_user_for_login(
    pool: &DbPool,
    username: &str,
) -> Result<Option<(i32, String, bool, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, password_hash, must_change_password, mfa_enabled FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct UserRow {
    pub id: i32,
    pub username: String,
    pub role: String,
}

pub async fn get_all_users(pool: &DbPool) -> Result<Vec<UserRow>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, role FROM users")
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

    // Retention defaults: 30 days, capped at 2 million rows regardless of
    // age. The row cap is the important one for a runaway-source scenario
    // like a feedback loop -- it can fill a disk in hours, well inside any
    // reasonable day-based window.
    sqlx::query("ALTER TABLE settings ADD COLUMN IF NOT EXISTS log_retention_days INT NOT NULL DEFAULT 30")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE settings ADD COLUMN IF NOT EXISTS max_log_rows BIGINT NOT NULL DEFAULT 2000000")
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
    sqlx::query("UPDATE agents SET last_seen = NOW() WHERE id =?")
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
    Ok(())
}

pub async fn create_enrollment_token(
    pool: &DbPool,
    token: &str,
) -> Result<(), sqlx::Error> {
    let token_hash = auth::hash_token(token);

    sqlx::query("INSERT INTO enrollment_tokens (token) VALUES (?)")
        .bind(token_hash)
        .execute(pool)
        .await?;

    Ok(())
}

// Returns true if the token existed and was unused (and marks it used
// atomically-ish via the UPDATE's row count) -- one-time use only.
pub async fn consume_enrollment_token(
    pool: &DbPool,
    token: &str,
) -> Result<bool, sqlx::Error> {
    let token_hash = auth::hash_token(token);

    let result = sqlx::query(
        "UPDATE enrollment_tokens
         SET used_at = NOW()
         WHERE token = ? AND used_at IS NULL",
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
