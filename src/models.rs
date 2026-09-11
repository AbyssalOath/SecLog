use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Used internally by the CLI parser (parser.rs) -- never sent over the wire
// directly. What gets sent to the API is a String ("Low"/"Medium"/etc),
// built via format!("{:?}", ...) on this enum.
#[derive(Debug)]
pub struct LogEntry {
    pub severity: Severity,
    pub user: String,
    pub message: String,
    // The event's own timestamp, recovered from the raw line where
    // possible (see parser::extract_event_time) -- distinct from
    // whenever the server happens to insert the row. None when no
    // recognized timestamp was found in the source line.
    pub event_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct LogRow {
    pub id: i32,
    pub severity: String,
    pub user: String,
    pub message: String,
    pub host: String,
    // The event's own timestamp if one was recovered from the source
    // line, distinct from when SecLog ingested it (CJIS AU-8). None
    // means no recognized timestamp was found -- treat ingestion time
    // as the best available signal, not an exact one.
    pub event_time: Option<DateTime<Utc>>,
    pub review_status: String,
    pub reviewed_by_username: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub review_note: Option<String>,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct HostSummaryRow {
    pub host: String,
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub host: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedLogs {
    pub logs: Vec<LogRow>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// CJIS AU-6: marks a log row reviewed/investigated. `status` must be
// one of "open"/"reviewed"/"false_positive" -- validated in the
// set_log_review handler, not here.
#[derive(Debug, Deserialize)]
pub struct LogReviewRequest {
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
}

// What the CLIENT sends us as JSON. severity travels as a plain String
// ("Low"/"Medium"/"High"/"Critical") -- the Severity enum above is only
// used internally during file-based parsing, not over HTTP.
#[derive(Debug, Deserialize)]
pub struct NewLogEntry {
    pub severity: String,
    pub user: String,
    pub message: String,
    pub host: String,
    #[serde(default)]
    pub event_time: Option<DateTime<Utc>>,
}

impl NewLogEntry {
    pub fn is_valid(&self) -> bool {
        !self.severity.trim().is_empty()
            && !self.user.trim().is_empty()
            && !self.message.trim().is_empty()
            && !self.host.trim().is_empty()
            && self.host.len() <= 255
            && self.severity.len() <= 20
            && self.user.len() <= 255
            && self.message.len() <= 5000
    }
}

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    // Only meaningful when mfa_required is false -- while a second factor
    // is still outstanding, the caller has no session yet, so this is
    // always false in that response.
    pub must_change_password: bool,
    pub mfa_required: bool,
    // Present only when mfa_required is true. Not a session credential --
    // it proves the password was already checked and identifies which
    // account for /mfa/login-verify, nothing more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    pub otpauth_url: String,
    // Base32, for authenticator apps (Aegis included) that offer "enter
    // code manually" instead of scanning the QR.
    pub secret_base32: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaCodeRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    // Re-proves identity before turning MFA off, same spirit as
    // change-password requiring the current password.
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaLoginVerifyRequest {
    pub pending_token: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateUserRequest {
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub hostname: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub agent_id: i32,
    pub api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AddPathRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct AgentConfigResponse {
    pub hostname: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EnrollmentTokenResponse {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct SelfRegisterRequest {
    pub enrollment_token: String,
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentPackageRequest {
    #[serde(default)]
    pub label: Option<String>,
    pub max_uses: i64,
    pub expires_days: i64,
}

#[derive(Debug, Serialize)]
pub struct DeploymentPackageResponse {
    pub token_id: i32,
    // Shown once, same as any other freshly-issued credential -- never
    // recoverable again after this response (it's stored hashed, like
    // every other token in this system).
    pub script: String,
    pub gpo_instructions: String,
    pub intune_instructions: String,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct NotificationChannel {
    pub id: i32,
    pub kind: String,
    pub name: String,
    pub config: String, // raw JSON string; parsed per-kind only in notify.rs
    pub min_severity: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub kind: String,
    pub name: String,
    pub config: serde_json::Value, // accepted as arbitrary JSON, re-serialized to String for storage
    pub min_severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscordConfig {
    pub webhook_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NtfyConfig {
    pub server_url: String,
    pub topic: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenericWebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

// --- Directory (LDAP/Active Directory) sync ---

#[derive(Debug, Deserialize)]
pub struct LdapConfigRequest {
    pub enabled: bool,
    pub server_uri: String,
    pub bind_dn: String,
    // None/omitted leaves the currently-saved password untouched --
    // same "write-only, shown once" shape as the agent API key. Only a
    // non-empty value here triggers a re-encrypt-and-store.
    #[serde(default)]
    pub bind_password: Option<String>,
    pub base_dn: String,
    pub computer_filter: String,
    pub sync_interval_minutes: i64,
    // Directory-backed dashboard login (Phase 2) -- same connection,
    // a second consumer of it. See README: Directory login.
    pub login_enabled: bool,
    #[serde(default)]
    pub user_base_dn: String,
    #[serde(default)]
    pub user_filter_template: String,
    #[serde(default)]
    pub admin_group_dn: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LdapConfigResponse {
    pub enabled: bool,
    pub server_uri: String,
    pub bind_dn: String,
    // The bind password itself is never sent back to the browser --
    // this just tells the UI whether one has been saved, so it can
    // render "configured" instead of an empty field.
    pub password_configured: bool,
    pub base_dn: String,
    pub computer_filter: String,
    pub sync_interval_minutes: i64,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_status: Option<String>,
    pub last_sync_count: Option<i64>,
    pub master_key_configured: bool,
    pub login_enabled: bool,
    pub user_base_dn: String,
    pub user_filter_template: String,
    pub admin_group_dn: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DirectorySyncResponse {
    pub hosts_found: usize,
}

#[derive(Debug, Serialize)]
pub struct DiscoveredHostResponse {
    pub id: i32,
    pub hostname: String,
    pub distinguished_name: String,
    pub operating_system: Option<String>,
    pub organizational_unit: Option<String>,
    pub ad_last_logon: Option<chrono::DateTime<chrono::Utc>>,
    pub first_seen_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_in_ad: chrono::DateTime<chrono::Utc>,
    // Best-effort short-hostname match against `agents` -- see
    // db::list_discovered_hosts. A hint for the UI, not a guarantee.
    pub likely_enrolled: bool,
    pub agent_id: Option<i32>,
    pub stale: bool,
}
