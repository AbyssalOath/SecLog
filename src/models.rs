use serde::{Deserialize, Serialize};
 
// Used internally by the CLI parser (parser.rs) -- never sent over the wire
// directly. What gets sent to the API is a String ("Low"/"Medium"/etc),
// built via format!("{:?}", ...) on this enum.
#[derive(Debug)]
pub struct LogEntry {
    pub severity: Severity,
    pub user: String,
    pub message: String,
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
 
// What the CLIENT sends us as JSON. severity travels as a plain String
// ("Low"/"Medium"/"High"/"Critical") -- the Severity enum above is only
// used internally during file-based parsing, not over HTTP.
#[derive(Debug, Deserialize)]
pub struct NewLogEntry {
    pub severity: String,
    pub user: String,
    pub message: String,
    pub host: String,
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
    pub must_change_password: bool,
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
