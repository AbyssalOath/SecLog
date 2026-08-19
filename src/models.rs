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
