use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use rand::distr::Alphanumeric;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use totp_rs::{Algorithm, Secret, TOTP};

// Tracks recent failed login attempts per username. Wrapped in a Mutex so
// multiple concurrent requests can safely read/modify it -- Rust won't let
// you share mutable data across threads without some synchronization
// mechanism like this; it's not optional boilerplate, it's what prevents
// data races
pub struct LoginRateLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
}

const MAX_ATTEMPTS: usize = 5;
const WINDOW: Duration = Duration::from_secs(15 * 60); // 15 minutes

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        LoginRateLimiter {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    // Returns true if this username is currently allowed to attempt login.
    pub fn check (&self, username: &str) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Instant::now();

        let entry = attempts.entry(username.to_string()).or_default();
        // Drop attempts older than the window -- only recent failures count.
        entry.retain(|&t| now.duration_since(t) < WINDOW);

        entry.len() < MAX_ATTEMPTS
    }

    // Call this after a failed password check.
    pub fn record_failure(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.entry(username.to_string()).or_default().push(Instant::now());
    }

    // Call this after a successful login -- clears their slate
    pub fn record_success(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(username);
    }
}

// Takes a plaintext password, returns a hash string safe to store in the DB.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    // OsRng pulls randomness from the operating system's secure random
    // source -- not Rust's general-purpose rand, but a cryptographically
    // secure on, which matters for anything security-sensitive like a salt.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    // hash_password returns PasswordHash struct; .to_string() gives us
    // the full encoded string (algorithm + salt + hash all together) that
    // we can store directly in the password_hash column.
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

// Takes a plaintext password attempt and a stored hash, returns true/false.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false, // malformed hash in DB -- treat as failure, don't panic
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Hashes a bearer-style credential before it is stored in the database.
///
/// The plaintext token is returned to the caller and is only used by the
/// client/agent. The database stores only this SHA-256 digest.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

// Generates a random 64-character alphanumeric string to use as a session
// token. Unlike a password, this doesn't need hashing -- it's not secret
// input from a user, it's random data WE generate specifically to be
// hard to guess.
pub fn generate_session_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

// Generates a cryptographically random temporary password.
// The plaintext is returned to the caller so it can be displayed once,
// but it must never be stored in the database.
pub fn generate_temporary_password() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

// --- Multi-Factor Authentication (TOTP, RFC 6238) ---
//
// Standard 6-digit / 30-second / SHA1 TOTP -- deliberately the most
// widely-compatible combination, since that's what nearly every
// authenticator app (Aegis, Google Authenticator, Authy, 1Password,
// Bitwarden, etc.) assumes by default. Some apps silently fall back to
// SHA1 even when a QR advertises SHA256/SHA512 and just fail to match,
// so we don't offer those as an option here.
const MFA_ISSUER: &str = "SecLog";

// We store the secret in the DB as our own hex string (matching the hex
// pattern already used for token hashes in this file) rather than as
// base32 -- base32 is only a wire/display format TOTP needs for QR/manual
// entry, not a storage requirement. `mfa_secret_from_hex` reverses this
// whenever we need to rebuild a `TOTP` struct.
pub fn generate_mfa_secret_hex() -> Result<String, String> {
    let bytes = Secret::generate_secret()
        .to_bytes()
        .map_err(|e| format!("{:?}", e))?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

fn mfa_secret_from_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn build_totp(secret_hex: &str, username: &str) -> Option<TOTP> {
    let bytes = mfa_secret_from_hex(secret_hex)?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,  // skew: accept the previous/next 30s step too, to absorb
            // ordinary phone clock drift without widening the window
            // enough to matter for security.
        30,
        bytes,
        Some(MFA_ISSUER.to_string()),
        username.to_string(),
    )
    .ok()
}

// Everything an authenticator app needs to provision this account: a
// scannable otpauth:// URL (rendered as a QR code client-side) and the
// same secret spelled out in base32 for apps -- like Aegis -- that offer
// "enter code manually" as an alternative to scanning.
pub struct MfaProvisioning {
    pub otpauth_url: String,
    pub secret_base32: String,
}

pub fn mfa_provisioning(secret_hex: &str, username: &str) -> Option<MfaProvisioning> {
    let totp = build_totp(secret_hex, username)?;
    Some(MfaProvisioning {
        otpauth_url: totp.get_url(),
        secret_base32: totp.get_secret_base32(),
    })
}

// Verifies a 6-digit code against a stored secret, allowing the ~30s of
// clock skew configured above.
pub fn verify_totp_code(secret_hex: &str, username: &str, code: &str) -> bool {
    match build_totp(secret_hex, username) {
        Some(totp) => totp.check_current(code).unwrap_or(false),
        None => false,
    }
}
