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

        let entry = attempts.entry(username.to_string()).or_insert_with(Vec::new);
        // Drop attempts older than the window -- only recent failures count.
        entry.retain(|&t| now.duration_since(t) < WINDOW);

        entry.len() < MAX_ATTEMPTS
    }

    // Call this after a failed password check.
    pub fn record_failure(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.entry(username.to_string()).or_insert_with(Vec::new).push(Instant::now());
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
