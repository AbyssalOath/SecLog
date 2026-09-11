// Reversible secret encryption -- deliberately separate from auth.rs.
//
// Every credential auth.rs deals with (passwords, session tokens, agent
// API keys, enrollment tokens) only ever needs to be VERIFIED: hash it,
// compare hashes, done. The LDAP bind password is the first secret in
// this codebase that SecLog has to hand back to a third party (the
// directory server) on every sync, so it has to be recoverable. Mixing
// "one-way, can never be recovered" and "two-way, recoverable by design"
// in one file would make it too easy for a future change to blur which
// is which -- keeping them apart is the point.

use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};

pub const MASTER_KEY_ENV_VAR: &str = "SECLOG_MASTER_KEY";

#[derive(Clone)]
pub struct MasterKey(Key<Aes256Gcm>);

impl MasterKey {
    /// Reads and decodes SECLOG_MASTER_KEY from the environment, if set.
    /// A directory bind password can only be saved once this returns
    /// Some -- see the /directory/config handler in main.rs. Absent by
    /// default so existing deployments that never touch directory sync
    /// don't need to set anything new just to keep running.
    pub fn from_env() -> Result<Option<Self>, String> {
        let raw = match std::env::var(MASTER_KEY_ENV_VAR) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let bytes = STANDARD
            .decode(raw.trim())
            .map_err(|e| format!("{} is not valid base64: {}", MASTER_KEY_ENV_VAR, e))?;

        if bytes.len() != 32 {
            return Err(format!(
                "{} must decode to exactly 32 bytes (got {}) -- generate one with `openssl rand -base64 32`",
                MASTER_KEY_ENV_VAR,
                bytes.len()
            ));
        }

        let key = Key::<Aes256Gcm>::try_from(bytes.as_slice())
            .map_err(|_| format!("{} could not be loaded as a 256-bit key", MASTER_KEY_ENV_VAR))?;
        Ok(Some(MasterKey(key)))
    }

    /// Encrypts `plaintext`, returning a single base64 string (random
    /// nonce prepended to the ciphertext) safe to store in a TEXT
    /// column. A fresh random nonce is generated per call -- never
    /// reuse a nonce with the same key, which is why this isn't just
    /// "the ciphertext" but "nonce || ciphertext".
    pub fn encrypt(&self, plaintext: &str) -> Result<String, String> {
        let cipher = Aes256Gcm::new(&self.0);
        let nonce = Nonce::generate();
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("encryption failed: {}", e))?;

        let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(combined))
    }

    /// Reverses `encrypt`. Fails closed on any tampering or corruption
    /// (wrong key, truncated blob, flipped bit) -- AES-GCM is
    /// authenticated, so a bad decrypt is a hard error, never silently
    /// wrong plaintext.
    pub fn decrypt(&self, stored: &str) -> Result<String, String> {
        let combined = STANDARD
            .decode(stored)
            .map_err(|e| format!("stored secret is not valid base64: {}", e))?;

        if combined.len() < 12 {
            return Err("stored secret is too short to contain a nonce".to_string());
        }
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::try_from(nonce_bytes)
            .map_err(|_| "stored secret has an invalid nonce".to_string())?;

        let cipher = Aes256Gcm::new(&self.0);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| "decryption failed (wrong master key, or the value was tampered with)".to_string())?;

        String::from_utf8(plaintext).map_err(|e| format!("decrypted secret is not valid UTF-8: {}", e))
    }
}
