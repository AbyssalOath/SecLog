// External archival storage (S3-compatible object storage, or SFTP) --
// lets the retention loop (main.rs) ship rows off to cold storage
// before deleting them, instead of only ever deleting.
//
// Both upload paths are pure-Rust/tokio-native (rusty-s3 + reqwest for
// S3, russh + russh-sftp for SFTP) -- no new apt packages needed in the
// Dockerfile, matching why ldap3/sqlx are already pinned to rustls
// over OpenSSL elsewhere in this codebase.
//
// SFTP host keys are NOT verified against a known-hosts store (see
// `SftpClient::check_server_key` below) -- there's no host-key-pinning
// UI in this pass, so trust here rests on the admin having typed in
// the right hostname, the same tradeoff already accepted for `ldap://`
// vs `ldaps://` (README recommends TLS/a trusted network, doesn't
// enforce it). Documented, not silently assumed.

use crate::crypto::MasterKey;
use crate::db::{self, ArchiveConfigRow, ArchiveLogRow, DbPool};
use rusty_s3::S3Action;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

// Large uploads to a remote host warrant an explicit timeout for the
// same reason the shipper's own outbound HTTP client needed one this
// session: an archival upload that hangs forever would silently stall
// the retention loop, which is a worse failure mode than a slow
// webhook (disk fills up behind it, not just a delayed notification).
const S3_UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);

pub struct S3Params<'a> {
    pub endpoint: &'a str,
    pub bucket: &'a str,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub path_style: bool,
}

pub async fn upload_s3(params: S3Params<'_>, key: &str, body: Vec<u8>) -> Result<(), String> {
    let endpoint: url::Url = params.endpoint.parse().map_err(|e| format!("invalid S3 endpoint: {e}"))?;
    let url_style = if params.path_style { rusty_s3::UrlStyle::Path } else { rusty_s3::UrlStyle::VirtualHost };
    let bucket = rusty_s3::Bucket::new(endpoint, url_style, params.bucket.to_string(), params.region.to_string())
        .map_err(|e| format!("invalid S3 bucket config: {e}"))?;
    let credentials = rusty_s3::Credentials::new(params.access_key.to_string(), params.secret_key.to_string());

    let action = rusty_s3::actions::PutObject::new(&bucket, Some(&credentials), key);
    let signed_url = action.sign(Duration::from_secs(300));

    let client = reqwest::Client::builder()
        .timeout(S3_UPLOAD_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build S3 HTTP client: {e}"))?;

    let response = client
        .put(signed_url)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("S3 upload request failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("S3 upload rejected: HTTP {status} -- {text}"));
    }
    Ok(())
}

pub struct SftpParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub username: &'a str,
    // Exactly one of these should be Some -- password auth or
    // key auth, admin's choice (see the "Archival Storage" panel).
    pub password: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub remote_path: &'a str,
}

struct SftpClient;

impl russh::client::Handler for SftpClient {
    type Error = russh::Error;

    // See the module comment: no host-key verification in this pass.
    // (russh 0.63 widened this parameter from a plain PublicKey to
    // PublicKeyOrCertificate, since the server side of a handshake can
    // now present an OpenSSH certificate instead of a bare key -- we
    // still accept unconditionally either way.)
    async fn check_server_key(&mut self, _server_public_key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

pub async fn upload_sftp(params: SftpParams<'_>, filename: &str, body: Vec<u8>) -> Result<(), String> {
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, (params.host, params.port), SftpClient)
        .await
        .map_err(|e| format!("SFTP connection failed: {e}"))?;

    let authenticated = if let Some(pem) = params.private_key {
        let key = russh::keys::decode_secret_key(pem, None)
            .map_err(|e| format!("failed to parse SFTP private key: {e}"))?;
        let key_with_alg = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
        session
            .authenticate_publickey(params.username, key_with_alg)
            .await
            .map_err(|e| format!("SFTP public-key auth failed: {e}"))?
    } else {
        let password = params.password.unwrap_or("");
        session
            .authenticate_password(params.username, password)
            .await
            .map_err(|e| format!("SFTP password auth failed: {e}"))?
    };

    if !authenticated.success() {
        return Err("SFTP authentication rejected -- check username/password/private key".to_string());
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("SFTP channel open failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem request failed: {e}"))?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP session init failed: {e}"))?;

    let remote_path = params.remote_path.trim_end_matches('/');
    let full_path = if remote_path.is_empty() {
        filename.to_string()
    } else {
        format!("{remote_path}/{filename}")
    };

    let mut file = sftp
        .open_with_flags(
            &full_path,
            russh_sftp::protocol::OpenFlags::CREATE | russh_sftp::protocol::OpenFlags::TRUNCATE | russh_sftp::protocol::OpenFlags::WRITE,
        )
        .await
        .map_err(|e| format!("failed to open remote file {full_path}: {e}"))?;

    file.write_all(&body).await.map_err(|e| format!("SFTP write failed: {e}"))?;
    file.shutdown().await.map_err(|e| format!("SFTP file close failed: {e}"))?;

    Ok(())
}

// --- Orchestration, called from the retention loop in main.rs ---

fn decrypt_secret(master_key: Option<&MasterKey>, encrypted: Option<&str>, what: &str) -> Result<String, String> {
    let encrypted = encrypted.ok_or_else(|| format!("no {what} configured"))?;
    let key = master_key.ok_or_else(|| format!("SECLOG_MASTER_KEY is not set -- cannot decrypt the stored {what}"))?;
    key.decrypt(encrypted).map_err(|e| format!("failed to decrypt stored {what}: {e}"))
}

async fn upload_archive(
    cfg: &ArchiveConfigRow,
    master_key: Option<&MasterKey>,
    kind: &str,
    rows: &[ArchiveLogRow],
) -> Result<String, String> {
    let mut body = Vec::new();
    for row in rows {
        let line = serde_json::to_string(row).map_err(|e| e.to_string())?;
        body.extend_from_slice(line.as_bytes());
        body.push(b'\n');
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("{kind}-{timestamp}-{}rows.jsonl", rows.len());

    match cfg.backend.as_str() {
        "s3" => {
            let secret_key = decrypt_secret(master_key, cfg.s3_secret_key_encrypted.as_deref(), "S3 secret key")?;
            let key = format!("seclog-logs/{filename}");
            upload_s3(
                S3Params {
                    endpoint: &cfg.s3_endpoint,
                    bucket: &cfg.s3_bucket,
                    region: &cfg.s3_region,
                    access_key: &cfg.s3_access_key,
                    secret_key: &secret_key,
                    path_style: cfg.s3_path_style,
                },
                &key,
                body,
            )
            .await?;
            Ok(key)
        }
        "sftp" => {
            let password = match &cfg.sftp_password_encrypted {
                Some(_) => Some(decrypt_secret(master_key, cfg.sftp_password_encrypted.as_deref(), "SFTP password")?),
                None => None,
            };
            let private_key = match &cfg.sftp_private_key_encrypted {
                Some(_) => Some(decrypt_secret(master_key, cfg.sftp_private_key_encrypted.as_deref(), "SFTP private key")?),
                None => None,
            };
            upload_sftp(
                SftpParams {
                    host: &cfg.sftp_host,
                    port: cfg.sftp_port as u16,
                    username: &cfg.sftp_username,
                    password: password.as_deref(),
                    private_key: private_key.as_deref(),
                    remote_path: &cfg.sftp_remote_path,
                },
                &filename,
                body,
            )
            .await?;
            Ok(filename)
        }
        other => Err(format!("unknown archive backend '{other}'")),
    }
}

// Archives rows about to be aged out, then deletes exactly what
// db::delete_logs_older_than would have deleted anyway -- on an upload
// failure, the delete is skipped for this cycle entirely (never lose
// data behind a failed archive), matching db::delete_logs_older_than's
// own return shape so main.rs's retention loop needs no branching
// beyond "which function do I call."
pub async fn archive_and_delete_older_than(pool: &DbPool, days: i64, master_key: Option<&MasterKey>) -> Result<u64, sqlx::Error> {
    let cfg = db::get_archive_config(pool).await?;
    if !cfg.enabled || cfg.backend == "none" {
        return db::delete_logs_older_than(pool, days).await;
    }

    let rows = db::select_logs_older_than(pool, days).await?;
    if rows.is_empty() {
        return Ok(0);
    }

    match upload_archive(&cfg, master_key, "age", &rows).await {
        Ok(_) => {
            let _ = db::record_archive_result(pool, "ok", Some(rows.len() as i64)).await;
            db::delete_logs_older_than(pool, days).await
        }
        Err(e) => {
            eprintln!("Archive upload failed (age-based purge skipped this cycle): {e}");
            let _ = db::record_archive_result(pool, "failed", None).await;
            crate::notify::trigger_alert(
                pool, "High",
                &format!("[SYSTEM] Log archival failed, age-based retention purge skipped this cycle: {e}"),
                "seclog-server",
            ).await;
            Ok(0)
        }
    }
}

// Same shape as archive_and_delete_older_than, for the row-cap purge.
pub async fn archive_and_delete_beyond_row_cap(pool: &DbPool, max_rows: i64, master_key: Option<&MasterKey>) -> Result<u64, sqlx::Error> {
    let cfg = db::get_archive_config(pool).await?;
    if !cfg.enabled || cfg.backend == "none" {
        return db::enforce_max_log_rows(pool, max_rows).await;
    }

    let rows = db::select_logs_beyond_row_cap(pool, max_rows).await?;
    if rows.is_empty() {
        return Ok(0);
    }

    match upload_archive(&cfg, master_key, "rowcap", &rows).await {
        Ok(_) => {
            let _ = db::record_archive_result(pool, "ok", Some(rows.len() as i64)).await;
            db::enforce_max_log_rows(pool, max_rows).await
        }
        Err(e) => {
            eprintln!("Archive upload failed (row-cap purge skipped this cycle): {e}");
            let _ = db::record_archive_result(pool, "failed", None).await;
            crate::notify::trigger_alert(
                pool, "High",
                &format!("[SYSTEM] Log archival failed, row-cap retention purge skipped this cycle: {e}"),
                "seclog-server",
            ).await;
            Ok(0)
        }
    }
}

// Backs the Settings "Test Connection" button -- proves reachability
// and credentials with one tiny object/file, without waiting on a real
// retention cycle. Never touches `logs` or deletes anything.
pub async fn test_connection(cfg: &ArchiveConfigRow, master_key: Option<&MasterKey>) -> Result<(), String> {
    let body = format!("SecLog archive connection test -- {}\n", chrono::Utc::now().to_rfc3339());
    match cfg.backend.as_str() {
        "s3" => {
            let secret_key = decrypt_secret(master_key, cfg.s3_secret_key_encrypted.as_deref(), "S3 secret key")?;
            upload_s3(
                S3Params {
                    endpoint: &cfg.s3_endpoint,
                    bucket: &cfg.s3_bucket,
                    region: &cfg.s3_region,
                    access_key: &cfg.s3_access_key,
                    secret_key: &secret_key,
                    path_style: cfg.s3_path_style,
                },
                "seclog-logs/connection-test.txt",
                body.into_bytes(),
            )
            .await
        }
        "sftp" => {
            let password = match &cfg.sftp_password_encrypted {
                Some(_) => Some(decrypt_secret(master_key, cfg.sftp_password_encrypted.as_deref(), "SFTP password")?),
                None => None,
            };
            let private_key = match &cfg.sftp_private_key_encrypted {
                Some(_) => Some(decrypt_secret(master_key, cfg.sftp_private_key_encrypted.as_deref(), "SFTP private key")?),
                None => None,
            };
            upload_sftp(
                SftpParams {
                    host: &cfg.sftp_host,
                    port: cfg.sftp_port as u16,
                    username: &cfg.sftp_username,
                    password: password.as_deref(),
                    private_key: private_key.as_deref(),
                    remote_path: &cfg.sftp_remote_path,
                },
                "seclog-connection-test.txt",
                body.into_bytes(),
            )
            .await
        }
        other => Err(format!("unknown archive backend '{other}'")),
    }
}
