// LDAP/Active Directory connector -- read-only by design. This module
// finds computer objects; it never connects to one of them. Rollout
// (getting the shipper actually running on a discovered machine) stays
// on the existing enrollment-token flow, surfaced per-host from the
// Directory page -- see ARCHITECTURE.md and the roadmap this was
// scoped from for why a push/remote-exec model was deliberately not
// built here.

use chrono::{DateTime, TimeZone, Utc};
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{ldap_escape, LdapConnAsync, Scope, SearchEntry};

use crate::crypto::MasterKey;
use crate::db::{self, DbPool, LdapConfigRow};

// AD returns at most 1000 entries per unpaged search by default; a page
// size well under that keeps each round trip small without needing an
// unreasonable number of pages for a typical-sized domain.
const PAGE_SIZE: i32 = 500;

/// A connectable LDAP configuration -- the bind password here is
/// plaintext, decrypted moments before use, and must never be logged,
/// echoed in an error message, or held longer than the connection
/// attempt that needs it.
pub struct LdapConfig {
    pub server_uri: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    pub computer_filter: String,
    pub login_enabled: bool,
    pub user_base_dn: String,
    pub user_filter_template: String,
    pub admin_group_dn: Option<String>,
}

impl LdapConfig {
    /// Decrypts `row`'s stored bind password using `key`. Fails if no
    /// password has ever been saved, or if it can't be decrypted with
    /// the given key (wrong/rotated SECLOG_MASTER_KEY).
    pub fn from_row(row: &LdapConfigRow, key: &MasterKey) -> Result<Self, String> {
        let encrypted = row
            .bind_password_encrypted
            .as_deref()
            .ok_or("no bind password has been saved yet")?;

        Ok(LdapConfig {
            server_uri: row.server_uri.clone(),
            bind_dn: row.bind_dn.clone(),
            bind_password: key.decrypt(encrypted)?,
            base_dn: row.base_dn.clone(),
            computer_filter: row.computer_filter.clone(),
            login_enabled: row.login_enabled,
            user_base_dn: row.user_base_dn.clone(),
            user_filter_template: row.user_filter_template.clone(),
            admin_group_dn: row.admin_group_dn.clone(),
        })
    }
}

pub struct DiscoveredComputer {
    pub hostname: String,
    pub distinguished_name: String,
    pub operating_system: Option<String>,
    pub organizational_unit: Option<String>,
    pub ad_last_logon: Option<DateTime<Utc>>,
}

/// Opens a connection and attempts a simple bind, nothing else. Backs
/// the Directory page's "Test Connection" button -- lets an admin
/// validate the service account and URI before saving, or re-check a
/// saved config without waiting for the next scheduled sync.
pub async fn test_connection(config: &LdapConfig) -> Result<(), String> {
    let (conn, mut ldap) = LdapConnAsync::new(&config.server_uri)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    ldap3::drive!(conn);

    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .map_err(|e| format!("bind failed: {}", e))?
        .success()
        .map_err(|e| format!("bind rejected: {}", e))?;

    let _ = ldap.unbind().await;
    Ok(())
}

pub struct LdapAuthResult {
    /// True only if `admin_group_dn` is configured AND the
    /// authenticated user's `memberOf` includes it. No config means no
    /// one is ever auto-admin through this path.
    pub is_admin: bool,
}

/// Verifies a username/password pair against the directory: search for
/// the user (as the service account), then bind AS THAT USER with the
/// password they supplied -- the second bind is what actually proves
/// the password is correct, the search alone proves nothing.
///
/// Deliberately does not say *why* a given attempt failed (wrong
/// password vs. no such user vs. more than one match) -- the caller
/// only gets "authentication failed," so a login response can't be used
/// to enumerate directory usernames.
pub async fn authenticate_user(
    config: &LdapConfig,
    username: &str,
    password: &str,
) -> Result<LdapAuthResult, String> {
    // Never attempt a simple bind with an empty password: many LDAP/AD
    // servers treat that as an ANONYMOUS bind and report success
    // without checking anything at all. Left unhandled, that turns
    // "submit a blank password" into an authentication bypass. This
    // check has to come before any network call, not after.
    if password.is_empty() {
        return Err("empty password".to_string());
    }

    let (search_conn, mut search_ldap) = LdapConnAsync::new(&config.server_uri)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    ldap3::drive!(search_conn);

    search_ldap
        .simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .map_err(|e| format!("service bind failed: {}", e))?
        .success()
        .map_err(|e| format!("service bind rejected: {}", e))?;

    // ldap_escape (from the ldap3 crate) applies the RFC 4515 escaping
    // rules -- without it, a username containing '(', ')', '*', '\', or
    // NUL could alter the filter's structure instead of just being
    // searched for as literal text.
    let filter = config
        .user_filter_template
        .replace("{username}", &ldap_escape(username));

    let (entries, _res) = search_ldap
        .search(&config.user_base_dn, Scope::Subtree, &filter, vec!["memberOf"])
        .await
        .map_err(|e| format!("user search failed: {}", e))?
        .success()
        .map_err(|e| format!("user search did not complete cleanly: {}", e))?;

    let _ = search_ldap.unbind().await;

    // Anything but exactly one match is a failure -- an ambiguous
    // filter is not a "pick the first one" situation for something
    // that grants a login.
    if entries.len() != 1 {
        return Err("no unique matching directory entry".to_string());
    }
    let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
    let user_dn = entry.dn.clone();

    // A fresh connection for the actual credential check -- this bind,
    // not the search above, is what proves the password is correct.
    let (auth_conn, mut auth_ldap) = LdapConnAsync::new(&config.server_uri)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    ldap3::drive!(auth_conn);

    auth_ldap
        .simple_bind(&user_dn, password)
        .await
        .map_err(|e| format!("bind failed: {}", e))?
        .success()
        .map_err(|_| "invalid credentials".to_string())?;

    let _ = auth_ldap.unbind().await;

    let is_admin = match &config.admin_group_dn {
        Some(admin_dn) => entry
            .attrs
            .get("memberOf")
            .map(|groups| groups.iter().any(|g| g.eq_ignore_ascii_case(admin_dn)))
            .unwrap_or(false),
        None => false,
    };

    Ok(LdapAuthResult { is_admin })
}

/// Binds, then walks `computer_filter` under `base_dn` with the
/// paged-results control (required -- AD silently caps an unpaged
/// search at 1000 entries, which a real domain can exceed easily).
/// Read-only: no writes are ever sent to the directory.
async fn fetch_computers(config: &LdapConfig) -> Result<Vec<DiscoveredComputer>, String> {
    let (conn, mut ldap) = LdapConnAsync::new(&config.server_uri)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    ldap3::drive!(conn);

    ldap.simple_bind(&config.bind_dn, &config.bind_password)
        .await
        .map_err(|e| format!("bind failed: {}", e))?
        .success()
        .map_err(|e| format!("bind rejected: {}", e))?;

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(PAGE_SIZE)),
    ];

    let mut search = ldap
        .streaming_search_with(
            adapters,
            &config.base_dn,
            Scope::Subtree,
            &config.computer_filter,
            vec!["dNSHostName", "cn", "operatingSystem", "lastLogonTimestamp"],
        )
        .await
        .map_err(|e| format!("search failed: {}", e))?;

    let mut results = Vec::new();
    while let Some(entry) = search
        .next()
        .await
        .map_err(|e| format!("search failed while paging: {}", e))?
    {
        results.push(parse_computer_entry(SearchEntry::construct(entry)));
    }

    search
        .finish()
        .await
        .success()
        .map_err(|e| format!("search did not complete cleanly: {}", e))?;

    let _ = ldap.unbind().await;
    Ok(results)
}

fn parse_computer_entry(entry: SearchEntry) -> DiscoveredComputer {
    let hostname = entry
        .attrs
        .get("dNSHostName")
        .and_then(|v| v.first())
        .cloned()
        .or_else(|| entry.attrs.get("cn").and_then(|v| v.first()).cloned())
        .unwrap_or_else(|| entry.dn.clone());

    let operating_system = entry.attrs.get("operatingSystem").and_then(|v| v.first()).cloned();
    let organizational_unit = parent_ou(&entry.dn);
    let ad_last_logon = entry
        .attrs
        .get("lastLogonTimestamp")
        .and_then(|v| v.first())
        .and_then(|s| parse_ad_filetime(s));

    DiscoveredComputer {
        hostname,
        distinguished_name: entry.dn,
        operating_system,
        organizational_unit,
        ad_last_logon,
    }
}

// Everything after a DN's leading RDN (e.g. strips "CN=WS01," from
// "CN=WS01,OU=Workstations,OU=Corp,DC=example,DC=com"), which is the
// object's containing OU/container path. Not a full RFC 4514 DN parser
// -- AD's computer DNs don't contain the escaped-comma edge cases that
// would require one, so a plain split is enough here.
fn parent_ou(dn: &str) -> Option<String> {
    let comma = dn.find(',')?;
    Some(dn[comma + 1..].to_string())
}

// AD's *Timestamp attributes are Windows FILETIME: the number of
// 100-nanosecond intervals since 1601-01-01T00:00:00Z. "0" or "not
// set" (the account has never logged on, or the attribute is absent)
// both come back as None rather than as a bogus 1601 or 1970 date.
fn parse_ad_filetime(raw: &str) -> Option<DateTime<Utc>> {
    let ticks: i64 = raw.parse().ok()?;
    if ticks <= 0 {
        return None;
    }

    const FILETIME_TO_UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    let unix_ticks = ticks.checked_sub(FILETIME_TO_UNIX_EPOCH_TICKS)?;
    if unix_ticks < 0 {
        return None;
    }

    let secs = unix_ticks / 10_000_000;
    let nanos = ((unix_ticks % 10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nanos).single()
}

/// Fetches every computer object and upserts it into `discovered_hosts`,
/// recording the outcome on `ldap_config` either way so the Directory
/// page can show "last synced ... (ok / failed: ...)" without a
/// separate status check.
pub async fn sync_computers(pool: &DbPool, config: &LdapConfig) -> Result<usize, String> {
    let result = fetch_computers(config).await;

    match &result {
        Ok(computers) => {
            let _ = db::record_ldap_sync_result(pool, "ok", Some(computers.len() as i64)).await;
        }
        Err(_) => {
            let _ = db::record_ldap_sync_result(pool, "failed", None).await;
        }
    }

    let computers = result?;
    let count = computers.len();

    for c in computers {
        db::upsert_discovered_host(
            pool,
            &c.hostname,
            &c.distinguished_name,
            c.operating_system.as_deref(),
            c.organizational_unit.as_deref(),
            c.ad_last_logon,
        )
        .await
        .map_err(|e| format!("failed to store {}: {}", c.hostname, e))?;
    }

    Ok(count)
}
