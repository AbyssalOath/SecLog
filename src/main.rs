use axum::{
    extract::{FromRequestParts, State, Path, Query},
    routing::{get, post},
    http::{request::Parts, StatusCode, HeaderMap},
    Json,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use models::{NewLogEntry, SignupRequest, LoginRequest, MfaCodeRequest, MfaDisableRequest, MfaLoginVerifyRequest, LdapConfigRequest};
use seclog::{
    archive,
    auth::{self, LoginRateLimiter},
    crypto::{self, MasterKey},
    db,
    directory,
    models,
    parser,
    notify,
    syslog,
};
use std::{env, sync::Arc};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::CACHE_CONTROL;

// include_str! embeds the file's contents into the binary at COMPILE
// time -- the running server always knows exactly what version it is,
// with zero runtime file dependency.
const VERSION: &str = include_str!("../VERSION");

#[derive(serde::Serialize)]
struct VersionResponse {
    version: String,
    latest_version: Option<String>,
    update_available: bool,
}

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
}

async fn check_latest_version() -> Option<String> {
    // Explicit timeout is the whole point here -- reqwest's default
    // client waits indefinitely (falling back to the OS's own TCP
    // timeout, which can be minutes). Without this, a slow/unreachable
    // GitHub call can stall this request far longer than the version
    // check is worth -- and since the frontend awaits /version before
    // /logs, that stall was blocking the dashboard's detections too.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;

    let resp = client
        .get("https://api.github.com/repos/AbyssalOath/SecLog/releases/latest")
        .header("User-Agent", "seclog") // GitHub's API requires a User-Agent header
        .send()
        .await
        .ok()?;

    let release: GithubRelease = resp.json().await.ok()?;
    Some(release.tag_name.trim_start_matches('v').to_string())
}

fn parse_version(v: &str) -> Vec<u32> {
    v.split('.').filter_map(|p| p.parse().ok()).collect()
}

fn is_newer(latest: &str, current: &str) -> bool {
    parse_version(latest) > parse_version(current)
}

async fn version() -> Json<VersionResponse> {
    let current = VERSION.trim().to_string();
    let latest = check_latest_version().await;
    let update_available = latest
        .as_deref()
        .map(|l| is_newer(l, &current))
        .unwrap_or(false);

    Json(VersionResponse {
        version: current,
        latest_version: latest,
        update_available,
    })
}

fn base_url_from_headers(headers: &HeaderMap) -> String {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:3000");

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or("http");

    format!("{}://{}", scheme, host)
}

// Trusts X-Forwarded-For for the same reason self_register_agent
// originally did: Caddy/the reverse proxy is the only thing that can
// reach this service directly (app:3000 isn't published to the host).
// Shared here so every audit-logged handler gets the same IP-extraction
// logic instead of it being copy-pasted at each call site.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or("unknown")
        .to_string()
}

// Axum handler can only receive specific kinds of arguments. To give every
// handler access to the DB pool, we wrap it in "shared state" that axum
// passes in automatically per-request. Arc = "atomic reference count",
// a way to share one value across many place safely, even across
// concurrent requests -- more on this in a second
#[derive(Clone)]
struct AppState {
    pool: db::DbPool,
    rate_limiter: Arc<LoginRateLimiter>,
    register_rate_limiter: Arc<LoginRateLimiter>,
    mfa_rate_limiter: Arc<LoginRateLimiter>,
    agent_register_rate_limiter: Arc<LoginRateLimiter>,
    // Absent unless SECLOG_MASTER_KEY is set -- see crypto::MasterKey.
    // Existing deployments that never touch directory sync don't need
    // to set it just to keep running; saving an LDAP bind password
    // without it fails loudly instead of ever storing one unencrypted.
    master_key: Option<MasterKey>,
}

async fn create_log(
    State(state): State<AppState>,
    agent: AgentAuth,
    Json(payload): Json<NewLogEntry>,
) -> Result<StatusCode, StatusCode> {
    if !payload.is_valid() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let event_time = parser::sanitize_event_time(payload.event_time);
    if let Some(et) = event_time {
        let skew = (chrono::Utc::now() - et).num_minutes().abs();
        if skew > parser::EVENT_TIME_SKEW_WARN_MINUTES {
            eprintln!(
                "Clock skew: {} reported an event {} min from server time (event_time={})",
                agent.hostname, skew, et
            );
        }
        if skew > parser::EVENT_TIME_SKEW_ALERT_MINUTES {
            let pool = state.pool.clone();
            let host = agent.hostname.clone();
            tokio::spawn(async move {
                notify::trigger_alert(
                    &pool,
                    "Medium",
                    &format!("[SYSTEM] Clock skew of {} minutes detected -- check NTP on this host", skew),
                    &host,
                )
                .await;
            });
        }
    }

    let combined = format!("{}{}{}{}", payload.severity, payload.user, payload.message, agent.hostname);
    let hash = parser::hash_line(&combined);

    match db::insert_log(&state.pool, &payload.severity, &payload.user, &payload.message, &agent.hostname, &hash, event_time)
        .await
    {
        Ok(true) => {
            let pool = state.pool.clone();
            let severity = payload.severity.clone();
            let message = payload.message.clone();
            let host = agent.hostname.clone();
            tokio::spawn(async move {
                notify::trigger_alert(&pool, &severity, &message, &host).await;
            });
            Ok(StatusCode::CREATED)
        }
        Ok(false) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// This is a handler function. Its signature is what tells axum how to call
// it: State(state) pulls our AppState out automatically. The return type,
// Json<Vec<LogRow>>, tells axum "serialize this to JSON and send it back."
//
// Deliberately per-host and paginated, not "give me everything" -- that
// was the original design, and it's what let a bug (or a genuinely noisy
// host) push 600k+ rows straight into the browser's DOM and crash the tab
// (and the whole machine, since the browser and the Docker host were the
// same box). limit is clamped so a hand-crafted request can't ask for an
// unbounded page either.
// AdminUser-gated per CJIS AU-9 ("restrict access to audit logs to
// authorized personnel"): a "user"-role account can no longer read
// ingested events at all, only an admin can. See README: Directory
// login / CJIS notes for the reasoning.
async fn list_logs(
    State(state): State<AppState>,
    admin: AuditAccess,
    headers: HeaderMap,
    Query(params): Query<models::LogsQuery>,
) -> Result<Json<models::PaginatedLogs>, StatusCode> {
    println!("Logs requested by: {}, host={}", admin.username, params.host);

    // CJIS AU-2/AU-9: records who actually looked at audit data, not
    // just who's allowed to. Fire-and-forget, same as every other
    // record_audit_event call -- this is a read on a page-turn, not
    // worth blocking the dashboard over.
    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "audit.logs.view",
        Some(&format!("host:{}", params.host)), "success", &client_ip(&headers), None,
    ).await;

    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0).max(0);

    let logs = match db::get_logs_for_host(&state.pool, &params.host, limit, offset).await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let total = match db::count_logs_for_host(&state.pool, &params.host).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(models::PaginatedLogs { logs, total, limit, offset }))
}

// Backs the dashboard's default view: one row per host with a severity
// breakdown, instead of a raw log firehose. Cheap regardless of table
// size since it never touches message text, just GROUP BY + COUNT.
async fn logs_summary(
    State(state): State<AppState>,
    admin: AuditAccess,
    headers: HeaderMap,
) -> Result<Json<Vec<models::HostSummaryRow>>, StatusCode> {
    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "audit.logs.view", Some("summary"),
        "success", &client_ip(&headers), None,
    ).await;

    match db::get_host_summary(&state.pool).await {
        Ok(rows) => Ok(Json(rows)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// CJIS AU-6: marks one log row reviewed/investigated -- itself an
// audited action (audit.log.review), which is the natural overlap
// between AU-6 ("review... and document") and AU-2/AU-3.
async fn set_log_review_handler(
    State(state): State<AppState>,
    admin: AuditAccess,
    headers: HeaderMap,
    Path(log_id): Path<i32>,
    Json(payload): Json<models::LogReviewRequest>,
) -> Result<StatusCode, StatusCode> {
    let valid_statuses = ["open", "reviewed", "false_positive"];
    if !valid_statuses.contains(&payload.status.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    db::set_log_review(&state.pool, log_id, admin.user_id, &payload.status, payload.note.as_deref())
        .await
        .map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "audit.log.review",
        Some(&format!("log:{}", log_id)), "success", &client_ip(&headers),
        Some(&format!("status={}", payload.status)),
    ).await;

    Ok(StatusCode::OK)
}

async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<StatusCode, StatusCode> {
    let username = payload.username.trim().to_lowercase();

    if payload.username.trim().is_empty() || payload.password.len() < 15{
        return Err(StatusCode::BAD_REQUEST); // 400: malformed/insufficient input
    }

    if !state.register_rate_limiter.check(&username) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let self_signup_enabled = db::get_self_signup_enabled(&state.pool)
        .await
        .unwrap_or(true); // fail open on read error is fine here -- worse case, an extra signup
                          // attempt gets validated normally by create_user anyway

    let user_count = match db::get_all_users(&state.pool).await {
        Ok(users) => users.len(),
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if user_count > 0 && !self_signup_enabled {
        return Err(StatusCode::FORBIDDEN);
    }

    let hash = auth::hash_password(&payload.password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;


    match db::create_user(&state.pool, &username, &hash).await {
        Ok(Some(_user_id)) => {
            state.register_rate_limiter.record_success(&username);
            Ok(StatusCode::CREATED)
        }

        Ok(None) => {
            state.register_rate_limiter.record_failure(&username);
            Err(StatusCode::CONFLICT)
        }

        Err(e) => {
            eprintln!("DB error: {}", e);
            state.register_rate_limiter.record_failure(&username);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(serde::Serialize)]
struct AdminCreateUserResponse {
    username: String,
    temporary_password: String,
}

async fn admin_create_user(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<models::AdminCreateUserRequest>,
) -> Result<(StatusCode, Json<AdminCreateUserResponse>), StatusCode> {
    let ip = client_ip(&headers);

    if payload.username.trim().is_empty() || payload.username.len() > 255 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Previously unvalidated -- any string could end up in `role`.
    // "auditor" (view/review log & audit data, administer nothing) is
    // the newest of the three.
    if !["admin", "user", "auditor"].contains(&payload.role.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate the temporary password once.
    // This plaintext exists only in memory for this request.
    let temporary_password = auth::generate_temporary_password();

    // Only the Argon2 hash goes into the database.
    let hash = auth::hash_password(&temporary_password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match db::create_user_with_role(
        &state.pool,
        &payload.username,
        &hash,
        &payload.role,
    ).await {
        Ok(Some(user_id)) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.user.create",
                Some(&format!("user:{}", user_id)), "success", &ip,
                Some(&format!("username={} role={}", payload.username, payload.role)),
            ).await;
            Ok((
                StatusCode::CREATED,
                Json(AdminCreateUserResponse {
                    username: payload.username,
                    temporary_password,
                }),
            ))
        }

        Ok(None) => Err(StatusCode::CONFLICT),

        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Shared tail end of a successful login, whether that login needed a
// second factor or not: issue a real session and set the cookie. Only
// ever called once both factors (or the only factor, for non-MFA
// accounts) have actually been proven.
async fn finish_login(
    state: &AppState,
    user_id: i32,
    username: &str,
    must_change_password: bool,
    ip: &str,
) -> Result<(CookieJar, Json<models::LoginResponse>), StatusCode> {
    let token = auth::generate_session_token();

    if let Err(e) = db::create_session(&state.pool, &token, user_id).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // CJIS AU-2 names "logon" explicitly. This is the one shared point
    // where BOTH login paths (with or without MFA) actually grant a
    // session, so it's the single correct place to record success --
    // not earlier, when only the first factor has been proven.
    db::record_audit_event(
        &state.pool, Some(user_id), username, "user.login.success", None, "success", ip, None,
    ).await;

    let cookie = Cookie::build(("__Host-seclog_session", token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build();

    Ok((
        CookieJar::new().add(cookie),
        Json(models::LoginResponse {
            must_change_password,
            mfa_required: false,
            pending_token: None,
        }),
    ))
}

// Loads the directory config, decrypts it, and runs authenticate_user
// against it -- everything login() needs to attempt a directory-backed
// login, in one place. Any failure along the way (login not enabled,
// no master key, bad config, wrong credentials) collapses to a single
// Err -- login() treats all of them identically, as a failed attempt.
async fn authenticate_via_directory(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<directory::LdapAuthResult, String> {
    let config_row = db::get_ldap_config(&state.pool).await.map_err(|e| e.to_string())?;
    if !config_row.login_enabled {
        return Err("directory login is not enabled".to_string());
    }
    let key = state
        .master_key
        .as_ref()
        .ok_or_else(|| format!("{} is not set", crypto::MASTER_KEY_ENV_VAR))?;
    let config = directory::LdapConfig::from_row(&config_row, key)?;
    directory::authenticate_user(&config, username, password).await
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<models::LoginResponse>), StatusCode> {
    let ip = client_ip(&headers);

    if !state.rate_limiter.check(&payload.username) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let existing = db::get_user_for_login(&state.pool, &payload.username)
        .await
        .map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Three cases: a local account (verified exactly as before -- the
    // directory is never even consulted), an already-directory-backed
    // account (re-verified LIVE against the directory every time, never
    // trusted from a cached local row), or no account at all (where a
    // successful directory login JIT-provisions one). A local account
    // can never be shadowed or taken over by a directory entry sharing
    // its username -- see db::create_ldap_user/update_ldap_user_role.
    // Every failure branch below is audited (CJIS AU-2/AU-3(1)) with the
    // source IP -- this is what lets someone brute-forcing usernames or
    // passwords against SecLog itself actually be noticed.
    let (user_id, must_change_password, mfa_enabled) = match existing {
        Some(row) if row.auth_source == "local" => {
            if !auth::verify_password(&payload.password, &row.password_hash) {
                state.rate_limiter.record_failure(&payload.username);
                db::record_audit_event(
                    &state.pool, Some(row.id), &payload.username, "user.login.failure",
                    None, "failure", &ip, Some("invalid password"),
                ).await;
                return Err(StatusCode::UNAUTHORIZED);
            }
            (row.id, row.must_change_password, row.mfa_enabled)
        }
        Some(row) => {
            // row.auth_source == "ldap"
            let result = match authenticate_via_directory(&state, &payload.username, &payload.password).await {
                Ok(r) => r,
                Err(_) => {
                    state.rate_limiter.record_failure(&payload.username);
                    db::record_audit_event(
                        &state.pool, Some(row.id), &payload.username, "user.login.failure",
                        None, "failure", &ip, Some("directory re-verification failed"),
                    ).await;
                    return Err(StatusCode::UNAUTHORIZED);
                }
            };
            let role = if result.is_admin { "admin" } else { "user" };
            if let Err(e) = db::update_ldap_user_role(&state.pool, row.id, role).await {
                eprintln!("DB error: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            (row.id, false, row.mfa_enabled)
        }
        None => {
            let result = match authenticate_via_directory(&state, &payload.username, &payload.password).await {
                Ok(r) => r,
                Err(_) => {
                    state.rate_limiter.record_failure(&payload.username);
                    db::record_audit_event(
                        &state.pool, None, &payload.username, "user.login.failure",
                        None, "failure", &ip, Some("no matching local or directory account"),
                    ).await;
                    return Err(StatusCode::UNAUTHORIZED);
                }
            };
            let role = if result.is_admin { "admin" } else { "user" };
            let user_id = match db::create_ldap_user(&state.pool, &payload.username, role).await {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("DB error: {}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            };
            // Freshly provisioned: no forced password change (there's
            // no local password at all) and MFA hasn't been set up yet.
            (user_id, false, false)
        }
    };

    state.rate_limiter.record_success(&payload.username);

    if !mfa_enabled {
        return finish_login(&state, user_id, &payload.username, must_change_password, &ip).await;
    }

    // Password checked out, but a second factor is still owed -- no
    // session yet, and so no audit "success" event yet either (that
    // happens once finish_login actually grants one, from
    // mfa_login_verify below). Issue a short-lived pending token
    // instead; the client exchanges it (plus a TOTP code) at
    // /mfa/login-verify.
    let pending_token = auth::generate_session_token();
    if let Err(e) = db::create_mfa_pending(&state.pool, &pending_token, user_id).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok((
        CookieJar::new(),
        Json(models::LoginResponse {
            must_change_password: false,
            mfa_required: true,
            pending_token: Some(pending_token),
        }),
    ))
}

async fn mfa_login_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<MfaLoginVerifyRequest>,
) -> Result<(CookieJar, Json<models::LoginResponse>), StatusCode> {
    let ip = client_ip(&headers);

    let (user_id, username, must_change_password) =
        match db::get_mfa_pending(&state.pool, &payload.pending_token).await {
            Ok(Some(row)) => row,
            Ok(None) => return Err(StatusCode::UNAUTHORIZED),
            Err(e) => {
                eprintln!("DB error: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    // MFA attempts are rate-limited by the stable user_id, not
    // by the pending token. This means minting a new pending token
    // does not reset the MFA attempt bucket.
    let mfa_key = user_id.to_string();

    if !state.mfa_rate_limiter.check(&mfa_key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let secret = match db::get_mfa_secret(&state.pool, user_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED), // MFA got disabled mid-flow
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !auth::verify_totp_code(&secret, &username, &payload.code) {
        state.mfa_rate_limiter.record_failure(&mfa_key);
        db::record_audit_event(
            &state.pool, Some(user_id), &username, "user.login.failure",
            None, "failure", &ip, Some("invalid MFA code"),
        ).await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.mfa_rate_limiter.record_success(&mfa_key);

    db::delete_mfa_pending(&state.pool, &payload.pending_token)
        .await
        .map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    finish_login(&state, user_id, &username, must_change_password, &ip).await
}

fn check_same_origin(parts: &Parts) -> Result<(), StatusCode> {
    let method = &parts.method;

    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return Ok(());
    }

    let origin = parts
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok());

    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;

    let scheme = parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .unwrap_or("http");

    let expected = format!("{}://{}", scheme, host);

    match origin {
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(StatusCode::FORBIDDEN),

        // Browsers normally send Origin for fetch POST/DELETE requests.
        // For non-browser clients, you can decide whether to reject or allow.
        None => Ok(()),
    }
}

// Represents "a request that has been proven to belong to a real,
// logged-in user." Any handler that takes this as an argument
// automatically requires a valid session -- axum won't even call
// the handler if this fails to extract.
struct AuthUser {
    user_id: i32,
    username: String,
    role: String,
    #[allow(dead_code)]
    must_change_password: bool,
}

// This trait is what makes AuthUser usable as a handler argument at all.
// It runs BEFORE your handler's own code -- extraction happens first.
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_same_origin(parts)?;

        let jar = CookieJar::from_headers(&parts.headers);

        let token = jar
            .get("__Host-seclog_session")
            .map(|cookie| cookie.value().to_owned())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        match db::get_session_user(&state.pool, &token).await {
            Ok(Some((user_id, username, role, must_change_password))) => {
                let path = parts.uri.path();
                let allowed_during_forced_change = path == "/change-password" || path == "/me";

                if must_change_password && !allowed_during_forced_change {
                    // 428: "you're authenticated, but a precondition (password
                    // change) must be satisfied before this request proceeds."
                    return Err(StatusCode::from_u16(428).unwrap());
                }

                Ok(AuthUser { user_id, username, role, must_change_password })
            }
            Ok(None) => Err(StatusCode::UNAUTHORIZED),
            Err(e) => {
                eprintln!("DB error: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

// Same idea as AuthUser, but additionally requires role == "admin".
// Handlers that take AdminUser as an argument are automatically
// unreachable by non-admins -- axum rejects the request during
// extraction, before your handler's own code ever runs.
struct AdminUser {
    #[allow(dead_code)] // not used yet, but real data -- silences the warning intentionally
    user_id: i32,
    username: String,
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Reuses AuthUser's extraction logic first -- this is how we avoi
        // duplicating the token-parsing/lookup code. If AuthUser fails
        // (bad/missing token), that failure propagates automatically via '?'.
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        if auth_user.role != "admin" {
            return Err(StatusCode::FORBIDDEN); // 403: authenticated, but not allowed
        }

        Ok(AdminUser {
            user_id: auth_user.user_id,
            username: auth_user.username,
        })
    }
}

// Same shape as AdminUser, but accepts the narrower "auditor" role too
// -- someone who can view and review log/audit data but administers
// nothing (no agents, no directory, no settings, no user management).
// Used only on the handful of endpoints that are genuinely about
// reviewing evidence: list_logs, logs_summary, the audit-log endpoints,
// and set_log_review_handler. Everything else stays on AdminUser.
struct AuditAccess {
    #[allow(dead_code)]
    user_id: i32,
    username: String,
}

impl FromRequestParts<AppState> for AuditAccess {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        if auth_user.role != "admin" && auth_user.role != "auditor" {
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(AuditAccess {
            user_id: auth_user.user_id,
            username: auth_user.username,
        })
    }
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    let ip = client_ip(&headers);

    if payload.new_password.len() < 15 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let stored_hash = match db::get_password_hash(&state.pool, &auth_user.username).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !auth::verify_password(&payload.current_password, &stored_hash) {
        db::record_audit_event(
            &state.pool, Some(auth_user.user_id), &auth_user.username, "user.password_change.failure",
            None, "failure", &ip, Some("current password incorrect"),
        ).await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_hash = auth::hash_password(&payload.new_password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = db::update_password(&state.pool, auth_user.user_id, &new_hash).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Rotate the session: the old token stays valid until this point, so
    // password compromise + change wouldn't actually kick out an attacker
    // holding the old cookie unless we explicitly invalidate it here.
    if let Some(old_cookie) = jar.get("__Host-seclog_session")
        && let Err(e) = db::delete_session(&state.pool, old_cookie.value()).await
    {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let new_token = auth::generate_session_token();
    if let Err(e) = db::create_session(&state.pool, &new_token, auth_user.user_id).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let new_cookie = Cookie::build(("__Host-seclog_session", new_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build();

    db::record_audit_event(
        &state.pool, Some(auth_user.user_id), &auth_user.username, "user.password_change.success",
        None, "success", &ip, None,
    ).await;

    Ok((jar.add(new_cookie), StatusCode::OK))
}

async fn mfa_setup(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<models::MfaSetupResponse>, StatusCode> {
    let secret_hex = auth::generate_mfa_secret_hex().map_err(|e| {
        eprintln!("MFA secret generation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::set_pending_mfa_secret(&state.pool, auth_user.user_id, &secret_hex)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    let provisioning = auth::mfa_provisioning(&secret_hex, &auth_user.username)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(models::MfaSetupResponse {
        otpauth_url: provisioning.otpauth_url,
        secret_base32: provisioning.secret_base32,
    }))
}

async fn mfa_verify_setup(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<MfaCodeRequest>,
) -> Result<StatusCode, StatusCode> {
    let ip = client_ip(&headers);

    let secret = match db::get_mfa_secret(&state.pool, auth_user.user_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Err(StatusCode::BAD_REQUEST), // no setup in progress
        Err(e) => { eprintln!("DB error: {}", e); return Err(StatusCode::INTERNAL_SERVER_ERROR); }
    };

    if !auth::verify_totp_code(&secret, &auth_user.username, &payload.code) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    db::confirm_mfa_enabled(&state.pool, auth_user.user_id)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    db::record_audit_event(
        &state.pool, Some(auth_user.user_id), &auth_user.username, "user.mfa_enable", None, "success", &ip, None,
    ).await;

    Ok(StatusCode::OK)
}

async fn mfa_disable(
    State(state): State<AppState>,
    auth_user: AuthUser,
    headers: HeaderMap,
    Json(payload): Json<MfaDisableRequest>,
) -> Result<StatusCode, StatusCode> {
    let ip = client_ip(&headers);

    let stored_hash = match db::get_password_hash(&state.pool, &auth_user.username).await {
        Ok(Some(h)) => h,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(e) => { eprintln!("DB error: {}", e); return Err(StatusCode::INTERNAL_SERVER_ERROR); }
    };

    if !auth::verify_password(&payload.password, &stored_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    db::disable_mfa(&state.pool, auth_user.user_id)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    db::record_audit_event(
        &state.pool, Some(auth_user.user_id), &auth_user.username, "user.mfa_disable", None, "success", &ip, None,
    ).await;

    Ok(StatusCode::OK)
}

#[derive(serde::Serialize)]
struct MfaStatusResponse {
    mfa_enabled: bool,
}

async fn mfa_status(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<MfaStatusResponse>, StatusCode> {
    let mfa_enabled = db::get_mfa_enabled(&state.pool, auth_user.user_id)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(MfaStatusResponse { mfa_enabled }))
}

async fn admin_delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(user_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    if user_id == admin.user_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    match db::delete_user(&state.pool, user_id).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.user.delete",
                Some(&format!("user:{}", user_id)), "success", &client_ip(&headers), None,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<CookieJar, StatusCode> {
    if let Some(cookie) = jar.get("__Host-seclog_session") {
        // Resolve who this is BEFORE deleting the session -- there's
        // nothing left to look up afterward, and logout is exactly the
        // kind of access event CJIS AU-2 wants a record of.
        if let Ok(Some((user_id, username, _role, _mcp))) = db::get_session_user(&state.pool, cookie.value()).await {
            db::record_audit_event(
                &state.pool, Some(user_id), &username, "user.logout", None, "success", &client_ip(&headers), None,
            ).await;
        }

        db::delete_session(&state.pool, cookie.value())
            .await
            .map_err(|e| {
                eprintln!("DB error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    let removal = Cookie::build(("__Host-seclog_session", ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::seconds(0))
        .build();

    Ok(jar.remove(removal))
}

#[derive(serde::Serialize)]
struct SignupStatusResponse {
    enabled: bool,
    bootstrap: bool,
}

async fn signup_status(
    State(state): State<AppState>,
) -> Result<Json<SignupStatusResponse>, StatusCode> {
    let self_signup_enabled = db::get_self_signup_enabled(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user_count = db::get_all_users(&state.pool).await.map(|u| u.len()).map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(SignupStatusResponse {
        enabled: user_count == 0 || self_signup_enabled,
        bootstrap: user_count == 0,
    }))
}

async fn list_users(
    State(state): State<AppState>,
    admin: AdminUser,
) -> Result<Json<Vec<db::UserRow>>, StatusCode> {
    println!("User list requested by admin: {}", admin.username);

    match db::get_all_users(&state.pool).await {
        Ok(rows) => Ok(Json(rows)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(serde::Serialize)]
struct MeResponse {
    username: String,
    role: String,
}

async fn me(auth_user: AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        username: auth_user.username,
        role: auth_user.role,
    })
}

#[derive(serde::Serialize)]
struct SettingsResponse {
    self_signup_enabled: bool,
    log_retention_days: i64,
    max_log_rows: i64,
    stale_agent_minutes: i64,
    // CJIS AU-11: real on-disk size, informational only (no setting
    // reads this back) -- see db::get_table_size_bytes.
    logs_table_size_bytes: i64,
}

#[derive(serde::Deserialize)]
struct UpdateSettingsRequest {
    self_signup_enabled: bool,
    log_retention_days: i64,
    max_log_rows: i64,
    stale_agent_minutes: i64,
}

async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<SettingsResponse>, StatusCode> {
    let self_signup_enabled = match db::get_self_signup_enabled(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let (log_retention_days, max_log_rows) = match db::get_retention_settings(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let stale_agent_minutes = match db::get_stale_agent_minutes(&state.pool).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Best-effort: informational only, so a failure here shouldn't take
    // down the whole Settings page. `0` just means "unknown," not
    // "empty."
    let logs_table_size_bytes = db::get_table_size_bytes(&state.pool, "logs").await.unwrap_or(0);

    Ok(Json(SettingsResponse {
        self_signup_enabled,
        log_retention_days,
        max_log_rows,
        stale_agent_minutes,
        logs_table_size_bytes,
    }))
}

async fn update_settings(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<StatusCode, StatusCode> {
    // Guardrails, not just cosmetic: a 0-day retention or a near-zero row
    // cap would either silently discard everything shipped or make the
    // dashboard useless. min values keep the box usable even if someone
    // fat-fingers the settings form.
    if payload.log_retention_days < 1 || payload.max_log_rows < 1000 || payload.stale_agent_minutes < 5 {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Err(e) = db::set_self_signup_enabled(&state.pool, payload.self_signup_enabled).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = db::set_retention_settings(&state.pool, payload.log_retention_days, payload.max_log_rows).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = db::set_stale_agent_minutes(&state.pool, payload.stale_agent_minutes).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.settings.update", None, "success",
        &client_ip(&headers),
        Some(&format!(
            "self_signup_enabled={} log_retention_days={} max_log_rows={} stale_agent_minutes={}",
            payload.self_signup_enabled, payload.log_retention_days, payload.max_log_rows, payload.stale_agent_minutes
        )),
    ).await;

    Ok(StatusCode::OK)
}

async fn list_notification_channels_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<models::NotificationChannel>>, StatusCode> {
    match db::list_notification_channels(&state.pool).await {
        Ok(channels) => Ok(Json(channels)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn create_notification_channel_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<models::CreateChannelRequest>,
) -> Result<StatusCode, StatusCode> {
    let valid_kinds = ["email", "slack", "discord", "telegram", "ntfy", "webhook"];
    if !valid_kinds.contains(&payload.kind.as_str()) || payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let config_json = serde_json::to_string(&payload.config)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    match db::create_notification_channel(&state.pool, &payload.kind, &payload.name, &config_json, &payload.min_severity).await {
        Ok(_) => {
            // Never the config JSON itself -- it can hold an SMTP
            // password, a webhook URL, a bot token.
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.notification.create",
                None, "success", &client_ip(&headers),
                Some(&format!("kind={} name={}", payload.kind, payload.name)),
            ).await;
            Ok(StatusCode::CREATED)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_notification_channel_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::delete_notification_channel(&state.pool, id).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.notification.delete",
                Some(&format!("channel:{}", id)), "success", &client_ip(&headers), None,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn test_notification_channel_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    let channel = match db::get_channel_by_id(&state.pool, id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    match notify::dispatch(&channel, "Medium", "This is a test alert from SecLog.", "test-host").await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("notify test failed: {}", e);
            Err(StatusCode::BAD_GATEWAY) // distinguishes "channel unreachable" from a server bug
        }
    }
}

// --- Correlation rules ---
// Threshold detection over the same [Label]-prefixed rule table
// parser.rs already maintains -- see db::correlation_rule_hits and the
// background sweep loop below in main(). Deliberately not a free-text
// rule engine: match_label must be one of parser::known_labels(),
// enforced here rather than left to the DB layer.

async fn list_correlation_rule_labels() -> Json<Vec<&'static str>> {
    Json(parser::known_labels())
}

async fn list_correlation_rules_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<db::CorrelationRuleRow>>, StatusCode> {
    match db::list_correlation_rules(&state.pool).await {
        Ok(rows) => Ok(Json(rows)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(serde::Deserialize)]
struct CorrelationRuleRequest {
    name: String,
    match_label: String,
    group_by: String,
    threshold_count: i64,
    window_minutes: i64,
    alert_severity: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

fn validate_correlation_rule(payload: &CorrelationRuleRequest) -> bool {
    !payload.name.trim().is_empty()
        && parser::known_labels().contains(&payload.match_label.as_str())
        && matches!(payload.group_by.as_str(), "host" | "user")
        && payload.threshold_count >= 2
        && payload.window_minutes >= 1
        && matches!(payload.alert_severity.as_str(), "Low" | "Medium" | "High" | "Critical")
}

async fn create_correlation_rule_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<CorrelationRuleRequest>,
) -> Result<StatusCode, StatusCode> {
    if !validate_correlation_rule(&payload) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let id = db::create_correlation_rule(
        &state.pool, &payload.name, &payload.match_label, &payload.group_by,
        payload.threshold_count, payload.window_minutes, &payload.alert_severity,
    ).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.correlation_rule.create",
        Some(&format!("correlation_rule:{}", id)), "success", &client_ip(&headers),
        Some(&format!("name={} label={} group_by={} threshold={} window={}min",
            payload.name, payload.match_label, payload.group_by, payload.threshold_count, payload.window_minutes)),
    ).await;

    Ok(StatusCode::CREATED)
}

async fn update_correlation_rule_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<i32>,
    Json(payload): Json<CorrelationRuleRequest>,
) -> Result<StatusCode, StatusCode> {
    if !validate_correlation_rule(&payload) {
        return Err(StatusCode::BAD_REQUEST);
    }

    db::update_correlation_rule(
        &state.pool, id, &payload.name, &payload.match_label, &payload.group_by,
        payload.threshold_count, payload.window_minutes, &payload.alert_severity, payload.enabled,
    ).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.correlation_rule.update",
        Some(&format!("correlation_rule:{}", id)), "success", &client_ip(&headers),
        Some(&format!("enabled={}", payload.enabled)),
    ).await;

    Ok(StatusCode::OK)
}

async fn delete_correlation_rule_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    db::delete_correlation_rule(&state.pool, id).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.correlation_rule.delete",
        Some(&format!("correlation_rule:{}", id)), "success", &client_ip(&headers), None,
    ).await;

    Ok(StatusCode::NO_CONTENT)
}

// --- Directory (LDAP/Active Directory) sync ---

async fn get_directory_config(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<models::LdapConfigResponse>, StatusCode> {
    let row = db::get_ldap_config(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(models::LdapConfigResponse {
        enabled: row.enabled,
        server_uri: row.server_uri,
        bind_dn: row.bind_dn,
        password_configured: row.bind_password_encrypted.is_some(),
        base_dn: row.base_dn,
        computer_filter: row.computer_filter,
        sync_interval_minutes: row.sync_interval_minutes,
        last_sync_at: row.last_sync_at,
        last_sync_status: row.last_sync_status,
        last_sync_count: row.last_sync_count,
        master_key_configured: state.master_key.is_some(),
        login_enabled: row.login_enabled,
        user_base_dn: row.user_base_dn,
        user_filter_template: row.user_filter_template,
        admin_group_dn: row.admin_group_dn,
    }))
}

async fn update_directory_config(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<LdapConfigRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.server_uri.trim().is_empty()
        || payload.bind_dn.trim().is_empty()
        || payload.base_dn.trim().is_empty()
        || payload.sync_interval_minutes < 5
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // user_base_dn and a {username}-containing filter are only
    // meaningful -- and only required -- once login is actually turned
    // on. Turning login off doesn't clear them, so re-enabling later
    // doesn't require retyping.
    if payload.login_enabled
        && (payload.user_base_dn.trim().is_empty()
            || !payload.user_filter_template.contains("{username}"))
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // A blank password field means "leave the saved one alone" -- same
    // write-once UX as the agent API key. Only a non-empty value here
    // triggers a re-encrypt.
    let new_encrypted = match payload.bind_password.as_deref() {
        Some(pw) if !pw.is_empty() => {
            let key = state.master_key.as_ref().ok_or_else(|| {
                eprintln!(
                    "Cannot save LDAP bind password: {} is not set",
                    crypto::MASTER_KEY_ENV_VAR
                );
                StatusCode::SERVICE_UNAVAILABLE
            })?;
            Some(key.encrypt(pw).map_err(|e| {
                eprintln!("Failed to encrypt LDAP bind password: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?)
        }
        _ => None,
    };

    let filter = if payload.computer_filter.trim().is_empty() {
        "(objectClass=computer)".to_string()
    } else {
        payload.computer_filter.trim().to_string()
    };

    let user_filter = if payload.user_filter_template.trim().is_empty() {
        "(&(objectClass=user)(sAMAccountName={username}))".to_string()
    } else {
        payload.user_filter_template.trim().to_string()
    };

    let admin_group_dn = payload.admin_group_dn.as_deref().map(str::trim).filter(|s| !s.is_empty());

    db::set_ldap_config(
        &state.pool,
        db::LdapConfigUpdate {
            enabled: payload.enabled,
            server_uri: payload.server_uri.trim(),
            bind_dn: payload.bind_dn.trim(),
            new_bind_password_encrypted: new_encrypted.as_deref(),
            base_dn: payload.base_dn.trim(),
            computer_filter: &filter,
            sync_interval_minutes: payload.sync_interval_minutes,
            login_enabled: payload.login_enabled,
            user_base_dn: payload.user_base_dn.trim(),
            user_filter_template: &user_filter,
            admin_group_dn,
        },
    )
    .await
    .map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Deliberately never includes the bind password (new or existing)
    // or the encrypted blob -- only whether one was CHANGED, not what
    // it is.
    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.directory.config_update", None, "success",
        &client_ip(&headers),
        Some(&format!(
            "enabled={} login_enabled={} bind_password_changed={}",
            payload.enabled, payload.login_enabled, new_encrypted.is_some()
        )),
    ).await;

    Ok(StatusCode::OK)
}

// Backs the Directory page's "Test Connection" button. Accepts the
// same shape as save so it can test whatever's currently in the form
// (including a not-yet-saved password); if the password field is left
// blank, falls back to decrypting and testing the already-saved config.
async fn test_directory_connection(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(payload): Json<LdapConfigRequest>,
) -> Result<StatusCode, StatusCode> {
    let config = if let Some(pw) = payload.bind_password.filter(|p| !p.is_empty()) {
        directory::LdapConfig {
            server_uri: payload.server_uri,
            bind_dn: payload.bind_dn,
            bind_password: pw,
            base_dn: payload.base_dn,
            computer_filter: payload.computer_filter,
            login_enabled: payload.login_enabled,
            user_base_dn: payload.user_base_dn,
            user_filter_template: payload.user_filter_template,
            admin_group_dn: payload.admin_group_dn,
        }
    } else {
        let row = db::get_ldap_config(&state.pool).await.map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let key = state.master_key.as_ref().ok_or_else(|| {
            eprintln!(
                "Cannot test LDAP connection: {} is not set",
                crypto::MASTER_KEY_ENV_VAR
            );
            StatusCode::SERVICE_UNAVAILABLE
        })?;
        directory::LdapConfig::from_row(&row, key).map_err(|e| {
            eprintln!("LDAP config error: {}", e);
            StatusCode::BAD_REQUEST
        })?
    };

    directory::test_connection(&config).await.map_err(|e| {
        eprintln!("LDAP test connection failed: {}", e);
        StatusCode::BAD_GATEWAY // distinguishes "directory unreachable/rejected" from a server bug
    })?;

    Ok(StatusCode::OK)
}

async fn sync_directory_now(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<models::DirectorySyncResponse>, StatusCode> {
    let row = db::get_ldap_config(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let key = state.master_key.as_ref().ok_or_else(|| {
        eprintln!(
            "Cannot sync directory: {} is not set",
            crypto::MASTER_KEY_ENV_VAR
        );
        StatusCode::SERVICE_UNAVAILABLE
    })?;
    let config = directory::LdapConfig::from_row(&row, key).map_err(|e| {
        eprintln!("LDAP config error: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let count = directory::sync_computers(&state.pool, &config).await.map_err(|e| {
        eprintln!("LDAP sync failed: {}", e);
        StatusCode::BAD_GATEWAY
    })?;

    Ok(Json(models::DirectorySyncResponse { hosts_found: count }))
}

async fn list_directory_hosts(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<models::DiscoveredHostResponse>>, StatusCode> {
    let config_row = db::get_ldap_config(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let rows = db::list_discovered_hosts(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // "Stale" means not seen in the last TWO sync cycles, not one --
    // a single missed/failed sync (a transient LDAP hiccup) shouldn't
    // immediately flag every host as gone.
    let stale_after = chrono::Duration::minutes(config_row.sync_interval_minutes.max(1) * 2);
    let now = chrono::Utc::now();

    let hosts = rows
        .into_iter()
        .map(|r| models::DiscoveredHostResponse {
            id: r.id,
            hostname: r.hostname,
            distinguished_name: r.distinguished_name,
            operating_system: r.operating_system,
            organizational_unit: r.organizational_unit,
            ad_last_logon: r.ad_last_logon,
            first_seen_at: r.first_seen_at,
            last_seen_in_ad: r.last_seen_in_ad,
            likely_enrolled: r.agent_id.is_some(),
            agent_id: r.agent_id,
            stale: now.signed_duration_since(r.last_seen_in_ad) > stale_after,
        })
        .collect();

    Ok(Json(hosts))
}

// Generates a GPO-startup-script / Intune-platform-script deployment
// package: a bulk enrollment token plus a headless install script that
// embeds it. See README/ARCHITECTURE for why one script covers both
// mechanisms (both just run PowerShell unattended as SYSTEM) and why
// this can't produce an actual .intunewin binary (that requires
// Microsoft's Windows-only IntuneWinAppUtil.exe).
async fn create_deployment_package(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<models::DeploymentPackageRequest>,
) -> Result<Json<models::DeploymentPackageResponse>, StatusCode> {
    if payload.max_uses < 1 || payload.expires_days < 1 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let token = auth::generate_session_token();
    let label = payload.label.as_deref().filter(|s| !s.trim().is_empty());

    let token_id = db::create_bulk_enrollment_token(
        &state.pool, &token, payload.max_uses, payload.expires_days, label,
    )
    .await
    .map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.deployment_package.generate",
        Some(&format!("enrollment_token:{}", token_id)), "success", &client_ip(&headers),
        Some(&format!("max_uses={} expires_days={} label={:?}", payload.max_uses, payload.expires_days, label)),
    ).await;

    let base_url = base_url_from_headers(&headers);
    let script = windows_unattended_install_script(&base_url, &token);

    Ok(Json(models::DeploymentPackageResponse {
        token_id,
        script,
        gpo_instructions: "Group Policy Management Console → select/create a GPO linked to \
            the target OU → Computer Configuration → Policies → Windows Settings → Scripts \
            → Startup → PowerShell Scripts → add this file. Runs as SYSTEM the next time \
            each machine boots and re-checks in Group Policy."
            .to_string(),
        intune_instructions: "Intune admin center → Devices → Scripts and remediations → \
            Platform scripts → Add → Windows 10 and later → upload this file → set \"Run \
            this script using the logged on credentials\" to No (runs as SYSTEM) → assign \
            to the target device group."
            .to_string(),
    }))
}

async fn list_deployment_tokens(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<db::EnrollmentTokenRow>>, StatusCode> {
    match db::list_enrollment_tokens(&state.pool).await {
        Ok(rows) => Ok(Json(rows)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn revoke_deployment_token(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::revoke_enrollment_token(&state.pool, id).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.deployment_package.revoke",
                Some(&format!("enrollment_token:{}", id)), "success", &client_ip(&headers), None,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// --- Syslog receiver ---
// See src/syslog.rs for the listeners themselves. Enabling/disabling
// or changing which protocols listen takes a server restart (an
// infra-level socket bind, read once at startup below) -- the
// allowlist here is not restart-gated, see the 30s refresh task in
// main() below.

async fn get_syslog_config_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<db::SyslogConfigRow>, StatusCode> {
    db::get_syslog_config(&state.pool).await.map(Json).map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

#[derive(serde::Deserialize)]
struct SyslogConfigRequest {
    enabled_udp: bool,
    enabled_tcp: bool,
    allowed_cidrs: String,
}

async fn update_syslog_config_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<SyslogConfigRequest>,
) -> Result<StatusCode, StatusCode> {
    // Catch a typo'd CIDR at save time rather than have it silently
    // never match anything -- fail-closed is only a safe default if the
    // entries an admin DOES add actually work.
    for line in payload.allowed_cidrs.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let addr_part = line.split_once('/').map_or(line, |(addr, _)| addr);
        if addr_part.parse::<std::net::IpAddr>().is_err() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    db::update_syslog_config(&state.pool, payload.enabled_udp, payload.enabled_tcp, &payload.allowed_cidrs)
        .await
        .map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.syslog_config.update", None, "success",
        &client_ip(&headers),
        Some(&format!("enabled_udp={} enabled_tcp={}", payload.enabled_udp, payload.enabled_tcp)),
    ).await;

    Ok(StatusCode::OK)
}

// --- External archival storage (S3-compatible / SFTP) ---
// See src/archive.rs for the upload logic; this just handles config
// (never returning a stored secret -- same write-once contract as the
// LDAP bind password) and the Test Connection button.

#[derive(serde::Serialize)]
struct ArchiveConfigResponse {
    backend: String,
    enabled: bool,
    s3_endpoint: String,
    s3_bucket: String,
    s3_region: String,
    s3_access_key: String,
    s3_secret_key_configured: bool,
    s3_path_style: bool,
    sftp_host: String,
    sftp_port: i64,
    sftp_username: String,
    sftp_password_configured: bool,
    sftp_private_key_configured: bool,
    sftp_remote_path: String,
    last_archive_at: Option<chrono::DateTime<chrono::Utc>>,
    last_archive_status: Option<String>,
    last_archive_count: Option<i64>,
    master_key_configured: bool,
}

async fn get_archive_config_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ArchiveConfigResponse>, StatusCode> {
    let row = db::get_archive_config(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ArchiveConfigResponse {
        backend: row.backend,
        enabled: row.enabled,
        s3_endpoint: row.s3_endpoint,
        s3_bucket: row.s3_bucket,
        s3_region: row.s3_region,
        s3_access_key: row.s3_access_key,
        s3_secret_key_configured: row.s3_secret_key_encrypted.is_some(),
        s3_path_style: row.s3_path_style,
        sftp_host: row.sftp_host,
        sftp_port: row.sftp_port,
        sftp_username: row.sftp_username,
        sftp_password_configured: row.sftp_password_encrypted.is_some(),
        sftp_private_key_configured: row.sftp_private_key_encrypted.is_some(),
        sftp_remote_path: row.sftp_remote_path,
        last_archive_at: row.last_archive_at,
        last_archive_status: row.last_archive_status,
        last_archive_count: row.last_archive_count,
        master_key_configured: state.master_key.is_some(),
    }))
}

#[derive(serde::Deserialize)]
struct ArchiveConfigRequest {
    backend: String,
    enabled: bool,
    s3_endpoint: String,
    s3_bucket: String,
    s3_region: String,
    s3_access_key: String,
    #[serde(default)]
    s3_secret_key: Option<String>,
    s3_path_style: bool,
    sftp_host: String,
    sftp_port: i64,
    sftp_username: String,
    #[serde(default)]
    sftp_password: Option<String>,
    #[serde(default)]
    sftp_private_key: Option<String>,
    sftp_remote_path: String,
}

// A blank secret field means "leave the saved one alone" -- same
// write-once UX as the LDAP bind password (see update_directory_config).
fn encrypt_if_provided(master_key: Option<&MasterKey>, value: &Option<String>) -> Result<Option<String>, StatusCode> {
    match value.as_deref() {
        Some(v) if !v.is_empty() => {
            let key = master_key.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
            key.encrypt(v).map(Some).map_err(|e| {
                eprintln!("Failed to encrypt archive secret: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })
        }
        _ => Ok(None),
    }
}

async fn update_archive_config_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<ArchiveConfigRequest>,
) -> Result<StatusCode, StatusCode> {
    if !matches!(payload.backend.as_str(), "none" | "s3" | "sftp") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let new_s3_secret = encrypt_if_provided(state.master_key.as_ref(), &payload.s3_secret_key)?;
    let new_sftp_password = encrypt_if_provided(state.master_key.as_ref(), &payload.sftp_password)?;
    let new_sftp_private_key = encrypt_if_provided(state.master_key.as_ref(), &payload.sftp_private_key)?;

    db::update_archive_config(&state.pool, db::ArchiveConfigUpdate {
        backend: &payload.backend,
        enabled: payload.enabled,
        s3_endpoint: &payload.s3_endpoint,
        s3_bucket: &payload.s3_bucket,
        s3_region: &payload.s3_region,
        s3_access_key: &payload.s3_access_key,
        new_s3_secret_key_encrypted: new_s3_secret.as_deref(),
        s3_path_style: payload.s3_path_style,
        sftp_host: &payload.sftp_host,
        sftp_port: payload.sftp_port,
        sftp_username: &payload.sftp_username,
        new_sftp_password_encrypted: new_sftp_password.as_deref(),
        new_sftp_private_key_encrypted: new_sftp_private_key.as_deref(),
        sftp_remote_path: &payload.sftp_remote_path,
    }).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    db::record_audit_event(
        &state.pool, Some(admin.user_id), &admin.username, "admin.archive_config.update", None, "success",
        &client_ip(&headers),
        Some(&format!("backend={} enabled={}", payload.backend, payload.enabled)),
    ).await;

    Ok(StatusCode::OK)
}

async fn test_archive_connection_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<StatusCode, StatusCode> {
    let cfg = db::get_archive_config(&state.pool).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if cfg.backend == "none" {
        return Err(StatusCode::BAD_REQUEST);
    }

    match archive::test_connection(&cfg, state.master_key.as_ref()).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("Archive connection test failed: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

// --- Audit log (CJIS AU-2, AU-3, AU-3(1)) ---

#[derive(serde::Deserialize)]
struct AuditLogQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(serde::Serialize)]
struct PaginatedAuditLog {
    entries: Vec<db::AuditLogRow>,
    total: i64,
    limit: i64,
    offset: i64,
}

// Admin-only, same as /logs -- this table exists to answer "who did
// what," so read access to it needs the same restriction as read access
// to the shipper-sourced logs (see README: Compliance notes (CJIS)).
async fn list_audit_log_handler(
    State(state): State<AppState>,
    _admin: AuditAccess,
    Query(params): Query<AuditLogQuery>,
) -> Result<Json<PaginatedAuditLog>, StatusCode> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let offset = params.offset.unwrap_or(0).max(0);

    let entries = match db::list_audit_log(&state.pool, limit, offset).await {
        Ok(rows) => rows,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let total = match db::count_audit_log(&state.pool).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("DB error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(PaginatedAuditLog { entries, total, limit, offset }))
}

#[derive(serde::Deserialize)]
struct VerifyAuditLogQuery {
    since_id: Option<i32>,
    limit: Option<i64>,
}

// Default verification window: the most recent 5000 chained rows, not
// the whole table -- same anti-"fetch everything" discipline as
// everywhere else in this codebase. Pass since_id explicitly for a
// deeper (or full, since_id=1) walk.
const DEFAULT_AUDIT_VERIFY_WINDOW: i64 = 5000;

async fn verify_audit_log_handler(
    State(state): State<AppState>,
    _admin: AuditAccess,
    Query(params): Query<VerifyAuditLogQuery>,
) -> Result<Json<db::AuditChainVerification>, StatusCode> {
    let limit = params.limit.unwrap_or(DEFAULT_AUDIT_VERIFY_WINDOW).clamp(1, 100_000);

    let since_id = match params.since_id {
        Some(id) => id,
        None => {
            let latest = db::max_audit_log_id(&state.pool).await.map_err(|e| {
                eprintln!("DB error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            (latest as i64 - limit + 1).max(1) as i32
        }
    };

    let result = db::verify_audit_log_chain(&state.pool, since_id, limit).await.map_err(|e| {
        eprintln!("DB error: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(result))
}

#[derive(serde::Deserialize)]
struct CheckpointsQuery {
    limit: Option<i64>,
}

async fn list_log_checkpoints_handler(
    State(state): State<AppState>,
    _admin: AuditAccess,
    Query(params): Query<CheckpointsQuery>,
) -> Result<Json<Vec<db::CheckpointStatus>>, StatusCode> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);

    db::list_log_checkpoints_with_status(&state.pool, limit)
        .await
        .map(Json)
        .map_err(|e| {
            eprintln!("DB error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

struct AgentAuth {
    agent_id: i32,
    #[allow(dead_code)]
    hostname: String,
}

impl FromRequestParts<AppState> for AgentAuth {
    type Rejection = StatusCode;
    
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Agents authenticate with a custom header, not a Bearer token --
        // deliberately different from human sessions, since this is a
        // long-lived machine credential, not a login session.
        let api_key = parts
            .headers
            .get("X-Agent-Key")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        match db::get_agent_by_key(&state.pool, api_key).await {
            Ok(Some((agent_id, hostname))) => {
                // Best-effort -- if this fails, don't block the actual
                // request over a bookkeeping update.
                let _ = db::touch_agent_last_seen(&state.pool, agent_id).await;
                Ok(AgentAuth { agent_id, hostname })
            }
            Ok(None) => Err(StatusCode::UNAUTHORIZED),
            Err(e) => {
                eprintln!("DB error: {}", e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

async fn register_agent(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Json(payload): Json<models::RegisterAgentRequest>,
) -> Result<Json<models::RegisterAgentResponse>, StatusCode> {
    if payload.hostname.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Reusing the same random-token generator we build for sessions --
    // same underlying need (a long, unguessable random string), just a
    // different purpose here.
    let api_key = auth::generate_session_token();

    match db::create_agent(&state.pool, &payload.hostname, &api_key).await {
        Ok(agent_id) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.agent.register",
                Some(&format!("agent:{}", agent_id)), "success", &client_ip(&headers),
                Some(&format!("hostname={}", payload.hostname)),
            ).await;
            Ok(Json(models::RegisterAgentResponse { agent_id, api_key}))
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn agent_ping(agent: AgentAuth) -> StatusCode {
    println!("Agent checked in: id={}", agent.agent_id);
    StatusCode::OK
}

async fn get_agent_config(
    State(state): State<AppState>,
    agent: AgentAuth,
) -> Result<Json<models::AgentConfigResponse>, StatusCode> {
    match db::get_enabled_paths(&state.pool, agent.agent_id).await {
        Ok(paths) => Ok(Json(models::AgentConfigResponse {
            hostname: agent.hostname,
            paths,
        })),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_watched_paths(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(agent_id): Path<i32>,
) -> Result<Json<Vec<db::WatchedPathRow>>, StatusCode> {
    match db::get_watched_paths(&state.pool, agent_id).await {
        Ok(paths) => Ok(Json(paths)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn add_watched_path_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(agent_id): Path<i32>,
    Json(payload): Json<models::AddPathRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.path.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match db::add_watched_path(&state.pool, agent_id, &payload.path).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.path.add",
                Some(&format!("agent:{}", agent_id)), "success", &client_ip(&headers),
                Some(&payload.path),
            ).await;
            Ok(StatusCode::CREATED)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_watched_path_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(path_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::delete_watched_path(&state.pool, path_id).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.path.delete",
                Some(&format!("path:{}", path_id)), "success", &client_ip(&headers), None,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_agent_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(agent_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::delete_agent(&state.pool, agent_id).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.agent.delete",
                Some(&format!("agent:{}", agent_id)), "success", &client_ip(&headers), None,
            ).await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_agents(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<db::AgentRow>>, StatusCode> {
    match db::get_all_agents(&state.pool).await {
        Ok(agents) => Ok(Json(agents)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(serde::Deserialize)]
struct SetPathEnabledRequest {
    enabled: bool,
}

async fn set_path_enabled_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
    Path(path_id): Path<i32>,
    Json(payload): Json<SetPathEnabledRequest>,
) -> Result<StatusCode, StatusCode> {
    match db::set_path_enabled(&state.pool, path_id, payload.enabled).await {
        Ok(_) => {
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.path.set_enabled",
                Some(&format!("path:{}", path_id)), "success", &client_ip(&headers),
                Some(&format!("enabled={}", payload.enabled)),
            ).await;
            Ok(StatusCode::OK)
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn health(State(state): State<AppState>) -> StatusCode {
    // A trivial query -- if this succeeds, the DB connection is genuinely
    // alive, not just "the pool object exists in memory."
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            eprintln!("Health check failed: {}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

async fn generate_enrollment_token(
    State(state): State<AppState>,
    admin: AdminUser,
    headers: HeaderMap,
) -> Result<Json<models::EnrollmentTokenResponse>, StatusCode> {
    let token = auth::generate_session_token(); // reusing the same random-token generator

    match db::create_enrollment_token(&state.pool, &token).await {
        Ok(_) => {
            // Never the token itself -- it's single-use, but there's no
            // reason to put a live credential in a second place.
            db::record_audit_event(
                &state.pool, Some(admin.user_id), &admin.username, "admin.enrollment_token.generate",
                None, "success", &client_ip(&headers), None,
            ).await;
            Ok(Json(models::EnrollmentTokenResponse { token }))
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Unauthenticated by design -- a shipper has no credentials yet at this
// point. Security comes from the enrollment token itself: single-use,
// admin-issued, and consumed atomically on first successful use.
async fn self_register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<models::SelfRegisterRequest>,
) -> Result<Json<models::RegisterAgentResponse>, StatusCode> {
    let ip = client_ip(&headers);

    if !state.agent_register_rate_limiter.check(&ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if payload.hostname.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let valid = db::consume_enrollment_token(&state.pool, &payload.enrollment_token)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !valid {
        state.agent_register_rate_limiter.record_failure(&ip);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let api_key = auth::generate_session_token();
    match db::create_agent(&state.pool, &payload.hostname, &api_key).await {
        Ok(agent_id) => {
            db::record_audit_event(
                &state.pool, None, "shipper", "agent.self_register",
                Some(&format!("agent:{}", agent_id)), "success", &ip,
                Some(&format!("hostname={}", payload.hostname)),
            ).await;
            Ok(Json(models::RegisterAgentResponse { agent_id, api_key }))
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn linux_install_script(headers: HeaderMap) -> impl axum::response::IntoResponse {
    let base_url = base_url_from_headers(&headers);

    let script = format!(
        r#"#!/bin/bash
set -e

echo "Installing Seclog shipper..."

curl -fsSL "https://github.com/AbyssalOath/SecLog/releases/latest/download/shipper-linux-x86_64" \
    -o /tmp/seclog-shipper

# -f makes curl fail loudly (non-zero exit) on a 404/error instead of
# silently saving the error page as if it were the binary -- combined
# with `set -e` above, this stops the script immediately with a clear
# error rather than installing a broken "binary" that fails at runtime.

if ! file /tmp/seclog-shipper | grep -q "ELF"; then
    echo "ERROR: downloaded file is not a valid Linux binary. Aborting."
    echo "Check that a release with a 'shipper-linux-x86_64' asset exists."
    exit 1
fi

sudo mkdir -p /opt/seclog-shipper

# Reinstall handling: if the service is already running from a previous
# enrollment, its in-memory api_key was read from .seclog_agent_key at
# ITS OWN startup -- deleting the file alone wouldn't affect the process
# that's already running, since it never re-reads the file after boot.
# Stop it first, THEN remove the stale key, so the fresh enrollment token
# entered below is what actually gets used once the service starts back up.
if systemctl is-active --quiet seclog-shipper 2>/dev/null; then
    echo "Existing seclog-shipper install detected -- stopping it to re-enroll."
    sudo systemctl stop seclog-shipper
fi
if [ -f /opt/seclog-shipper/.seclog_agent_key ]; then
    echo "Removing stale agent key from previous enrollment."
    sudo rm -f /opt/seclog-shipper/.seclog_agent_key
fi
sudo mv /tmp/seclog-shipper /opt/seclog-shipper/shipper
sudo chmod +x /opt/seclog-shipper/shipper

# Read from the actual terminal, not stdin -- stdin here is the pipe
# from `curl | bash`, which is already closed/empty by this point.
read -p "Enter enrollment token: " TOKEN < /dev/tty

sudo tee /etc/systemd/system/seclog-shipper.service > /dev/null <<EOF
[Unit]
Description=Seclog Shipper Agent
After=network.target

[Service]
ExecStart=/opt/seclog-shipper/shipper
WorkingDirectory=/opt/seclog-shipper
Restart=always
RestartSec=5
Environment=SHIPPER_API_URL={base_url}
Environment=SECLOG_ENROLLMENT_TOKEN=$TOKEN

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable seclog-shipper
sudo systemctl restart seclog-shipper

echo "Done. Check status: systemctl status seclog-shipper"
"#,
        base_url = base_url
    );

    (
        [(axum::http::header::CONTENT_TYPE, "text/x-shellscript")],
        script,
    )
}

async fn windows_install_script(headers: HeaderMap) -> impl axum::response::IntoResponse {
    let base_url = base_url_from_headers(&headers);

    let script = format!(
        r#"$ErrorActionPreference = "Stop"

Write-Host "Installing Seclog shipper..."

Invoke-WebRequest -Uri "https://github.com/AbyssalOath/SecLog/releases/latest/download/shipper-windows-x86_64.exe" -OutFile "C:\seclog-shipper.exe"

$bytes = Get-Content "C:\seclog-shipper.exe" -Encoding Byte -TotalCount 2
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {{
    Write-Host "ERROR: downloaded file is not a valid Windows executable. Aborting."
    exit 1
}}

$token = Read-Host "Enter enrollment token"

[Environment]::SetEnvironmentVariable("SHIPPER_API_URL", "{base_url}", "Machine")
[Environment]::SetEnvironmentVariable("SECLOG_ENROLLMENT_TOKEN", $token, "Machine")

Write-Host "Downloaded. Run C:\seclog-shipper.exe as Administrator to start, or register it as a service (NSSM/sc.exe) for persistence."
"#,
        base_url = base_url
    );

    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        script,
    )
}

// Headless variant for GPO startup scripts / Intune platform scripts --
// no Read-Host (nobody's at the console), and persistence that actually
// gets set up (unlike windows_install_script above, which just tells a
// human to do it afterward). Registered as a Scheduled Task rather than
// a real Windows service via `sc.exe`: the shipper binary doesn't link
// the `windows-service` crate or call StartServiceCtrlDispatcher, so the
// Service Control Manager would kill it at startup with error 1053
// ("did not respond in a timely fashion") -- a Scheduled Task just
// launches and monitors the process, no SCM handshake required, and
// -RestartCount/-RestartInterval gives the same "come back after a
// crash" behavior a service would.
fn windows_unattended_install_script(base_url: &str, token: &str) -> String {
    format!(
        r#"$ErrorActionPreference = "Stop"
Start-Transcript -Path "C:\seclog-install.log" -Append | Out-Null

# GPO startup scripts re-run on every boot -- skip cleanly if this
# machine is already enrolled instead of re-downloading/re-registering.
if (Get-ScheduledTask -TaskName "SeclogShipper" -ErrorAction SilentlyContinue) {{
    Write-Host "SeclogShipper task already exists. Skipping."
    Stop-Transcript | Out-Null
    exit 0
}}

Write-Host "Installing Seclog shipper..."

Invoke-WebRequest -Uri "https://github.com/AbyssalOath/SecLog/releases/latest/download/shipper-windows-x86_64.exe" -OutFile "C:\seclog-shipper.exe"

$bytes = Get-Content "C:\seclog-shipper.exe" -Encoding Byte -TotalCount 2
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {{
    Write-Host "ERROR: downloaded file is not a valid Windows executable. Aborting."
    Stop-Transcript | Out-Null
    exit 1
}}

[Environment]::SetEnvironmentVariable("SHIPPER_API_URL", "{base_url}", "Machine")
[Environment]::SetEnvironmentVariable("SECLOG_ENROLLMENT_TOKEN", "{token}", "Machine")

$action = New-ScheduledTaskAction -Execute "C:\seclog-shipper.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit 0 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "SeclogShipper" -Action $action -Trigger $trigger -Settings $settings `
    -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "SeclogShipper"

Write-Host "Done. SeclogShipper scheduled task installed and started."
Stop-Transcript | Out-Null
"#,
        base_url = base_url,
        token = token
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = db::create_pool(&db_url).await?;
    // CorsLayer controls which origins (domain/ports) a browser is allowed
    // to make requests from. Any::any() is permissive -- fine for local dev,
    // but something to tighten later (restrict to your actual UI's origin)
    // once this isn't just running on localhost.
    let frontend_origin = env::var("FRONTEND_ORIGIN")
        .expect("FRONTEND_ORIGIN must be set (e.g. https://seclog.yourdomain.com)")
        .parse::<axum::http::HeaderValue>()
        .expect("FRONTEND_ORIGIN is not a valid origin");

    let cors = CorsLayer::new()
        .allow_origin(frontend_origin)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::DELETE])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_credentials(true);
    println!("Connected to MariaDB successfully!");

    db::init_schema(&pool).await?;
    db::init_users_schema(&pool).await?;
    db::init_sessions_schema(&pool).await?;
    db::init_mfa_schema(&pool).await?;
    db::init_settings_schema(&pool).await?;
    db::init_agents_schema(&pool).await?;
    db::init_watched_paths_schema(&pool).await?;
    db::init_enrollment_schema(&pool).await?;
    db::init_notifications_schema(&pool).await?;
    db::init_directory_schema(&pool).await?;
    db::init_audit_schema(&pool).await?;
    db::init_log_checkpoints_schema(&pool).await?;
    db::init_correlation_schema(&pool).await?;
    db::init_syslog_schema(&pool).await?;
    db::init_archive_schema(&pool).await?;

    // Optional, unlike DATABASE_URL/FRONTEND_ORIGIN: a deployment that
    // never touches directory sync shouldn't have to set a new env var
    // just to keep running. A malformed value (set, but not valid
    // base64 or not 32 bytes) still fails loudly at startup rather than
    // silently disabling the feature -- that's a config mistake worth
    // surfacing immediately, not discovering the first time someone
    // tries to save an LDAP bind password.
    let master_key = MasterKey::from_env().expect("Invalid SECLOG_MASTER_KEY");
    if master_key.is_some() {
        println!("Directory sync: {} loaded, LDAP features available.", crypto::MASTER_KEY_ENV_VAR);
    }

    let state = AppState {
        pool,
        rate_limiter: Arc::new(LoginRateLimiter::new()),
        register_rate_limiter: Arc::new(LoginRateLimiter::new()),
        mfa_rate_limiter: Arc::new(LoginRateLimiter::new()),
        agent_register_rate_limiter: Arc::new(LoginRateLimiter::new()),
        master_key,
    };

    // tokio::spawn starts a task that runs concurrently, independent of the
    // main server loop -- this is how you run "background jobs" alongside
    // a running axum server, without blocking request handling.
    let cleanup_pool = state.pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // hourly
            match db::delete_expired_sessions(&cleanup_pool).await {
                Ok(count) if count > 0 => println!("Cleaned up {} expired session(s)", count),
                Ok(_) => {}
                Err(e) => eprintln!("Session cleanup failed: {}", e),
            }
            match db::delete_expired_mfa_pending(&cleanup_pool).await {
                Ok(count) if count > 0 => println!("Cleaned up {} expired MFA pending token(s)", count),
                Ok(_) => {}
                Err(e) => eprintln!("MFA pending cleanup failed: {}", e),
            }
        }
    });

    // Log retention cleanup. Runs more often than the session cleanup
    // above (every 15 min, not hourly) deliberately -- a runaway source
    // (buggy shipper, misbehaving log, etc.) can produce hundreds of
    // thousands of rows in well under an hour, so this needs to catch up
    // fast rather than let a bad night turn into a bad week. Reads current
    // settings each iteration so changes via Settings apply without a
    // server restart.
    let retention_pool = state.pool.clone();
    let retention_master_key = state.master_key.clone();
    tokio::spawn(async move {
        // CJIS AU-11: tracks whether the "nearing capacity" alert has
        // already fired for the current episode, entirely within this
        // task -- a plain local outside the loop, since this is the
        // only place that reads or writes it. Reset once utilization
        // drops back under the threshold, so a capacity problem that
        // gets fixed and later recurs alerts again.
        let mut capacity_alert_sent = false;

        loop {
            match db::get_retention_settings(&retention_pool).await {
                Ok((days, max_rows)) => {
                    // archive::archive_and_delete_* fall straight through to
                    // the plain db:: delete when archiving isn't enabled
                    // (see archive.rs) -- reading archive_config here isn't
                    // needed, that check already lives inside them.
                    match archive::archive_and_delete_older_than(&retention_pool, days, retention_master_key.as_ref()).await {
                        Ok(count) if count > 0 => println!("Retention: deleted {} log(s) older than {} days", count, days),
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Retention cleanup (age) failed: {}", e);
                            notify::trigger_alert(
                                &retention_pool, "High",
                                &format!("[SYSTEM] Retention cleanup (age-based) failed: {}", e),
                                "seclog-server",
                            ).await;
                        }
                    }
                    match archive::archive_and_delete_beyond_row_cap(&retention_pool, max_rows, retention_master_key.as_ref()).await {
                        Ok(count) if count > 0 => println!("Retention: trimmed {} oldest log(s) to stay under {} row cap", count, max_rows),
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("Retention cleanup (row cap) failed: {}", e);
                            notify::trigger_alert(
                                &retention_pool, "High",
                                &format!("[SYSTEM] Retention cleanup (row cap) failed: {}", e),
                                "seclog-server",
                            ).await;
                        }
                    }

                    // CJIS AU-11: "periodically review storage availability."
                    // Row count vs. the configured cap is the primary
                    // proxy -- reliable across any deployment regardless
                    // of the underlying disk/volume setup, unlike raw
                    // filesystem free-space checks from inside a
                    // container (the app container doesn't share a
                    // volume with mariadb's, so there's no meaningful
                    // disk to check from here anyway). The actual
                    // on-disk byte size, read from MariaDB's own
                    // metadata, rides along in the alert text for real
                    // numbers, not just a percentage.
                    match db::count_all_logs(&retention_pool).await {
                        Ok(count) => {
                            let utilization = count as f64 / max_rows.max(1) as f64;
                            if utilization >= 0.9 {
                                if !capacity_alert_sent {
                                    capacity_alert_sent = true;
                                    let size_note = match db::get_table_size_bytes(&retention_pool, "logs").await {
                                        Ok(bytes) => format!(", \u{2248}{:.1} GB on disk", bytes as f64 / 1_073_741_824.0),
                                        Err(_) => String::new(),
                                    };
                                    notify::trigger_alert(
                                        &retention_pool, "Medium",
                                        &format!(
                                            "[SYSTEM] Log storage at {:.0}% of the configured row cap ({} of {} rows{}) -- review retention settings",
                                            utilization * 100.0, count, max_rows, size_note
                                        ),
                                        "seclog-server",
                                    ).await;
                                }
                            } else {
                                capacity_alert_sent = false;
                            }
                        }
                        Err(e) => eprintln!("Failed to check log row count: {}", e),
                    }
                }
                Err(e) => eprintln!("Failed to read retention settings: {}", e),
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(900)).await; // every 15 min
        }
    });

    // CJIS AU-5: agents that have gone dark. Wakes every 5 minutes;
    // stale_agent_minutes (Settings) controls the actual threshold, read
    // fresh each sweep so a change takes effect without a restart.
    let staleness_pool = state.pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;

            let threshold = match db::get_stale_agent_minutes(&staleness_pool).await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to read stale_agent_minutes: {}", e);
                    continue;
                }
            };

            match db::find_newly_stale_agents(&staleness_pool, threshold).await {
                Ok(agents) => {
                    for agent in agents {
                        notify::trigger_alert(
                            &staleness_pool, "High",
                            &format!(
                                "[SYSTEM] Agent {} has not checked in for over {} minutes",
                                agent.hostname, threshold
                            ),
                            &agent.hostname,
                        ).await;
                        if let Err(e) = db::mark_agent_stale_alerted(&staleness_pool, agent.id).await {
                            eprintln!("Failed to mark agent {} as stale-alerted: {}", agent.id, e);
                        }
                    }
                }
                Err(e) => eprintln!("Failed to check for stale agents: {}", e),
            }
        }
    });

    // CJIS AU-9 tamper-evidence for `logs`. Hourly, not per-insert --
    // see db::create_log_checkpoint's own comment for why a linear
    // per-row chain (like audit_log's) doesn't fit a shipper-fed,
    // high-write-volume table. A failed checkpoint is worth knowing
    // about the same way a failed retention run is.
    let checkpoint_pool = state.pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // hourly
            match db::create_log_checkpoint(&checkpoint_pool).await {
                Ok(Some((start, end, count))) => {
                    println!("Log checkpoint: hashed rows {}-{} ({} rows)", start, end, count);
                }
                Ok(None) => {} // nothing new to checkpoint this cycle
                Err(e) => {
                    eprintln!("Log checkpoint failed: {}", e);
                    notify::trigger_alert(
                        &checkpoint_pool, "High",
                        &format!("[SYSTEM] Log integrity checkpoint failed: {}", e),
                        "seclog-server",
                    ).await;
                }
            }
        }
    });

    // Directory (LDAP/AD) sync. Wakes every 5 minutes and re-reads
    // ldap_config each time (same "settings can change without a
    // restart" reasoning as the retention loop above), but only
    // actually syncs once sync_interval_minutes has elapsed since the
    // last one -- the 5-minute wake cadence is just how promptly a
    // newly-lowered interval or a freshly-enabled config takes effect,
    // not the sync cadence itself.
    let directory_pool = state.pool.clone();
    let directory_master_key = state.master_key.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;

            let config_row = match db::get_ldap_config(&directory_pool).await {
                Ok(row) => row,
                Err(e) => {
                    eprintln!("Directory sync: failed to read config: {}", e);
                    continue;
                }
            };

            if !config_row.enabled {
                continue;
            }

            let due = match config_row.last_sync_at {
                None => true,
                Some(last) => {
                    let interval = chrono::Duration::minutes(config_row.sync_interval_minutes.max(1));
                    chrono::Utc::now().signed_duration_since(last) >= interval
                }
            };
            if !due {
                continue;
            }

            let Some(key) = &directory_master_key else {
                eprintln!(
                    "Directory sync is enabled but {} is not set -- skipping",
                    crypto::MASTER_KEY_ENV_VAR
                );
                continue;
            };

            match directory::LdapConfig::from_row(&config_row, key) {
                Ok(config) => match directory::sync_computers(&directory_pool, &config).await {
                    Ok(count) => println!("Directory sync: found {} computer(s)", count),
                    Err(e) => eprintln!("Directory sync failed: {}", e),
                },
                Err(e) => eprintln!("Directory sync: config error: {}", e),
            }
        }
    });

    // Correlation rules: threshold detection over the same
    // [Label]-prefixed rows the dashboard already shows. Every 60s
    // (short window -- a brute-force burst worth alerting on is
    // typically minutes, not hours, so this needs to notice promptly).
    // Dedup mirrors the retention loop's capacity_alert_sent bool,
    // generalized to "one currently-firing set of group values per
    // rule" so re-checking doesn't re-alert every sweep while a burst
    // is still ongoing, but does re-alert on a later, separate burst.
    let correlation_pool = state.pool.clone();
    tokio::spawn(async move {
        let mut firing: std::collections::HashMap<i32, std::collections::HashSet<String>> = std::collections::HashMap::new();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            let rules = match db::list_correlation_rules(&correlation_pool).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Correlation sweep: failed to read rules: {}", e);
                    continue;
                }
            };

            for rule in rules {
                if !rule.enabled {
                    firing.remove(&rule.id);
                    continue;
                }

                let hits = match db::correlation_rule_hits(&correlation_pool, &rule).await {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("Correlation sweep: rule '{}' query failed: {}", rule.name, e);
                        continue;
                    }
                };

                let currently_firing = firing.entry(rule.id).or_default();
                let mut still_firing = std::collections::HashSet::new();

                for hit in hits {
                    still_firing.insert(hit.group_value.clone());
                    if !currently_firing.contains(&hit.group_value) {
                        notify::trigger_alert(
                            &correlation_pool, &rule.alert_severity,
                            &format!(
                                "[CORRELATION] {}: {} \"{}\" events from {} in {}min (threshold {})",
                                rule.name, hit.count, rule.match_label, hit.group_value, rule.window_minutes, rule.threshold_count
                            ),
                            &hit.group_value,
                        ).await;
                    }
                }

                *currently_firing = still_firing;
            }
        }
    });

    // Syslog receiver: bound once here, if enabled -- like
    // DATABASE_URL/FRONTEND_ORIGIN, this is an infra-level socket bind,
    // so toggling it takes a restart (see src/syslog.rs's module
    // comment). The CIDR allowlist is NOT restart-gated: this task
    // refreshes the shared list from the DB every 30s, so tightening or
    // loosening source IPs is live.
    let syslog_allowlist: Arc<tokio::sync::RwLock<Vec<String>>> = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    {
        let syslog_pool = state.pool.clone();
        let allowlist = syslog_allowlist.clone();
        tokio::spawn(async move {
            loop {
                match db::get_syslog_config(&syslog_pool).await {
                    Ok(cfg) => {
                        let cidrs: Vec<String> = cfg.allowed_cidrs.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
                        *allowlist.write().await = cidrs;
                    }
                    Err(e) => eprintln!("Syslog: failed to refresh allowlist: {}", e),
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });
    }

    match db::get_syslog_config(&state.pool).await {
        Ok(cfg) => {
            if cfg.enabled_udp {
                let pool = state.pool.clone();
                let allowlist = syslog_allowlist.clone();
                tokio::spawn(async move { syslog::run_udp_listener(pool, allowlist).await });
            }
            if cfg.enabled_tcp {
                let pool = state.pool.clone();
                let allowlist = syslog_allowlist.clone();
                tokio::spawn(async move { syslog::run_tcp_listener(pool, allowlist).await });
            }
        }
        Err(e) => eprintln!("Syslog: failed to read config at startup, receiver not started: {}", e),
    }

    // Router maps URL paths + HTTP methods to handler functions.
    // .with_state attaches our share AppState so every handler can use it.
    let app = Router::new()
        .route("/logs", get(list_logs).post(create_log))
        .route("/logs/summary", get(logs_summary))
        .route("/logs/{id}/review", post(set_log_review_handler))
        .route("/audit-log", get(list_audit_log_handler))
        .route("/audit-log/verify", get(verify_audit_log_handler))
        .route("/logs/checkpoints", get(list_log_checkpoints_handler))
        .route("/signup", post(signup))
        .route("/signup-status", get(signup_status))
        .route("/change-password", post(change_password))
        .route("/login", post(login))
        .route("/mfa/login-verify", post(mfa_login_verify))
        .route("/mfa/setup", post(mfa_setup))
        .route("/mfa/verify", post(mfa_verify_setup))
        .route("/mfa/disable", post(mfa_disable))
        .route("/mfa/status", get(mfa_status))
        .route("/users", get(list_users))
        .route("/admin/users", post(admin_create_user))
        .route("/admin/users/{user_id}", axum::routing::delete(admin_delete_user))
        .route("/settings", get(get_settings).post(update_settings))
        .route("/me", get(me))
        .route("/agents", get(list_agents))
        .route("/agents/register", post(register_agent))
        .route("/agents/config", get(get_agent_config))
        .route("/agents/enrollment-token", post(generate_enrollment_token))
        .route("/agents/self-register", post(self_register_agent))
        .route("/agents/{agent_id}", axum::routing::delete(delete_agent_handler))
        .route("/agents/{agent_id}/paths", get(list_watched_paths).post(add_watched_path_handler))
        .route("/agents/ping", get(agent_ping))
        .route("/notifications", get(list_notification_channels_handler).post(create_notification_channel_handler))
        .route("/notifications/{id}", axum::routing::delete(delete_notification_channel_handler))
        .route("/notifications/{id}/test", post(test_notification_channel_handler))
        .route("/directory/config", get(get_directory_config).post(update_directory_config))
        .route("/directory/test", post(test_directory_connection))
        .route("/directory/sync", post(sync_directory_now))
        .route("/directory/hosts", get(list_directory_hosts))
        .route("/directory/deployment-package", post(create_deployment_package))
        .route("/directory/deployment-tokens", get(list_deployment_tokens))
        .route("/directory/deployment-tokens/{id}", axum::routing::delete(revoke_deployment_token))
        .route("/correlation-rules/labels", get(list_correlation_rule_labels))
        .route("/correlation-rules", get(list_correlation_rules_handler).post(create_correlation_rule_handler))
        .route("/correlation-rules/{id}", axum::routing::patch(update_correlation_rule_handler).delete(delete_correlation_rule_handler))
        .route("/syslog/config", get(get_syslog_config_handler).post(update_syslog_config_handler))
        .route("/archive/config", get(get_archive_config_handler).post(update_archive_config_handler))
        .route("/archive/test", post(test_archive_connection_handler))
        .route("/health", get(health))
        .route("/logout", post(logout))
        .route("/paths/{path_id}", axum::routing::delete(delete_watched_path_handler))
        .route("/paths/{path_id}/enabled", post(set_path_enabled_handler))
        .route("/version", get(version))
        .route("/install/linux.sh", get(linux_install_script))
        .route("/install/windows.ps1", get(windows_install_script))
        .fallback_service(ServeDir::new("static"))
        .with_state(state)
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache"),
        ));

    // Bind to all network interfaces on port 3000.
    // This call runs "forever" -- it's the event loop that waits for
    // and dispatches incoming HTTP requests. Unlike your SLI's main(),
    // this doesn't return until the server is shut down.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
