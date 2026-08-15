use axum::{
    extract::{FromRequestParts, State, Path},
    routing::{get, post},
    http::{request::Parts, StatusCode, HeaderMap},
    Json,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use models::{LogRow, NewLogEntry, SignupRequest, LoginRequest};
use seclog::{
    auth::{self, LoginRateLimiter},
    db,
    models,
    parser,
};
use std::{env, sync::Arc};
use tower_http::cors::{CorsLayer, Any};
use tower_http::services::ServeDir;

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
    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.github.com/repos/LordSodomiser/SecLog/releases/latest")
        .header("User-Agent", "seclog") // GitHub's API requires a User-Agent header
        .send()
        .await
        .ok()?;

    let release: GithubRelease = resp.json().await.ok()?;
    Some(release.tag_name.trim_start_matches('v').to_string())
}

async fn version() -> Json<VersionResponse> {
    let current = VERSION.trim().to_string();
    let latest = check_latest_version().await;
    let update_available = latest.as_deref().map(|l| l != current).unwrap_or(false);

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

// Axum handler can only receive specific kinds of arguments. To give every
// handler access to the DB pool, we wrap it in "shared state" that axum
// passes in automatically per-request. Arc = "atomic reference count",
// a way to share one value across many place safely, even across
// concurrent requests -- more on this in a second
#[derive(Clone)]
struct AppState {
    pool: db::DbPool,
    rate_limiter: Arc<LoginRateLimiter>,
}

async fn create_log(
    State(state): State<AppState>,
    Json(payload): Json<NewLogEntry>,
) -> Result<StatusCode, StatusCode> {
    if !payload.is_valid() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let combined = format!("{}{}{}{}", payload.severity, payload.user, payload.message, payload.host);
    let hash = parser::hash_line(&combined);

    match db::insert_log(&state.pool, &payload.severity, &payload.user, &payload.message, &payload.host, &hash)
        .await
    {
        Ok(true) => Ok(StatusCode::CREATED),
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
async fn list_logs(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<Vec<LogRow>>, StatusCode> {
    println!("Logs requested by: {} (role: {})", auth_user.username, auth_user.role);

    match db::get_all_logs(&state.pool).await {
        Ok(rows) => Ok(Json(rows)),
        Err(e) => {
            eprintln!("DB error: {}", e);
            // 500 = "Internal Server Error" -- we don't leak the raw DB
            // error to the client, just log it server-side and return
            // a generic status code. Leaking internal errors to clients
            // is itself a minor security smell worth avoiding from the start.
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn signup(
    State(state): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.username.trim().is_empty() || payload.password.len() < 15{
        return Err(StatusCode::BAD_REQUEST); // 400: malformed/insufficient input
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

    match db::create_user(&state.pool, &payload.username, &hash).await {
        Ok(Some(_user_id)) => Ok(StatusCode::CREATED),
        Ok(None) => Err(StatusCode::CONFLICT), // 409:: username already taken
        Err(e) => {
            eprintln!("DB error: {}", e);
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
    _admin: AdminUser,
    Json(payload): Json<models::AdminCreateUserRequest>,
) -> Result<(StatusCode, Json<AdminCreateUserResponse>), StatusCode> {
    if payload.username.trim().is_empty() || payload.username.len() > 255 {
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
        Ok(Some(_user_id)) => Ok((
            StatusCode::CREATED,
            Json(AdminCreateUserResponse {
                username: payload.username,
                temporary_password,
            }),
        )),

        Ok(None) => Err(StatusCode::CONFLICT),

        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<(CookieJar, Json<models::LoginResponse>), StatusCode> {
    if !state.rate_limiter.check(&payload.username) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let (user_id, stored_hash, must_change_password) =
        match db::get_user_for_login(&state.pool, &payload.username).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                state.rate_limiter.record_failure(&payload.username);
                return Err(StatusCode::UNAUTHORIZED);
            }
            Err(e) => {
                eprintln!("DB error: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    if !auth::verify_password(&payload.password, &stored_hash) {
        state.rate_limiter.record_failure(&payload.username);
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.rate_limiter.record_success(&payload.username);

    let token = auth::generate_session_token();

    if let Err(e) = db::create_session(&state.pool, &token, user_id).await {
        eprintln!("DB error: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

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
        }),
    ))
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

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
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
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_hash = auth::hash_password(&payload.new_password)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match db::update_password(&state.pool, auth_user.user_id, &new_hash).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn admin_delete_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    if user_id == admin.user_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    match db::delete_user(&state.pool, user_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<CookieJar, StatusCode> {
    if let Some(cookie) = jar.get("__Host-seclog_session") {
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
}

#[derive(serde::Deserialize)]
struct UpdateSettingsRequest {
    self_signup_enabled: bool,
}

async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<SettingsResponse>, StatusCode> {
    match db::get_self_signup_enabled(&state.pool).await {
        Ok(enabled) => Ok(Json(SettingsResponse { self_signup_enabled: enabled })),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn update_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(payload): Json<UpdateSettingsRequest>,
) -> Result<StatusCode, StatusCode> {
    match db::set_self_signup_enabled(&state.pool, payload.self_signup_enabled).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
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
    _admin: AdminUser,
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
        Ok(agent_id) => Ok(Json(models::RegisterAgentResponse { agent_id, api_key})),
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
    _admin: AdminUser,
    Path(agent_id): Path<i32>,
    Json(payload): Json<models::AddPathRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.path.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    match db::add_watched_path(&state.pool, agent_id, &payload.path).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_watched_path_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(path_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::delete_watched_path(&state.pool, path_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("DB error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_agent_handler(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(agent_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    match db::delete_agent(&state.pool, agent_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
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
    _admin: AdminUser,
    Path(path_id): Path<i32>,
    Json(payload): Json<SetPathEnabledRequest>,
) -> Result<StatusCode, StatusCode> {
    match db::set_path_enabled(&state.pool, path_id, payload.enabled).await {
        Ok(_) => Ok(StatusCode::OK),
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
    _admin: AdminUser,
) -> Result<Json<models::EnrollmentTokenResponse>, StatusCode> {
    let token = auth::generate_session_token(); // reusing the same random-token generator

    match db::create_enrollment_token(&state.pool, &token).await {
        Ok(_) => Ok(Json(models::EnrollmentTokenResponse { token })),
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
    Json(payload): Json<models::SelfRegisterRequest>,
) -> Result<Json<models::RegisterAgentResponse>, StatusCode> {
    if payload.hostname.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let valid = db::consume_enrollment_token(&state.pool, &payload.enrollment_token)
        .await
        .map_err(|e| { eprintln!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    if !valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let api_key = auth::generate_session_token();
    match db::create_agent(&state.pool, &payload.hostname, &api_key).await {
        Ok(agent_id) => Ok(Json(models::RegisterAgentResponse { agent_id, api_key })),
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

curl -fsSL "https://github.com/LordSodomiser/SecLog/releases/latest/download/shipper-linux-x86_64" \
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
sudo mv /tmp/seclog-shipper /opt/seclog-shipper/shipper
sudo chmod +x /opt/seclog-shipper/shipper

# On SELinux systems (Fedora/RHEL/Rocky/AlmaLinux), `mv` preserves the
# file's original context from /tmp (user_tmp_t) instead of picking up
# a context systemd is allowed to execute.
#
# restorecon alone only resets a file to whatever the policy database
# already maps that path to -- if there's no existing rule for
# /opt/seclog-shipper, there's nothing to restore *to* and it's a no-op.
# semanage fcontext registers that rule explicitly first, so restorecon
# actually has something to apply. Both steps are safely skipped on
# distros without SELinux tooling.
if command -v semanage >/dev/null 2>&1; then
    sudo semanage fcontext -a -t bin_t "/opt/seclog-shipper/shipper" 2>/dev/null || \
        sudo semanage fcontext -m -t bin_t "/opt/seclog-shipper/shipper"
elif command -v restorecon >/dev/null 2>&1; then
    echo "NOTE: semanage not found -- install policycoreutils-python-utils"
    echo "for a more reliable SELinux fix if the service fails to start."
fi

if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -v /opt/seclog-shipper/shipper
fi

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
sudo systemctl start seclog-shipper

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

Invoke-WebRequest -Uri "https://github.com/LordSodomiser/SecLog/releases/latest/download/shipper-windows-x86_64.exe" -OutFile "C:\seclog-shipper.exe"

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = db::create_pool(&db_url).await?;
    // CorsLayer controls which origins (domain/ports) a browser is allowed
    // to make requests from. Any::any() is permissive -- fine for local dev,
    // but something to tighten later (restrict to your actual UI's origin)
    // once this isn't just running on localhost.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    println!("Connected to MariaDB successfully!");

    db::init_schema(&pool).await?;
    db::init_users_schema(&pool).await?;
    db::init_sessions_schema(&pool).await?;
    db::init_settings_schema(&pool).await?;
    db::init_agents_schema(&pool).await?;
    db::init_watched_paths_schema(&pool).await?;
    db::init_enrollment_schema(&pool).await?;

    let state = AppState {
        pool,
        rate_limiter: Arc::new(LoginRateLimiter::new()),
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
        }
    });

    // Router maps URL paths + HTTP methods to handler functions.
    // .with_state attaches our share AppState so every handler can use it.
    let app = Router::new()
        .route("/logs", get(list_logs).post(create_log))
        .route("/signup", post(signup))
        .route("/signup-status", get(signup_status))
        .route("/change-password", post(change_password))
        .route("/login", post(login))
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
        .route("/health", get(health))
        .route("/logout", post(logout))
        .route("/paths/{path_id}", axum::routing::delete(delete_watched_path_handler))
        .route("/paths/{path_id}/enabled", post(set_path_enabled_handler))
        .route("/version", get(version))
        .route("/install/linux.sh", get(linux_install_script))
        .route("/install/windows.ps1", get(windows_install_script))
        .fallback_service(ServeDir::new("static"))
        .with_state(state)
        .layer(cors);

    // Bind to all network interfaces on port 3000.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://0.0.0.0:3000");

    // This call runs "forever" -- it's the event loop that waits for
    // and dispatches incoming HTTP requests. Unlike your SLI's main(),
    // this doesn't return until the server is shut down.
    axum::serve(listener, app).await?;

    Ok(())
}
