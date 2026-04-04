use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    config::PermissionEnforcementMode,
    error::AppError,
    models::{AccessToken, AuthorizationCode, OAuthClient, PendingConsent, RefreshToken},
    staffdb,
    state::{generate_secret, now_plus_seconds, sha256_hex, AppState},
};

const PERM_OAUTH_CLIENT_CREATE: &str = "oauth.client.create";
const PERM_OAUTH_CLIENT_READ: &str = "oauth.client.read";
const PERM_OAUTH_CLIENT_COLLABORATOR_MANAGE: &str = "oauth.client.collaborator.manage";
const PERM_OAUTH_TOKEN_REVOKE: &str = "oauth.token.revoke";
const PERM_OAUTH_TOKEN_INTROSPECT: &str = "oauth.token.introspect";
const PERM_OAUTH_STAFF_AUTHORIZE: &str = "oauth.staff.authorize";

const DECISION_ALLOW: &str = "allow";
const DECISION_DENY: &str = "deny";
const DECISION_OBSERVE_ALLOW: &str = "observe_allow";
const DECISION_OBSERVE_DENY: &str = "observe_deny";
const DECISION_SKIP: &str = "skip";

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: String,
    environment: String,
    version: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    ready: bool,
    service: String,
    database: &'static str,
    staffdb_base_url: String,
    permission_enforcement_mode: String,
}

#[derive(Debug, Deserialize)]
struct RegisterClientRequest {
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    audience: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterClientResponse {
    client_id: String,
    client_secret: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    audience: String,
    owner_account_id: String,
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    audience: String,
    owner_account_id: String,
    collaborator_account_ids: Vec<String>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CollaboratorRequest {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct CollaboratorsResponse {
    client_id: String,
    owner_account_id: String,
    collaborator_account_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthorizePendingResponse {
    request_id: String,
    client_id: String,
    requested_scope: Vec<String>,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct ConsentRequest {
    request_id: String,
    approve: bool,
}

#[derive(Debug, Serialize)]
struct ConsentResponse {
    approved: bool,
    redirect_to: String,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    client_id: String,
    client_secret: String,
    redirect_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    scope: String,
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct IntrospectResponse {
    active: bool,
    client_id: Option<String>,
    sub: Option<String>,
    scope: Option<String>,
    permissions: Option<Vec<String>>,
    exp: Option<i64>,
    token_type: Option<&'static str>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/api/clients", post(register_client))
        .route("/api/clients/:client_id", get(get_client))
        .route(
            "/api/clients/:client_id/collaborators",
            post(add_collaborator).get(list_collaborators),
        )
        .route(
            "/api/clients/:client_id/collaborators/:account_id",
            delete(remove_collaborator),
        )
        .route("/api/authorize", get(authorize))
        .route("/api/consent", post(consent))
        .route("/api/token", post(token))
        .route("/api/revoke", post(revoke))
        .route("/api/introspect", post(introspect))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: state.config.service_id,
        environment: state.config.environment,
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready(State(state): State<AppState>) -> Json<ReadyResponse> {
    Json(ReadyResponse {
        ready: true,
        service: state.config.service_id,
        database: "in-memory",
        staffdb_base_url: state.config.staffdb_base_url,
        permission_enforcement_mode: state
            .config
            .permission_enforcement_mode
            .as_str()
            .to_string(),
    })
}

async fn register_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterClientRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(
        &state,
        &headers,
        PERM_OAUTH_CLIENT_CREATE,
        "register_client",
    )
    .await?;

    let owner_account_id = verified_staff_actor_id(&state, &headers)?;

    if payload.name.trim().is_empty() {
        return Err(AppError::Validation("name is required".to_string()));
    }
    if payload.redirect_uris.is_empty() {
        return Err(AppError::Validation(
            "at least one redirect URI is required".to_string(),
        ));
    }

    for uri in &payload.redirect_uris {
        let parsed = url::Url::parse(uri)
            .map_err(|_| AppError::Validation(format!("invalid redirect URI: {uri}")))?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(AppError::Validation(format!(
                "unsupported redirect URI scheme: {uri}"
            )));
        }
    }

    let audience = payload.audience.unwrap_or_else(|| "public".to_string());
    if audience != "public" && audience != "staff" {
        return Err(AppError::Validation(
            "audience must be either public or staff".to_string(),
        ));
    }

    let client_id = Uuid::new_v4().to_string();
    let client_secret = generate_secret(48);
    let client = OAuthClient {
        client_id: client_id.clone(),
        client_secret_hash: sha256_hex(&client_secret),
        name: payload.name.clone(),
        redirect_uris: payload.redirect_uris.clone(),
        allowed_scopes: payload.allowed_scopes.clone(),
        audience: audience.clone(),
        owner_account_id: owner_account_id.clone(),
        collaborator_account_ids: Vec::new(),
        created_at: Utc::now(),
    };

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
    store.clients.insert(client_id.clone(), client);

    Ok((
        StatusCode::CREATED,
        Json(RegisterClientResponse {
            client_id,
            client_secret,
            name: payload.name,
            redirect_uris: payload.redirect_uris,
            allowed_scopes: payload.allowed_scopes,
            audience,
            owner_account_id,
        }),
    ))
}

async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Json<ClientResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(&state, &headers, PERM_OAUTH_CLIENT_READ, "get_client").await?;
    let caller_account_id = verified_staff_actor_id(&state, &headers)?;
    let store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get(&client_id).ok_or(AppError::NotFound)?;
    ensure_client_access(&caller_account_id, client)?;

    Ok(Json(ClientResponse {
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        redirect_uris: client.redirect_uris.clone(),
        allowed_scopes: client.allowed_scopes.clone(),
        audience: client.audience.clone(),
        owner_account_id: client.owner_account_id.clone(),
        collaborator_account_ids: client.collaborator_account_ids.clone(),
        created_at: client.created_at.to_rfc3339(),
    }))
}

async fn add_collaborator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(payload): Json<CollaboratorRequest>,
) -> Result<Json<CollaboratorsResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(
        &state,
        &headers,
        PERM_OAUTH_CLIENT_COLLABORATOR_MANAGE,
        "add_collaborator",
    )
    .await?;

    let caller_account_id = verified_staff_actor_id(&state, &headers)?;

    if payload.account_id.trim().is_empty() {
        return Err(AppError::Validation("account_id is required".to_string()));
    }

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get_mut(&client_id).ok_or(AppError::NotFound)?;
    ensure_client_access(&caller_account_id, client)?;

    if payload.account_id == client.owner_account_id {
        return Ok(Json(CollaboratorsResponse {
            client_id: client.client_id.clone(),
            owner_account_id: client.owner_account_id.clone(),
            collaborator_account_ids: client.collaborator_account_ids.clone(),
        }));
    }

    if !client
        .collaborator_account_ids
        .iter()
        .any(|id| id == &payload.account_id)
    {
        client.collaborator_account_ids.push(payload.account_id.clone());
    }

    Ok(Json(CollaboratorsResponse {
        client_id: client.client_id.clone(),
        owner_account_id: client.owner_account_id.clone(),
        collaborator_account_ids: client.collaborator_account_ids.clone(),
    }))
}

async fn list_collaborators(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Json<CollaboratorsResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(&state, &headers, PERM_OAUTH_CLIENT_READ, "list_collaborators")
        .await?;

    let caller_account_id = verified_staff_actor_id(&state, &headers)?;
    let store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get(&client_id).ok_or(AppError::NotFound)?;
    ensure_client_access(&caller_account_id, client)?;

    Ok(Json(CollaboratorsResponse {
        client_id: client.client_id.clone(),
        owner_account_id: client.owner_account_id.clone(),
        collaborator_account_ids: client.collaborator_account_ids.clone(),
    }))
}

async fn remove_collaborator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, account_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(
        &state,
        &headers,
        PERM_OAUTH_CLIENT_COLLABORATOR_MANAGE,
        "remove_collaborator",
    )
    .await?;

    let caller_account_id = verified_staff_actor_id(&state, &headers)?;
    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get_mut(&client_id).ok_or(AppError::NotFound)?;
    ensure_client_access(&caller_account_id, client)?;

    client.collaborator_account_ids.retain(|id| id != &account_id);
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<AuthorizePendingResponse>, AppError> {
    if query.response_type != "code" {
        return Err(AppError::Validation(
            "only response_type=code is supported".to_string(),
        ));
    }

    let client = {
        let store = state
            .store
            .lock()
            .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
        store
            .clients
            .get(&query.client_id)
            .cloned()
            .ok_or(AppError::NotFound)?
    };

    if !client.redirect_uris.iter().any(|u| u == &query.redirect_uri) {
        return Err(AppError::Validation("redirect_uri mismatch".to_string()));
    }

    let requested_scope = parse_scope(query.scope.as_deref().unwrap_or("openid profile"));
    if !requested_scope
        .iter()
        .all(|s| client.allowed_scopes.iter().any(|allowed| allowed == s))
    {
        return Err(AppError::Validation(
            "requested scope is not allowed for this client".to_string(),
        ));
    }

    let actor_account_id = verified_staff_actor_id(&state, &headers)?;
    let account = staffdb::get_account_by_id(&state, &actor_account_id).await?;
    if !account.is_active {
        return Err(AppError::Authorization);
    }

    let mut effective_permissions = Vec::new();
    if client.audience == "staff" && account.account_type != "staff" {
        return Err(AppError::Authorization);
    }
    if client.audience == "staff" {
        let permission_result =
            staffdb::get_effective_permissions(&state, &account.id).await?;
        effective_permissions = permission_result.permissions;

        enforce_permission_claim(
            &state,
            &account.id,
            &effective_permissions,
            PERM_OAUTH_STAFF_AUTHORIZE,
            "authorize",
            Some(&correlation_id_from_headers(&headers)),
        )?;
    }

    let pending = PendingConsent {
        request_id: Uuid::new_v4().to_string(),
        client_id: client.client_id.clone(),
        redirect_uri: query.redirect_uri,
        state: query.state,
        scope: requested_scope,
        account_id: account.id,
        account_type: account.account_type,
        effective_permissions: effective_permissions.clone(),
        expires_at: now_plus_seconds(state.config.auth_code_ttl_seconds),
    };

    let response = AuthorizePendingResponse {
        request_id: pending.request_id.clone(),
        client_id: pending.client_id.clone(),
        requested_scope: pending.scope.clone(),
        expires_at: pending.expires_at.to_rfc3339(),
    };

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
    store
        .pending_consents
        .insert(pending.request_id.clone(), pending);

    Ok(Json(response))
}

async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ConsentRequest>,
) -> Result<Json<ConsentResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    let actor_account_id = verified_staff_actor_id(&state, &headers)?;

    let pending = {
        let mut store = state
            .store
            .lock()
            .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

        store
            .pending_consents
            .remove(&payload.request_id)
            .ok_or(AppError::NotFound)?
    };

    if actor_account_id != pending.account_id {
        return Err(AppError::Authorization);
    }

    if Utc::now() > pending.expires_at {
        return Err(AppError::Validation("consent request expired".to_string()));
    }

    if !payload.approve {
        let deny_url = with_query(
            &pending.redirect_uri,
            &[(&"error", &"access_denied"), (&"state", pending.state.as_deref().unwrap_or(""))],
        )?;
        return Ok(Json(ConsentResponse {
            approved: false,
            redirect_to: deny_url,
        }));
    }

    let code = generate_secret(64);
    let auth_code = AuthorizationCode {
        code: code.clone(),
        client_id: pending.client_id.clone(),
        account_id: pending.account_id,
        scope: pending.scope,
        effective_permissions: pending.effective_permissions,
        redirect_uri: pending.redirect_uri.clone(),
        expires_at: now_plus_seconds(state.config.auth_code_ttl_seconds),
    };

    {
        let mut store = state
            .store
            .lock()
            .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
        store.auth_codes.insert(code.clone(), auth_code);
    }

    let callback = with_query(
        &pending.redirect_uri,
        &[(&"code", &code), (&"state", pending.state.as_deref().unwrap_or(""))],
    )?;

    Ok(Json(ConsentResponse {
        approved: true,
        redirect_to: callback,
    }))
}

async fn token(
    State(state): State<AppState>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let client = validate_client(&state, &payload.client_id, &payload.client_secret)?;

    if payload.grant_type == "authorization_code" {
        let code = payload
            .code
            .as_deref()
            .ok_or_else(|| AppError::Validation("code is required".to_string()))?;
        let redirect_uri = payload
            .redirect_uri
            .as_deref()
            .ok_or_else(|| AppError::Validation("redirect_uri is required".to_string()))?;

        let auth_code = {
            let mut store = state
                .store
                .lock()
                .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
            store.auth_codes.remove(code).ok_or(AppError::Authentication)?
        };

        if auth_code.client_id != client.client_id || auth_code.redirect_uri != redirect_uri {
            return Err(AppError::Authentication);
        }
        if Utc::now() > auth_code.expires_at {
            return Err(AppError::Authentication);
        }

        let access_token = issue_access_token(
            &state,
            &auth_code.client_id,
            &auth_code.account_id,
            &auth_code.scope,
            &auth_code.effective_permissions,
        )?;
        let refresh_token = issue_refresh_token(
            &state,
            &auth_code.client_id,
            &auth_code.account_id,
            &auth_code.scope,
            &auth_code.effective_permissions,
        )?;

        return Ok(Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl_seconds,
            refresh_token,
            scope: auth_code.scope.join(" "),
            permissions: auth_code.effective_permissions,
        }));
    }

    if payload.grant_type == "refresh_token" {
        let refresh = payload
            .refresh_token
            .as_deref()
            .ok_or_else(|| AppError::Validation("refresh_token is required".to_string()))?;

        let refresh_data = {
            let mut store = state
                .store
                .lock()
                .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
            let mut token = store
                .refresh_tokens
                .remove(refresh)
                .ok_or(AppError::Authentication)?;
            if token.revoked || Utc::now() > token.expires_at {
                return Err(AppError::Authentication);
            }
            if token.client_id != client.client_id {
                return Err(AppError::Authentication);
            }
            token.revoked = true;
            token
        };

        let access_token = issue_access_token(
            &state,
            &refresh_data.client_id,
            &refresh_data.account_id,
            &refresh_data.scope,
            &refresh_data.effective_permissions,
        )?;
        let new_refresh_token = issue_refresh_token(
            &state,
            &refresh_data.client_id,
            &refresh_data.account_id,
            &refresh_data.scope,
            &refresh_data.effective_permissions,
        )?;

        return Ok(Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl_seconds,
            refresh_token: new_refresh_token,
            scope: refresh_data.scope.join(" "),
            permissions: refresh_data.effective_permissions,
        }));
    }

    Err(AppError::Validation("unsupported grant_type".to_string()))
}

async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RevokeRequest>,
) -> Result<StatusCode, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(&state, &headers, PERM_OAUTH_TOKEN_REVOKE, "revoke").await?;

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    if let Some(token) = store.access_tokens.get_mut(&payload.token) {
        token.revoked = true;
    }
    if let Some(token) = store.refresh_tokens.get_mut(&payload.token) {
        token.revoked = true;
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    enforce_header_actor_permission(
        &state,
        &headers,
        PERM_OAUTH_TOKEN_INTROSPECT,
        "introspect",
    )
    .await?;

    let store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    if let Some(token) = store.access_tokens.get(&payload.token) {
        let active = !token.revoked && Utc::now() <= token.expires_at;
        return Ok(Json(IntrospectResponse {
            active,
            client_id: if active { Some(token.client_id.clone()) } else { None },
            sub: if active { Some(token.account_id.clone()) } else { None },
            scope: if active { Some(token.scope.join(" ")) } else { None },
            permissions: if active {
                Some(token.effective_permissions.clone())
            } else {
                None
            },
            exp: if active { Some(token.expires_at.timestamp()) } else { None },
            token_type: if active { Some("access_token") } else { None },
        }));
    }

    if let Some(token) = store.refresh_tokens.get(&payload.token) {
        let active = !token.revoked && Utc::now() <= token.expires_at;
        return Ok(Json(IntrospectResponse {
            active,
            client_id: if active { Some(token.client_id.clone()) } else { None },
            sub: if active { Some(token.account_id.clone()) } else { None },
            scope: if active { Some(token.scope.join(" ")) } else { None },
            permissions: if active {
                Some(token.effective_permissions.clone())
            } else {
                None
            },
            exp: if active { Some(token.expires_at.timestamp()) } else { None },
            token_type: if active { Some("refresh_token") } else { None },
        }));
    }

    Ok(Json(IntrospectResponse {
        active: false,
        client_id: None,
        sub: None,
        scope: None,
        permissions: None,
        exp: None,
        token_type: None,
    }))
}

fn assert_admin_key(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Authentication)?;

    if key != state.config.admin_api_key {
        return Err(AppError::Authentication);
    }

    Ok(())
}

fn verified_staff_actor_id(state: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    let account_id = headers
        .get("x-staff-account-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or(AppError::Authentication)?;

    let signed_ts = headers
        .get("x-staff-identity-ts")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Authentication)?
        .parse::<i64>()
        .map_err(|_| AppError::Authentication)?;

    let signature_hex = headers
        .get("x-staff-identity-sig")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Authentication)?;

    let now = Utc::now().timestamp();
    let skew = (now - signed_ts).abs();
    if skew > state.config.staff_identity_max_skew_seconds {
        return Err(AppError::Authentication);
    }

    let signature = decode_hex(signature_hex)?;

    let mut mac = HmacSha256::new_from_slice(state.config.staff_identity_hmac_secret.as_bytes())
        .map_err(|_| AppError::Authentication)?;
    mac.update(format!("{account_id}:{signed_ts}").as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| AppError::Authentication)?;

    Ok(account_id)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, AppError> {
    if value.len() % 2 != 0 {
        return Err(AppError::Authentication);
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let high = (bytes[i] as char)
            .to_digit(16)
            .ok_or(AppError::Authentication)?;
        let low = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or(AppError::Authentication)?;
        out.push(((high << 4) | low) as u8);
    }

    Ok(out)
}

fn correlation_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn has_client_access(actor_account_id: &str, client: &OAuthClient) -> bool {
    actor_account_id == client.owner_account_id
        || client
            .collaborator_account_ids
            .iter()
            .any(|id| id == actor_account_id)
}

fn ensure_client_access(actor_account_id: &str, client: &OAuthClient) -> Result<(), AppError> {
    if has_client_access(actor_account_id, client) {
        return Ok(());
    }

    Err(AppError::Authorization)
}

fn emit_permission_decision(
    mode: PermissionEnforcementMode,
    operation: &str,
    actor_id: Option<&str>,
    permission_key: &str,
    decision: &str,
    correlation_id: &str,
) {
    tracing::info!(
        event = "permission_decision",
        mode = mode.as_str(),
        operation = operation,
        actor_id = actor_id.unwrap_or("unknown"),
        permission_key = permission_key,
        decision = decision,
        correlation_id = correlation_id,
        "Permission policy decision recorded"
    );
}

async fn enforce_header_actor_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission_key: &str,
    operation: &str,
) -> Result<(), AppError> {
    let mode = state.config.permission_enforcement_mode;
    let correlation_id = correlation_id_from_headers(headers);

    if mode == PermissionEnforcementMode::Off {
        emit_permission_decision(
            mode,
            operation,
            None,
            permission_key,
            DECISION_SKIP,
            &correlation_id,
        );
        return Ok(());
    }

    let actor_id = match verified_staff_actor_id(state, headers) {
        Ok(actor_id) => actor_id,
        Err(_) => {
            emit_permission_decision(
                mode,
                operation,
                None,
                permission_key,
                DECISION_DENY,
                &correlation_id,
            );
            return Err(AppError::Authentication);
        }
    };

    let permission_result = staffdb::get_effective_permissions(state, &actor_id).await?;
    enforce_permission_claim(
        state,
        &actor_id,
        &permission_result.permissions,
        permission_key,
        operation,
        Some(&correlation_id),
    )
}

fn enforce_permission_claim(
    state: &AppState,
    actor_id: &str,
    permissions: &[String],
    permission_key: &str,
    operation: &str,
    correlation_id: Option<&str>,
) -> Result<(), AppError> {
    let mode = state.config.permission_enforcement_mode;
    let correlation_id = correlation_id
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if mode == PermissionEnforcementMode::Off {
        emit_permission_decision(
            mode,
            operation,
            Some(actor_id),
            permission_key,
            DECISION_SKIP,
            &correlation_id,
        );
        return Ok(());
    }

    let granted = permissions.iter().any(|perm| perm == permission_key);
    if granted {
        let decision = if mode == PermissionEnforcementMode::Observe {
            DECISION_OBSERVE_ALLOW
        } else {
            DECISION_ALLOW
        };
        emit_permission_decision(
            mode,
            operation,
            Some(actor_id),
            permission_key,
            decision,
            &correlation_id,
        );
        return Ok(());
    }

    if mode == PermissionEnforcementMode::Enforce {
        emit_permission_decision(
            mode,
            operation,
            Some(actor_id),
            permission_key,
            DECISION_DENY,
            &correlation_id,
        );
        return Err(AppError::Authorization);
    }

    emit_permission_decision(
        mode,
        operation,
        Some(actor_id),
        permission_key,
        DECISION_OBSERVE_DENY,
        &correlation_id,
    );

    Ok(())
}

fn parse_scope(scope: &str) -> Vec<String> {
    scope
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn validate_client(state: &AppState, client_id: &str, client_secret: &str) -> Result<OAuthClient, AppError> {
    let store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get(client_id).ok_or(AppError::Authentication)?;
    if client.client_secret_hash != sha256_hex(client_secret) {
        return Err(AppError::Authentication);
    }

    Ok(client.clone())
}

fn issue_access_token(
    state: &AppState,
    client_id: &str,
    account_id: &str,
    scope: &[String],
    effective_permissions: &[String],
) -> Result<String, AppError> {
    let token = generate_secret(64);
    let token_data = AccessToken {
        token: token.clone(),
        client_id: client_id.to_string(),
        account_id: account_id.to_string(),
        scope: scope.to_vec(),
        effective_permissions: effective_permissions.to_vec(),
        expires_at: now_plus_seconds(state.config.access_token_ttl_seconds),
        revoked: false,
    };

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
    store.access_tokens.insert(token.clone(), token_data);

    Ok(token)
}

fn issue_refresh_token(
    state: &AppState,
    client_id: &str,
    account_id: &str,
    scope: &[String],
    effective_permissions: &[String],
) -> Result<String, AppError> {
    let token = generate_secret(72);
    let token_data = RefreshToken {
        token: token.clone(),
        client_id: client_id.to_string(),
        account_id: account_id.to_string(),
        scope: scope.to_vec(),
        effective_permissions: effective_permissions.to_vec(),
        expires_at: now_plus_seconds(state.config.refresh_token_ttl_seconds),
        revoked: false,
    };

    let mut store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;
    store.refresh_tokens.insert(token.clone(), token_data);

    Ok(token)
}

fn with_query(base_uri: &str, pairs: &[(&str, &str)]) -> Result<String, AppError> {
    let mut url = url::Url::parse(base_uri)
        .map_err(|_| AppError::Validation("invalid callback URI".to_string()))?;
    for (k, v) in pairs {
        if !v.is_empty() {
            url.query_pairs_mut().append_pair(k, v);
        }
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use axum::http::{HeaderMap, HeaderValue};

    use crate::config::{Config, PermissionEnforcementMode};
    use crate::state::AppState;

    use super::{correlation_id_from_headers, enforce_permission_claim, has_client_access};
    use crate::models::OAuthClient;
    use chrono::Utc;

    fn build_state(mode: PermissionEnforcementMode) -> AppState {
        AppState::new(Config {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 4000,
            environment: "test".to_string(),
            service_id: "oauth2-test".to_string(),
            log_level: "info".to_string(),
            database_url: "sqlite::memory:".to_string(),
            issuer: "https://example.test/oauth2".to_string(),
            admin_api_key: "admin-key".to_string(),
            staffdb_base_url: "http://127.0.0.1:3000".to_string(),
            staffdb_api_key: "staffdb-key".to_string(),
            access_token_ttl_seconds: 900,
            refresh_token_ttl_seconds: 2592000,
            auth_code_ttl_seconds: 300,
            permission_enforcement_mode: mode,
            staff_identity_hmac_secret: "test-secret".to_string(),
            staff_identity_max_skew_seconds: 120,
        })
    }

    #[test]
    fn permission_claim_enforce_mode_denies_missing_permission() {
        let state = build_state(PermissionEnforcementMode::Enforce);
        let result = enforce_permission_claim(
            &state,
            "actor-1",
            &[],
            "oauth.client.create",
            "register_client",
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn permission_claim_observe_mode_allows_missing_permission() {
        let state = build_state(PermissionEnforcementMode::Observe);
        let result = enforce_permission_claim(
            &state,
            "actor-1",
            &[],
            "oauth.client.create",
            "register_client",
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn correlation_id_from_header_is_used_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert("x-correlation-id", HeaderValue::from_static("corr-123"));

        let correlation_id = correlation_id_from_headers(&headers);
        assert_eq!(correlation_id, "corr-123");
    }

    #[test]
    fn correlation_id_is_generated_when_missing() {
        let headers = HeaderMap::new();

        let correlation_id = correlation_id_from_headers(&headers);
        assert!(!correlation_id.is_empty());
        assert!(uuid::Uuid::parse_str(&correlation_id).is_ok());
    }

    #[test]
    fn client_access_allows_owner_and_collaborator() {
        let client = OAuthClient {
            client_id: "client-1".to_string(),
            client_secret_hash: "hash".to_string(),
            name: "Client".to_string(),
            redirect_uris: vec!["https://example.test/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            audience: "public".to_string(),
            owner_account_id: "owner-1".to_string(),
            collaborator_account_ids: vec!["collab-1".to_string()],
            created_at: Utc::now(),
        };

        assert!(has_client_access("owner-1", &client));
        assert!(has_client_access("collab-1", &client));
        assert!(!has_client_access("other-1", &client));
    }
}
