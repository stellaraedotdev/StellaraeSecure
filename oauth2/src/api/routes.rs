use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{AccessToken, AuthorizationCode, OAuthClient, PendingConsent, RefreshToken},
    staffdb,
    state::{generate_secret, now_plus_seconds, sha256_hex, AppState},
};

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
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    client_id: String,
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    audience: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    username: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuthorizePendingResponse {
    request_id: String,
    client_id: String,
    account_id: String,
    account_type: String,
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
    exp: Option<i64>,
    token_type: Option<&'static str>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ready", get(ready))
        .route("/api/clients", post(register_client))
        .route("/api/clients/:client_id", get(get_client))
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
    })
}

async fn register_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterClientRequest>,
) -> Result<(StatusCode, Json<RegisterClientResponse>), AppError> {
    assert_admin_key(&state, &headers)?;

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
        }),
    ))
}

async fn get_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> Result<Json<ClientResponse>, AppError> {
    assert_admin_key(&state, &headers)?;
    let store = state
        .store
        .lock()
        .map_err(|_| AppError::Internal("store lock poisoned".to_string()))?;

    let client = store.clients.get(&client_id).ok_or(AppError::NotFound)?;
    Ok(Json(ClientResponse {
        client_id: client.client_id.clone(),
        name: client.name.clone(),
        redirect_uris: client.redirect_uris.clone(),
        allowed_scopes: client.allowed_scopes.clone(),
        audience: client.audience.clone(),
        created_at: client.created_at.to_rfc3339(),
    }))
}

async fn authorize(
    State(state): State<AppState>,
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

    let account = staffdb::lookup_account(&state, query.username.as_deref(), query.email.as_deref()).await?;
    if !account.is_active {
        return Err(AppError::Authorization);
    }
    if client.audience == "staff" && account.account_type != "staff" {
        return Err(AppError::Authorization);
    }

    let pending = PendingConsent {
        request_id: Uuid::new_v4().to_string(),
        client_id: client.client_id.clone(),
        redirect_uri: query.redirect_uri,
        state: query.state,
        scope: requested_scope,
        account_id: account.id,
        account_type: account.account_type,
        expires_at: now_plus_seconds(state.config.auth_code_ttl_seconds),
    };

    let response = AuthorizePendingResponse {
        request_id: pending.request_id.clone(),
        client_id: pending.client_id.clone(),
        account_id: pending.account_id.clone(),
        account_type: pending.account_type.clone(),
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
    Json(payload): Json<ConsentRequest>,
) -> Result<Json<ConsentResponse>, AppError> {
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

        let access_token = issue_access_token(&state, &auth_code.client_id, &auth_code.account_id, &auth_code.scope)?;
        let refresh_token = issue_refresh_token(&state, &auth_code.client_id, &auth_code.account_id, &auth_code.scope)?;

        return Ok(Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl_seconds,
            refresh_token,
            scope: auth_code.scope.join(" "),
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

        let access_token = issue_access_token(&state, &refresh_data.client_id, &refresh_data.account_id, &refresh_data.scope)?;
        let new_refresh_token = issue_refresh_token(&state, &refresh_data.client_id, &refresh_data.account_id, &refresh_data.scope)?;

        return Ok(Json(TokenResponse {
            access_token,
            token_type: "Bearer",
            expires_in: state.config.access_token_ttl_seconds,
            refresh_token: new_refresh_token,
            scope: refresh_data.scope.join(" "),
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
            exp: if active { Some(token.expires_at.timestamp()) } else { None },
            token_type: if active { Some("refresh_token") } else { None },
        }));
    }

    Ok(Json(IntrospectResponse {
        active: false,
        client_id: None,
        sub: None,
        scope: None,
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
) -> Result<String, AppError> {
    let token = generate_secret(64);
    let token_data = AccessToken {
        token: token.clone(),
        client_id: client_id.to_string(),
        account_id: account_id.to_string(),
        scope: scope.to_vec(),
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
) -> Result<String, AppError> {
    let token = generate_secret(72);
    let token_data = RefreshToken {
        token: token.clone(),
        client_id: client_id.to_string(),
        account_id: account_id.to_string(),
        scope: scope.to_vec(),
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
