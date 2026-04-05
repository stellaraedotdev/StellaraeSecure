use axum::{
    extract::{Path, Query},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use stellarae_oauth2::{
    config::{Config, PermissionEnforcementMode},
    staffdb,
    state::AppState,
};

#[derive(Debug, Deserialize)]
struct LookupQuery {
    username: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct AccountFixture {
    id: String,
    username: String,
    email: String,
    is_active: bool,
    account_type: String,
}

#[derive(Debug, Serialize)]
struct EffectivePermissionsFixture {
    account_id: String,
    permissions: Vec<String>,
}

async fn spawn_mock_staffdb(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock staffdb listener");
    let address = listener.local_addr().expect("local addr");
    let server = axum::serve(listener, router);

    tokio::spawn(async move {
        let _ = server.await;
    });

    format!("http://{}", address)
}

fn build_state(staffdb_base_url: String) -> AppState {
    AppState::new(Config {
        host: "127.0.0.1".parse().expect("host"),
        port: 4000,
        environment: "test".to_string(),
        service_id: "oauth2-test".to_string(),
        log_level: "info".to_string(),
        database_url: "sqlite::memory:".to_string(),
        issuer: "https://example.test/oauth2".to_string(),
        admin_api_key: "admin-key".to_string(),
        staffdb_base_url,
        staffdb_api_key: "staffdb-key".to_string(),
        twofa_base_url: None,
        twofa_api_key: None,
        access_token_ttl_seconds: 900,
        refresh_token_ttl_seconds: 2592000,
        auth_code_ttl_seconds: 300,
        panel_session_ttl_seconds: 900,
        permission_enforcement_mode: PermissionEnforcementMode::Enforce,
        staff_identity_hmac_secret: "test-secret".to_string(),
        staff_identity_max_skew_seconds: 120,
        stepup_session_freshness_seconds: 300,
    })
    .expect("test app state")
}

#[tokio::test]
async fn lookup_account_uses_expected_query_and_auth_header() {
    let router = Router::new().route(
        "/api/accounts/lookup",
        get(|headers: HeaderMap, Query(query): Query<LookupQuery>| async move {
            let authorization = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .expect("authorization header");
            assert_eq!(authorization, "Bearer staffdb-key");
            let correlation_id = headers
                .get("x-correlation-id")
                .and_then(|value| value.to_str().ok())
                .expect("correlation id header");
            assert_eq!(correlation_id, "corr-lookup");
            assert_eq!(query.username.as_deref(), Some("alice"));
            assert_eq!(query.email, None);

            Json(AccountFixture {
                id: "account-1".to_string(),
                username: "alice".to_string(),
                email: "alice@example.com".to_string(),
                is_active: true,
                account_type: "staff".to_string(),
            })
        }),
    );

    let base_url = spawn_mock_staffdb(router).await;
    let state = build_state(base_url);

    let account = staffdb::lookup_account(&state, Some("alice"), None, "corr-lookup")
        .await
        .expect("lookup account");

    assert_eq!(account.id, "account-1");
    assert_eq!(account.username, "alice");
    assert!(account.is_active);
    assert_eq!(account.account_type, "staff");
}

#[tokio::test]
async fn get_account_by_id_hits_expected_path() {
    let router = Router::new().route(
        "/api/accounts/:account_id",
        get(|Path(account_id): Path<String>, headers: HeaderMap| async move {
            let authorization = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .expect("authorization header");
            assert_eq!(authorization, "Bearer staffdb-key");
            let correlation_id = headers
                .get("x-correlation-id")
                .and_then(|value| value.to_str().ok())
                .expect("correlation id header");
            assert_eq!(correlation_id, "corr-account");
            assert_eq!(account_id, "account-2");

            Json(AccountFixture {
                id: account_id,
                username: "bob".to_string(),
                email: "bob@example.com".to_string(),
                is_active: true,
                account_type: "staff".to_string(),
            })
        }),
    );

    let base_url = spawn_mock_staffdb(router).await;
    let state = build_state(base_url);

    let account = staffdb::get_account_by_id(&state, "account-2", "corr-account")
        .await
        .expect("get account by id");

    assert_eq!(account.id, "account-2");
    assert_eq!(account.username, "bob");
    assert_eq!(account.email, "bob@example.com");
}

#[tokio::test]
async fn get_effective_permissions_parses_permission_payload() {
    let router = Router::new().route(
        "/api/rbac/accounts/:account_id/permissions/effective",
        get(|Path(account_id): Path<String>, headers: HeaderMap| async move {
            let authorization = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .expect("authorization header");
            assert_eq!(authorization, "Bearer staffdb-key");
            let correlation_id = headers
                .get("x-correlation-id")
                .and_then(|value| value.to_str().ok())
                .expect("correlation id header");
            assert_eq!(correlation_id, "corr-perms");
            assert_eq!(account_id, "account-3");

            Json(EffectivePermissionsFixture {
                account_id,
                permissions: vec![
                    "oauth.client.create".to_string(),
                    "panel.audit.read".to_string(),
                ],
            })
        }),
    );

    let base_url = spawn_mock_staffdb(router).await;
    let state = build_state(base_url);

    let permissions = staffdb::get_effective_permissions(&state, "account-3", "corr-perms")
        .await
        .expect("effective permissions");

    assert_eq!(permissions.account_id, "account-3");
    assert_eq!(permissions.permissions.len(), 2);
    assert!(permissions
        .permissions
        .contains(&"oauth.client.create".to_string()));
}