// Integration tests for staffdb

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;
    use stellarae_staffdb::auth::password::{hash_password, verify_password};
    use stellarae_staffdb::auth::service_auth::extract_api_key;
    use stellarae_staffdb::db::migrations::run_migrations;
    use stellarae_staffdb::db::{
        AccountRepository,
        RbacRepository,
        SqliteAccountRepository,
        SqliteRbacRepository,
    };

    async fn test_pool() -> sqlx::SqlitePool {
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite pool should initialize")
    }

    // Password hashing tests
    #[test]
    fn test_password_hashing_integration() {
        let password = "test_password_123!@";
        let hash = hash_password(password).expect("hash should succeed");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_invalid_password() {
        let password = "correct_password";
        let hash = hash_password(password).expect("hash should succeed");
        let invalid = verify_password("wrong_password", &hash).expect("verify should succeed");
        assert!(!invalid);
    }

    #[test]
    fn test_password_uniqueness() {
        let password = "same_password";
        let hash1 = hash_password(password).expect("hash1 should succeed");
        let hash2 = hash_password(password).expect("hash2 should succeed");
        // Hashes should be different due to random salts
        assert_ne!(hash1, hash2);
        // But both should verify the same password
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    // Service authentication tests
    #[test]
    fn test_extract_api_key_valid_bearer() {
        let header = "Bearer test-key-123";
        let result = extract_api_key(header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-key-123");
    }

    #[test]
    fn test_extract_api_key_invalid_format() {
        let header = "Basic test-key";
        let result = extract_api_key(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_api_key_empty_bearer() {
        let header = "Bearer ";
        let result = extract_api_key(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_minimum_length() {
        let short_password = "short";
        let hash = hash_password(short_password).expect("hash should work even for short passwords");
        let valid = verify_password(short_password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_password_special_characters() {
        let password = "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/";
        let hash = hash_password(password).expect("hash should handle special chars");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn test_password_unicode() {
        let password = "بل میں آپ کو🚀مثال دیتا ہوں";
        let hash = hash_password(password).expect("hash should handle unicode");
        let valid = verify_password(password, &hash).expect("verify should succeed");
        assert!(valid);
    }

    #[tokio::test]
    async fn test_rbac_system_roles_seeded() {
        let pool = test_pool().await;
        run_migrations(&pool)
            .await
            .expect("migrations should succeed");

        let repo = SqliteRbacRepository::new(pool.clone());
        let roles = repo
            .list_rbac_roles()
            .await
            .expect("role listing should succeed");

        let names: std::collections::HashSet<String> =
            roles.into_iter().map(|r| r.name).collect();
        assert!(names.contains("super_admin"));
        assert!(names.contains("security_admin"));
        assert!(names.contains("support_readonly"));
    }

    #[tokio::test]
    async fn test_rbac_effective_permissions_lifecycle() {
        let pool = test_pool().await;
        run_migrations(&pool)
            .await
            .expect("migrations should succeed");

        let account_repo = SqliteAccountRepository::new(pool.clone());
        let rbac_repo = SqliteRbacRepository::new(pool.clone());

        let account = account_repo
            .create_account("rbac_user", "rbac@example.com", "hash", "staff")
            .await
            .expect("account creation should succeed");

        let role = rbac_repo
            .create_rbac_role("oauth_admin", Some("OAuth administration"), false)
            .await
            .expect("role creation should succeed");

        let permission = rbac_repo
            .create_permission(
                "oauth.client.create.integration_test",
                Some("Create OAuth clients"),
            )
            .await
            .expect("permission creation should succeed");

        rbac_repo
            .assign_permission_to_role(&role.id, &permission.id)
            .await
            .expect("permission assignment should succeed");

        rbac_repo
            .assign_role_to_account(&account.id, &role.id, Some("test-service"))
            .await
            .expect("role assignment should succeed");

        let effective = rbac_repo
            .get_effective_permissions(&account.id)
            .await
            .expect("effective permission lookup should succeed");
        assert_eq!(effective, vec!["oauth.client.create.integration_test".to_string()]);

        rbac_repo
            .revoke_role_from_account(&account.id, &role.id)
            .await
            .expect("role revoke should succeed");

        let effective_after_revoke = rbac_repo
            .get_effective_permissions(&account.id)
            .await
            .expect("effective permission lookup should succeed after revoke");
        assert!(effective_after_revoke.is_empty());
    }
}
