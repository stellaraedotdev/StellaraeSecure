# StellaraeSecure staffdb

The staffdb is the core account database service in StellaraeSecure, responsible for managing staff and user account identities, roles, and audit trails.

## Overview

**Purpose:**  
Central repository for user and staff account information, providing a single source of truth for identity and role management across StellaraeSecure services (OAuth2, admin panel, etc.).

**Deployment Model:**  
Two independent instances:
- **Staff instance**: Manages internal staff accounts (higher-privileged roles, 2FA required for creation)
- **Public instance**: Manages end-user accounts (self-service registration, standard 2FA options)

**Technology Stack:**  
- Language: Rust (for security and performance)
- API: REST (axum web framework)
- Storage: SQLite (Phase 1–2), PostgreSQL (Phase 3+)
- Auth: Service-to-service API keys (rotated by HSM)
- Hashing: Argon2id (OWASP recommended)
- Logging: Structured tracing to stdout

## Architecture

### Security Boundaries

**What staffdb DOES store:**
- Account identity (username, email, unique ID)
- Account roles and permissions (admin, staff, user)
- Password hashes (Argon2id, salted, high work factor)
- Account status (active, disabled, scheduled-deletion)
- Audit trail (who performed which actions, when, and consequences)
- Public metadata (optional account attributes)

**What staffdb DOES NOT store** (isolated in other services):
- 2FA secrets (TOTP codes, backup codes) → stored in `2fa` service
- Hardware security key private material → stored in `hsm` service
- OAuth2 tokens or refresh tokens → generated/stored in `oauth2` service
- Session state → managed by caller (OAuth2, admin, etc.)

### Data Flow

```
Client/Service → [staffdb API with key auth] → SQLite/PostgreSQL
                ↓
            Audit log (immutable)
            Service logging (structured to stdout)
```

Each request is:
1. Authenticated with rotating service API key
2. Validated against least-privilege rules (staff vs. public)
3. Processed with immutable audit trail
4. Responded with redacted/encrypted payload (per service-id)

## API Reference (Phase 1+)

### Health & Readiness

```
GET /healthz
  200 OK: {"status": "healthy", "version": "0.1.0", "uptime": 1234}

GET /ready
  200 OK: {"ready": true, "database": "ok", "service": "staffdb"}
```

### Accounts (Phase 4)

```
POST /accounts
  Create new account (staff-only or public based on account_type)

GET /accounts/{user_id}
  Retrieve account details and roles

PATCH /accounts/{user_id}
  Update account fields (selective)

DELETE /accounts/{user_id}
  Soft-delete or disable account

GET /accounts/lookup?email=user@example.com
  Resolve email to account ID (for OAuth2 / admin lookup)

POST /accounts/{user_id}/verify
  Verify credentials (internal only, not exposed publicly)
```

### Roles (Phase 4)

```
POST /accounts/{user_id}/roles
  Grant one or more roles to an account

DELETE /accounts/{user_id}/roles/{role}
  Revoke a role
```

### Audit Trail (Phase 4)

```
GET /audit/accounts/{user_id}
  Retrieve immutable audit log for an account
```

## Local Development

### Prerequisites

- Rust 1.86+ ([install](https://www.rust-lang.org/tools/install))
- SQLite 3 (pre-installed on macOS/Linux; Windows bundles via rustup)

### Quick Start

1. **Clone and navigate:**
   ```bash
   cd staffdb
   ```

2. **Copy environment template:**
   ```bash
   cp .env.example .env.development
   ```

3. **Build:**
   ```bash
   cargo build --release
   ```

4. **Run:**
   ```bash
   cargo run
   # or run the binary directly:
   ./target/release/staffdb
   ```

   The server listens on `http://127.0.0.1:3000` by default.

5. **Verify health:**
   ```bash
   curl http://127.0.0.1:3000/healthz
   ```

### Environment Variables

See [.env.example](.env.example) for all available configuration options. Key ones:

- `STAFFDB_HOST` / `STAFFDB_PORT`: Server bind address
- `DATABASE_URL`: SQLite path or PostgreSQL connection string
- `SERVICE_ID`: Identifier for logging (e.g., `staffdb-dev`, `staffdb-prod`)
- `ENVIRONMENT`: `development`, `staging`, or `production`
- `LOG_LEVEL`: `trace`, `debug`, `info`, `warn`, or `error`
- `SERVICE_API_KEYS`: Comma-separated `service_id:key` credentials for inbound service auth
- `PRIVILEGED_SERVICES`: Comma-separated service IDs allowed to mutate account data

### Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_config_validation
```

### Database Migrations

Migrations are managed via [sqlx](https://github.com/launchbadger/sqlx) and live in `migrations/`.

```bash
# Apply pending migrations (automatic on startup in Phase 2)
sqlx migrate run --database-url sqlite:staffdb.sqlite

# Add a new migration
sqlx migrate add -r my_migration_name
```

## Project Structure

```
staffdb/
├── src/
│   ├── main.rs              # Server entry point, initialization
│   ├── lib.rs               # Public crate interface
│   ├── error.rs             # Error types and HTTP response mapping
│   ├── logger.rs            # Structured logging setup (tracing)
│   ├── config/
│   │   ├── mod.rs           # Config loading from environment
│   │   └── security.rs      # Key rotation and encryption setup (Phase 3)
│   ├── models/
│   │   └── mod.rs           # Account, Role, AuditLog structs (Phase 2+)
│   ├── db/                  # Database layer (Phase 2)
│   ├── api/
│   │   └── (routes and handlers) (Phase 4)
│   └── auth/                # Password hashing, key validation (Phase 3)
├── migrations/              # SQL migration files (Phase 2)
├── tests/                   # Integration and unit tests (Phase 6)
├── Cargo.toml               # Rust project manifest
├── .env.example             # Configuration template
├── .env.development         # Development environment (git-ignored)
└── .gitignore
```

## Development Phases

1. **Phase 1** (COMPLETE ✅): Bootstrap service, health checks, config loading
2. **Phase 2** (COMPLETE ✅): SQLite storage layer, account model, migrations, repository abstraction
3. **Phase 3** (COMPLETE ✅): Security core (Argon2id hashing, service auth, audit log structure)
4. **Phase 4** (COMPLETE ✅): Full REST API for accounts and roles with input validation
5. **Phase 5** (COMPLETE ✅): Hardening (rate limiting, secret redaction in logs, comprehensive tests)
6. **Phase 6**: Testing framework expansion and containerization validation (in progress)

### API Documentation

See [API.md](API.md) for comprehensive endpoint reference, request/response examples, and authentication details.

## Production Deployment

See parent repository deployment guides (coming in `docs/`). Key considerations:

- Set `ENVIRONMENT=production` and `LOG_LEVEL=warn`
- Use PostgreSQL (not SQLite) for multi-instance deployments
- Provision service API keys via HSM; rotate every 24 hours
- Use encrypted connection to database (TLS or Unix socket)
- Enable audit log persistence to central SIEM
- Run behind reverse proxy with rate limiting and TLS termination
- Health check and ready endpoints accessible only from orchestration layer

## Security Considerations

- **No plaintext passwords**: All stored hashes are Argon2id with per-account salt
- **Timing-safe comparisons**: Field validation uses cryptographic comparison to prevent timing attacks
- **Service isolation**: This service cannot read/write 2FA state or HSM material
- **Immutable audit trail**: All mutations recorded; deletes are soft (flagged, not removed)
- **Key rotation**: Service API keys rotated by HSM; old keys rejected immediately
- **Least privilege**: API responses redacted per service ID (e.g., oauth2 doesn't see password hashes)

## Contributing

See parent repository [CONTRIBUTING](../CONTRIBUTING.md) guide. Security-related changes require additional review period.

## License

MIT — See [LICENSE](../LICENSE)