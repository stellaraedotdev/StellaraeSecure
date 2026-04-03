# StellaraeSecure oauth2

The oauth2 service is the dedicated server-side OAuth 2.0 authorization service for StellaraeSecure. It is responsible for issuing and managing OAuth credentials, authorization flows, access tokens, refresh tokens, and token lifecycle policy for StellaraeSecure applications.

## Scope

**Language / implementation:** Rust only.

**Service boundary:** This directory will contain server code only. Client libraries, SDKs, and application-side helpers will live in a separate repository or the shared `lib` area when appropriate.

**Primary responsibilities:**
- OAuth 2.0 authorization flows for StellaraeSecure applications
- Token issuance, validation, refresh, and revocation
- Client registration and application metadata management
- Consent handling and session binding for authenticated users
- Service-to-service integration with `staffdb` for identity lookup and account status
- Optional integration with the 2FA and hardware key systems for step-up authentication

**What this service must not own:**
- Password storage or verification logic
- Staff account lifecycle management
- 2FA secret storage
- Hardware key private material
- Client-side SDKs or browser helpers

## Reference Architecture

This service follows the same overall security model described in the root README:
- Rust-based microservice
- REST API surface
- Structured logging with `tracing`
- Configuration through environment variables
- Database-backed persistence
- Explicit service isolation between identity, 2FA, and OAuth concerns

## Implementation Plan

### Phase 1: Service bootstrap
- Create the Rust crate and project manifest.
- Add configuration loading for host, port, database URL, log level, and environment.
- Add structured logging, health checks, and readiness checks.
- Establish a minimal Axum server with startup and shutdown handling.

### Phase 2: Data model and persistence
- Define the schema for OAuth clients, authorization codes, access tokens, refresh tokens, consent grants, and session records.
- Add database migrations and repository access layers.
- Implement secure token generation, hashing, storage, and expiration rules.
- Add rotation and revocation primitives for issued credentials.

### Phase 3: Authorization flows
- Implement the authorization endpoint and login handoff.
- Implement consent capture and approval persistence.
- Implement token exchange for authorization code flow.
- Implement refresh-token rotation and revocation.
- Add token introspection or verification endpoints if needed by internal services.

### Phase 4: Identity and policy integration
- Integrate with `staffdb` for account lookup, status checks, and application authorization.
- Enforce policy for public vs staff-only OAuth clients.
- Integrate with 2FA and hardware-key flows for step-up authentication when required.
- Add request redaction and audit logging for security-sensitive events.

### Phase 5: Hardening
- Add rate limiting and abuse protections.
- Add stronger validation for redirect URIs, scopes, and client metadata.
- Ensure secrets never appear in logs or error output.
- Add comprehensive tests for happy paths, invalid flows, and security edge cases.

### Phase 6: Operational readiness
- Add deployment notes for production and staging environments.
- Define backup, rotation, and token cleanup policies.
- Document health, metrics, and audit expectations.
- Add container and CI validation once the service skeleton exists.

## Initial API Surface

The exact endpoint set will be finalized during implementation, but the initial server should support:
- Health and readiness endpoints
- Client registration and management endpoints for admins
- Authorization endpoint
- Token endpoint
- Revocation endpoint
- Token inspection or introspection endpoint if required by internal consumers
- User consent and callback handling

## Success Criteria

The oauth2 submodule is ready for integration when:
- It builds cleanly in Rust.
- It runs as a standalone server.
- It can authenticate against `staffdb`.
- It can issue, refresh, and revoke tokens securely.
- It has tests covering the core OAuth flows.
- It does not include client-side code.

## Open Questions

These will be resolved during implementation:
- Whether to support OAuth 2.0 only or a limited OIDC-compatible surface later.
- Whether token persistence uses SQLite first or goes straight to PostgreSQL.
- Whether introspection is required for all internal services or only selected consumers.
- Whether client registration is admin-only or partially self-service.

## Next Step

Create the crate scaffold, define the configuration surface, and wire the first health-check server path in Rust.
