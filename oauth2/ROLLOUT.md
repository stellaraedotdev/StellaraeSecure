# OAuth2 Service Rollout Guide

This guide provides operational procedures for deploying StellaraeSecure OAuth2 with the complete RBAC, permission enforcement, and step-up session infrastructure.

## Deployment Phases

### Phase 1: Pre-Deployment Verification

Before deploying to any environment, ensure:

1. **Staffdb is running and reachable** from the OAuth2 service
   - Test connectivity: `curl http://STAFFDB_BASE_URL/health`
   - Verify RBAC tables exist: `SELECT COUNT(*) FROM rbac_permissions;`
   - Verify permission seeds exist: `SELECT COUNT(*) FROM rbac_permissions WHERE permission_key LIKE 'oauth.%';`

2. **Required environment variables are set**
   ```bash
   # Required variables (no defaults)
   DATABASE_URL=                    # SQLite or PostgreSQL connection string
   OAUTH2_ADMIN_API_KEY=            # Strong randomly-generated key for admin API
   OAUTH2_STAFFDB_API_KEY=          # Shared secret with staffdb service
   OAUTH2_STAFF_IDENTITY_HMAC_SECRET=  # Shared HMAC secret (min 32 bytes of entropy)

   # Recommended overrides for environment
   ENVIRONMENT=production           # development | production
   OAUTH2_PERMISSION_ENFORCEMENT_MODE=observe  # off | observe | enforce
   OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS=300  # 5 minutes default
   ```

3. **OAuth2 tests pass locally**
   ```bash
   cd oauth2
   cargo test
   # Expected result: 22 passed
   ```

### Phase 2: Initial Deployment (Observe Mode)

Deploy to staging with enforcement in **observe mode** to collect baseline permission decision logs without blocking.

#### Deployment Steps

1. **Build and package**
   ```bash
   cargo build --release
   # Or use Docker
   docker build -t oauth2:v0.1.0 .
   ```

2. **Set environment for staging**
   ```bash
   ENVIRONMENT=production
   OAUTH2_PERMISSION_ENFORCEMENT_MODE=observe  # KEY: Observe mode
   OAUTH2_STAFFDB_API_KEY=<staging-secret>
   OAUTH2_ADMIN_API_KEY=<random-admin-key>
   OAUTH2_STAFF_IDENTITY_HMAC_SECRET=<strong-secret-min-32-bytes>
   ```

3. **Initialize database**
   ```bash
   DATABASE_URL=sqlite:/data/oauth2.db cargo run --release
   # Migrations run automatically on startup
   # Check: SELECT COUNT(*) FROM rbac_permissions;
   ```

4. **Smoke tests**
   - Health check: `curl http://oauth2:4000/health`
   - Readiness: `curl http://oauth2:4000/ready`
   - Create a test client: `curl -X POST http://oauth2:4000/api/admin/clients ...`

5. **Monitor audit logs for 24-48 hours**
   - Permission decisions logged but NOT enforced
   - Track decision volume: `SELECT decision, COUNT(*) FROM admin_audit_events GROUP BY decision;`
   - Identify missing permissions: `SELECT * FROM admin_audit_events WHERE decision = 'observe_deny';`

#### Monitoring in Observe Mode

Check audit logs for patterns:
```bash
# Count observe-deny decisions (would-be-denies in enforce mode)
SELECT operation, COUNT(*) as count 
FROM admin_audit_events 
WHERE decision = 'observe_deny' 
GROUP BY operation;

# Identify actors hitting permission boundaries
SELECT actor_account_id, COUNT(*) as denied_count 
FROM admin_audit_events 
WHERE decision = 'observe_deny' 
GROUP BY actor_account_id;
```

If observe-deny decisions relate to system operations (e.g., legitimate admin tasks), seed additional permissions:
- Contact staffdb admin to grant roles with required permissions
- Use staffdb API: `POST /api/roles/:role_id/permissions` to grant permission keys

### Phase 3: Gradual Enforcement Rollout

Once observe-mode logs confirm expected permission boundaries, switch to enforce mode.

#### Enforcement Rollout Strategy

**Option A: All-at-once (recommended for small teams)**
1. Set `OAUTH2_PERMISSION_ENFORCEMENT_MODE=enforce`
2. Restart service
3. High-risk operations now return 403 without valid permissions
4. Mitigate with 24-hour rollback plan

**Option B: Progressive (for large teams)**
1. Start with enforce mode but whitelist specific actors with special header
2. Gradually reduce whitelist as actors gain required permissions
3. Switch to full enforcement after 1 week

#### Production Enforcement Checklist

- [ ] Observe-mode audit logs show expected permission boundaries
- [ ] No `observe_deny` logs for legitimate admin operations
- [ ] Rollback plan documented and tested
- [ ] On-call team briefed on 403 authorization errors
- [ ] Staffdb role-permission mappings verified
- [ ] HMAC secret backed up and rotation plan ready

### Phase 4: Step-Up Session Enforcement

After permission enforcement is stable, enable step-up session validation for high-risk operations.

#### High-Risk Operations Requiring Step-Up

- Token revocation (`oauth.token.revoke`)
- Account/client modification (`oauth.client.collaborator.manage`)
- Secret rotation (`oauth.client.secret.rotate`)
- Client deletion (`oauth.client.delete`)

#### Step-Up Session Deployment

1. **Client-side change**: Add `x-panel-session-id` header to high-risk requests
   - Clients must first call `POST /api/panel/session` to get a fresh session
   - Include session ID: `x-panel-session-id: <session-id>`

2. **Configure freshness window**
   ```bash
   # Default 5 minutes
   OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS=300
   # Adjust based on UX requirements (shorter = more secure, longer = better UX)
   ```

3. **Rollout sequence**
   - Day 1: Deploy with step-up but in observe mode (`observe_allow` decisions)
   - Day 2-3: Monitor audit logs for missing session headers
   - Day 4+: Switch to enforce mode (`deny` if session missing/stale)

#### High-Risk Operation Flow

```
Client                          OAuth2 Service
  |                                |
  +---- POST /api/panel/session --->|
  |                                |
  |<-- session_id, expires_at -----+
  |
  +-- POST /api/admin/tokens/revoke |
  |     x-panel-session-id: ...  -->|
  |                                |
  |                            [validate freshness]
  |<-- 204 No Content --------+  OK or 403 Forbidden
  |
```

### Phase 5: Backup & Recovery

#### Audit Log Backup

Backup admin audit events daily:
```bash
# Export to JSON for long-term storage
SELECT 
  id, actor_account_id, operation, target_type, target_id, 
  decision, correlation_id, timestamp 
FROM admin_audit_events 
WHERE timestamp > datetime('now', '-1 day')
ORDER BY timestamp DESC;

# Archive to versioned S3/GCS bucket
aws s3 cp audit_events_2026-04-04.json s3://backup-oauth2-audit/2026/04/04/
```

#### Emergency Rollback

If enforcement causes critical service impact:

```bash
# Immediate: Switch to observe mode
OAUTH2_PERMISSION_ENFORCEMENT_MODE=observe
# Service restarts and logs decisions without blocking

# Short-term: Seed missing permissions for critical actor
POST /staffdb/api/roles/<role_id>/permissions
{
  "permission_id": "<permission-id>",
  "granted_by": "emergency-recovery"
}

# Long-term: Analyze audit logs to understand the boundary
SELECT operation, COUNT(*) 
FROM admin_audit_events 
WHERE decision IN ('deny', 'observe_deny') 
GROUP BY operation;
```

## Configuration Reference

### Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `ENVIRONMENT` | development | Controls default enforcement mode and logging |
| `OAUTH2_HOST` | 127.0.0.1 | Bind address |
| `OAUTH2_PORT` | 4000 | HTTP port |
| `DATABASE_URL` | (required) | SQLite or PostgreSQL connection |
| `OAUTH2_ISSUER` | https://secure.stellarae.org/oauth2/public | JWT issuer claim |
| `OAUTH2_ADMIN_API_KEY` | (required) | Secret for admin namespace (x-admin-key) |
| `OAUTH2_STAFFDB_BASE_URL` | http://127.0.0.1:3000 | Staffdb service location |
| `OAUTH2_STAFFDB_API_KEY` | (required) | Shared secret with staffdb |
| `OAUTH2_ACCESS_TOKEN_TTL_SECONDS` | 900 | 15 minutes |
| `OAUTH2_REFRESH_TOKEN_TTL_SECONDS` | 2592000 | 30 days |
| `OAUTH2_AUTH_CODE_TTL_SECONDS` | 300 | 5 minutes |
| `OAUTH2_PANEL_SESSION_TTL_SECONDS` | 900 | 15 minutes |
| `OAUTH2_PERMISSION_ENFORCEMENT_MODE` | observe (dev) / enforce (prod) | off / observe / enforce |
| `OAUTH2_STAFF_IDENTITY_HMAC_SECRET` | (required) | Min 32 bytes, shared with clients |
| `OAUTH2_STAFF_IDENTITY_MAX_SKEW_SECONDS` | 120 | Clock skew tolerance |
| `OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS` | 300 | 5 minutes |

### Permission Keys

Core OAuth2 permission keys seeded in staffdb:

```
oauth.client.create                  - Register new client applications
oauth.client.read                    - Read client metadata
oauth.client.secret.rotate           - Rotate client secrets (HIGH-RISK)
oauth.client.delete                  - Delete applications (HIGH-RISK)
oauth.client.collaborator.manage     - Add/remove collaborators (HIGH-RISK)
oauth.token.revoke                   - Revoke tokens (HIGH-RISK)
oauth.token.introspect               - Inspect token details
oauth.staff.authorize                - Authorize staff OAuth flows
panel.audit.read                     - Read admin audit events
panel.session.issue                  - Issue panel sessions
panel.session.verify                 - Validate panel sessions
```

### Signed Identity Headers

All admin requests require:

```
x-admin-key: <OAUTH2_ADMIN_API_KEY>
x-staff-account-id: <account-id>
x-staff-identity-ts: <unix-timestamp>
x-staff-identity-sig: <hmac-sha256-hex>

# HMAC computation:
# base64(hmac_sha256(
#   account_id + ":" + timestamp,
#   OAUTH2_STAFF_IDENTITY_HMAC_SECRET
# )) encoded as lowercase hex
```

## Operational Tasks

### Granting Permissions to a New Admin

1. **Create or update staffdb account**
   ```bash
   POST /staffdb/api/accounts
   { "username": "admin-alice", "email": "alice@example.com", "account_type": "staff" }
   ```

2. **Grant admin role**
   ```bash
   POST /staffdb/api/roles/super_admin/members
   { "account_id": "<account-id>" }
   ```

3. **Override specific operations** (for testing)
   ```bash
   POST /staffdb/api/accounts/<account-id>/permissions
   { "permission_id": "<oauth.token.revoke>", "granted_by": "direct" }
   ```

4. **Verify permissions**
   ```bash
   GET /staffdb/api/accounts/<account-id>/effective-permissions
   ```

### Rotating HMAC Secret

1. **Generate new secret**
   ```bash
   openssl rand -hex 32
   # Output: a1b2c3d4e5f6...
   ```

2. **Deploy with dual-secret support** (future enhancement)
   - Keep old secret in rotation window
   - Accept signatures from both old and new

3. **Update all clients**
   - Notify applications to use new `OAUTH2_STAFF_IDENTITY_HMAC_SECRET`
   - Provide 2-hour rotation window

4. **Monitor for failures**
   - Track 401 Unauthorized in logs
   - Check for signature verification failures

### Analyzing Audit Trails

```sql
-- All decisions for a specific actor
SELECT * FROM admin_audit_events 
WHERE actor_account_id = '<account-id>' 
ORDER BY timestamp DESC LIMIT 20;

-- High-risk operations in past 24 hours
SELECT operation, actor_account_id, COUNT(*) 
FROM admin_audit_events 
WHERE operation IN ('revoke_token', 'add_collaborator', 'remove_collaborator')
  AND timestamp > datetime('now', '-1 day')
GROUP BY operation, actor_account_id;

-- Denied vs allowed decisions
SELECT decision, COUNT(*) 
FROM admin_audit_events 
WHERE timestamp > datetime('now', '-7 days')
GROUP BY decision;

-- Trace request chain with correlation ID
SELECT * FROM admin_audit_events 
WHERE correlation_id = '<trace-id>'
ORDER BY timestamp ASC;
```

## Incident Response

### Access Denied After Enforcement is Enabled

**Symptoms**: 403 responses to previously working API calls

**Root cause analysis**:
1. Check audit logs: `SELECT * FROM admin_audit_events WHERE decision = 'deny' ORDER BY timestamp DESC LIMIT 20;`
2. Identify missing permission: `SELECT DISTINCT permission_key FROM audit_events WHERE decision = 'deny';`
3. Verify staffdb role assignment: `SELECT * FROM staffdb.rbac_account_roles WHERE account_id = '<actor>';`

**Resolution**:
1. **Short-term**: Switch to observe mode or grant specific permission
   ```bash
   POST /staffdb/api/accounts/<account-id>/permissions
   { "permission_id": "<missing-permission>" }
   ```
2. **Long-term**: Review role-permission mappings and adjust for sustainable access patterns

### Stale Step-Up Session Rejection

**Symptoms**: 403 on high-risk operations with valid admin key but old session

**Root cause**: Panel session older than `OAUTH2_STEPUP_SESSION_FRESHNESS_SECONDS`

**Resolution**:
1. Client must call `POST /api/panel/session` for a fresh session
2. Include new session ID in `x-panel-session-id` header
3. Retry high-risk operation

### Admin Key Compromise

**Symptoms**: Unauthorized admin operations in audit logs from unexpected actors

**Resolution**:
1. Rotate `OAUTH2_ADMIN_API_KEY` immediately
   ```bash
   # Generate new key
   openssl rand -base64 32
   ```
2. Revoke all tokens for affected account: `POST /api/admin/tokens/revoke`
3. Review audit logs for malicious operations: `SELECT * FROM admin_audit_events WHERE decision IN ('allow', 'observe_allow') ORDER BY timestamp DESC LIMIT 100;`
4. Restore any modified objects from backup
5. Document incident and post-mortem

## Testing Checklist

- [ ] Unit tests: `cargo test` passes all 22+ tests
- [ ] Authorization matrix: each permission key correctly grants/denies
- [ ] E2E workflow: client registration → collaboration → token revocation
- [ ] Privilege escalation: unprivileged actors cannot execute high-risk ops
- [ ] Step-up gates: high-risk operations fail without fresh session
- [ ] Audit logging: all operations emit correct decision events
- [ ] HMAC verification: invalid signatures rejected
- [ ] Timestamp skew: signatures outside `MAX_SKEW_SECONDS` rejected
- [ ] Correlation IDs: trace requests across service boundaries
- [ ] Load test: 1000 auth requests/sec with permission checks

## Success Criteria

OAuth2 service is production-ready when:

1. ✅ **All 22+ tests pass** with zero warnings
2. ✅ **Permission enforcement is stable** in observe mode (24+ hours)
3. ✅ **No unauthorized access** of legitimate operations in audit logs
4. ✅ **Step-up sessions work end-to-end** with correct freshness validation
5. ✅ **Audit trails are tamper-evident** with correlation IDs
6. ✅ **Rollback plan is tested** and documented
7. ✅ **On-call team is trained** on permission boundaries and incident response
8. ✅ **HMAC secret rotation is practiced** and can be executed in < 1 hour

## Post-Deployment

### Monitoring

Set up alerts for:
- Error rate > 1% (permission denials, HMAC failures)
- Audit log volume anomalies (sudden spike in operations)
- 403 Unauthorized rate > threshold
- Correlation ID drop (tracing failures)

### Regular Maintenance

- **Weekly**: Review `observe_deny` logs to identify edge cases
- **Monthly**: Rotate HMAC secrets and backups
- **Quarterly**: Audit permission mappings for role drift
- **Annually**: Full security review and penetration testing

## References

- [OAuth2 Service README](./README.md)
- [Staffdb RBAC API](../staffdb/README.md)
- [Permission keys and enforcement modes](./README.md#permission-enforcement-rollout)
- [Step-up authentication design](./README.md#step-up-authentication-for-high-risk-operations)
