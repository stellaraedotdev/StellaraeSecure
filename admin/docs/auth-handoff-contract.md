# Auth Handoff Contract

This document defines the payload and environment requirements for upstream staff auth integrations that redirect into the admin frontend.

## Callback URL

- Target: /auth/callback
- Supported payload channels:
  - Query params
  - Hash params
  - Base64url JSON in session query param

## Required Fields

- account_id or accountId
- permissions (space/comma string or string array)
- state (must match browser session state issued by login page)
- admin_key or adminKey
- identity_ts or identityTimestamp (unix seconds)
- identity_sig or identitySignature

Optional:

- panel_session_id or panelSessionId

## Freshness and Replay Controls

- Identity timestamp freshness is enforced using VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS.
- State verification is enforced when VITE_AUTH_HANDOFF_REQUIRE_STATE is true.
- Production should keep VITE_AUTH_HANDOFF_REQUIRE_STATE=true.
- Callback processing consumes the stored state after first use.
- Production should keep VITE_PERSIST_SENSITIVE_SESSION_FIELDS=false.

## Environment Rollout Checklist

1. Set VITE_AUTH_HANDOFF_START_URL in each environment.
2. Ensure return_to points to the environment-specific /auth/callback URL.
3. Set VITE_AUTH_HANDOFF_REQUIRE_STATE=true.
4. Set VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS (recommended: 300).
5. Confirm upstream signer issues admin_key, identity_ts, and identity_sig.
6. Verify callback failures display Ref: AUTH_CALLBACK_VALIDATION and are logged upstream.

## Verification Steps

1. Successful callback creates session and lands on /admin.
2. Missing or mismatched state fails at callback.
3. Stale identity timestamp fails at callback.
4. 401 admin/panel actions force logout to /login.
5. 403 admin/panel actions keep session and show authorization messaging.
