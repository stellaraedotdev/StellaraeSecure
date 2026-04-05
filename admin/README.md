# StellaraeSecure Admin Frontend

This workspace contains the new frontend implementation for two route namespaces:

- `/admin` for OAuth client lifecycle operations
- `/panel` for internal staff operations and security oversight

## Current Implementation Slice

- React + TypeScript + Vite workspace scaffolded in `admin/`
- Auth callback handoff flow via `/auth/callback`
- API-backed panel session issuance from `/api/panel/session`
- Panel session validation and audit event fetch actions on `/panel`
- API-backed admin actions on `/admin` for client lookup, collaborator management, token introspection, and token revocation
- Route-level session and permission guards for `/admin` and `/panel`
- Centralized API error handling for auth/permission failures (401/403)
- Vitest + Testing Library test harness with route-guard and page action coverage
- Playwright smoke tests for `/admin` and `/panel` critical paths
- Shared shell with `/admin` and `/panel` navigation
- Environment-based backend URL configuration

## Local Development

1. Install dependencies:

```bash
npm install
```

2. Create a local env file:

```bash
cp .env.example .env
```

3. Run the app:

```bash
npm run dev
```

## Scripts

- `npm run dev` starts Vite dev server
- `npm run typecheck` runs TypeScript checks
- `npm run lint` runs ESLint
- `npm run test` runs Vitest in watch mode
- `npm run test:run` runs tests once for CI/local verification
- `npm run test:e2e` runs Playwright smoke tests
- `npm run build` creates production build output

## Containerization

The admin frontend now includes a Dockerfile and nginx runtime configuration.

### Build locally

```bash
docker build -t stellarae-admin:local .
```

### Run locally

```bash
docker run --rm -p 8080:80 stellarae-admin:local
```

For full stack testing with backend services, use the root compose stack:

```bash
docker compose --env-file ../.env.compose -f ../docker-compose.yml up -d --build
```

## Auth Handoff

- `/login` is now an entry point that redirects users to upstream staff auth.
- Upstream auth must return to `/auth/callback` with signed payload fields in either
	query params, hash params, or a base64url `session` payload.
- Full deployment contract and rollout checklist: `docs/auth-handoff-contract.md`.
- Required payload data:
	- `account_id` / `accountId`
	- `permissions` (space/comma separated or array)
	- `state` (must match session-stored handoff state)
	- `admin_key` / `adminKey`
	- `identity_ts` / `identityTimestamp`
	- `identity_sig` / `identitySignature`
- Optional: `panel_session_id` / `panelSessionId`
- Callback payloads are rejected when identity timestamp exceeds
	`VITE_AUTH_HANDOFF_MAX_SKEW_SECONDS` (default 300s).
- Callback state is single-use and consumed during callback processing.
- Callback failures surface `Ref: AUTH_CALLBACK_VALIDATION` in UI for incident triage.

## Notes

- Primary sign-in is now callback-driven auth handoff.
- `VITE_ALLOW_BOOTSTRAP_LOGIN=true` only enables a development warning banner and should remain disabled in production.
- `VITE_AUTH_HANDOFF_REQUIRE_STATE=true` should remain enabled in production.
- `VITE_PERSIST_SENSITIVE_SESSION_FIELDS=false` is recommended for production so
	signed identity headers and step-up session IDs are not persisted across reloads.
- API-issued panel sessions require signed headers: `x-admin-key`, `x-staff-account-id`, `x-staff-identity-ts`, `x-staff-identity-sig`.
- High-risk admin actions require a fresh panel session id (`x-panel-session-id`) and will fail if the session is missing or stale.
- Client lifecycle operations now include `client delete` and `secret rotate`, both enforced as high-risk step-up actions.
