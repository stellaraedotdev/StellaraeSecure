# StellaraeSecure 2FA Service

Dedicated second-factor service for TOTP and HSK bootstrap lifecycle.

## Purpose

This service is the extraction target for second-factor flows previously implemented in staffdb.

- TOTP enrollment and verification
- HSK challenge and verification
- Consolidated second-factor status lookups for oauth2 policy checks

## Environment Variables

- `TWOFA_HOST` (default: `127.0.0.1`)
- `TWOFA_PORT` (default: `4100`)
- `DATABASE_URL` (default: `sqlite:twofa.sqlite`)
- `SERVICE_ID` (default: `twofa-dev`)
- `LOG_LEVEL` (default: `info`)
- `TWOFA_API_KEY` (required)
- `STAFFDB_BASE_URL` (optional; if set, account existence is validated against staffdb)
- `STAFFDB_API_KEY` (optional; used with STAFFDB_BASE_URL)

## API

- `GET /healthz`
- `GET /ready`
- `GET /api/status/:account_id`
- `POST /api/totp/:account_id/enroll`
- `POST /api/totp/:account_id/verify`
- `POST /api/hsk/:account_id/challenge`
- `POST /api/hsk/:account_id/verify`

All `/api/*` routes require:

`Authorization: Bearer <TWOFA_API_KEY>`

## Run

```bash
cd 2fa
TWOFA_API_KEY=dev-twofa-key cargo run
```
