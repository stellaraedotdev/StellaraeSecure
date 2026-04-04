import type { LoginInput } from '../types/auth'

type ParseAuthHandoffOptions = {
  expectedState?: string | null
  requireState?: boolean
  maxSkewSeconds?: number
  nowEpochSeconds?: number
}

type HandoffResult =
  | {
      ok: true
      loginInput: LoginInput
    }
  | {
      ok: false
      message: string
    }

type SessionPayload = {
  account_id?: string
  accountId?: string
  permissions?: string[] | string
  panel_session_id?: string
  panelSessionId?: string
  admin_key?: string
  adminKey?: string
  identity_ts?: string
  identityTimestamp?: string
  identity_sig?: string
  identitySignature?: string
}

function decodeBase64Url(input: string) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
  return atob(padded)
}

function mergeParamSources(search: string, hash: string) {
  const merged = new URLSearchParams(search)
  const normalizedHash = hash.startsWith('#') ? hash.slice(1) : hash
  const hashParams = new URLSearchParams(normalizedHash)

  for (const [key, value] of hashParams.entries()) {
    if (!merged.has(key)) {
      merged.set(key, value)
    }
  }

  return merged
}

function parsePermissions(input: string | string[] | undefined) {
  if (Array.isArray(input)) {
    return input.map((permission) => permission.trim()).filter(Boolean)
  }
  if (!input) return []
  return input
    .split(/[\s,]+/)
    .map((permission) => permission.trim())
    .filter(Boolean)
}

function readPayloadFromEncodedSession(params: URLSearchParams): SessionPayload | undefined {
  const encoded = params.get('session')
  if (!encoded) return undefined

  try {
    const decoded = decodeBase64Url(encoded)
    return JSON.parse(decoded) as SessionPayload
  } catch {
    return undefined
  }
}

export function parseAuthHandoff(
  search: string,
  hash: string,
  options: ParseAuthHandoffOptions = {},
): HandoffResult {
  const params = mergeParamSources(search, hash)
  const payload = readPayloadFromEncodedSession(params)
  const nowEpochSeconds =
    options.nowEpochSeconds ?? Math.floor(new Date().getTime() / 1000)
  const requireState = options.requireState ?? true

  const accountId =
    params.get('account_id') ??
    params.get('accountId') ??
    payload?.account_id ??
    payload?.accountId

  const permissions = parsePermissions(
    params.get('permissions') ?? params.get('perms') ?? payload?.permissions,
  )

  const panelSessionId =
    params.get('panel_session_id') ??
    params.get('panelSessionId') ??
    payload?.panel_session_id ??
    payload?.panelSessionId ??
    ''

  const adminKey =
    params.get('admin_key') ??
    params.get('adminKey') ??
    payload?.admin_key ??
    payload?.adminKey ??
    ''

  const identityTimestamp =
    params.get('identity_ts') ??
    params.get('identityTimestamp') ??
    payload?.identity_ts ??
    payload?.identityTimestamp ??
    ''

  const identitySignature =
    params.get('identity_sig') ??
    params.get('identitySignature') ??
    payload?.identity_sig ??
    payload?.identitySignature ??
    ''

  const returnedState = params.get('state') ?? ''

  if (!accountId?.trim()) {
    return {
      ok: false,
      message: 'Missing account identifier in auth handoff payload.',
    }
  }

  if (permissions.length === 0) {
    return {
      ok: false,
      message: 'Missing permissions in auth handoff payload.',
    }
  }

  if (!adminKey.trim() || !identityTimestamp.trim() || !identitySignature.trim()) {
    return {
      ok: false,
      message:
        'Missing signed identity headers (admin key, timestamp, signature) in auth handoff payload.',
    }
  }

  if (requireState) {
    if (!options.expectedState?.trim()) {
      return {
        ok: false,
        message: 'Missing expected handoff state in browser session storage.',
      }
    }

    if (!returnedState.trim()) {
      return {
        ok: false,
        message: 'Missing state parameter in auth callback payload.',
      }
    }

    if (returnedState !== options.expectedState) {
      return {
        ok: false,
        message: 'Auth callback state mismatch detected. Restart sign-in flow.',
      }
    }
  }

  const parsedIdentityTimestamp = Number(identityTimestamp)
  if (!Number.isFinite(parsedIdentityTimestamp)) {
    return {
      ok: false,
      message: 'Identity timestamp is invalid in auth callback payload.',
    }
  }

  const skew = Math.abs(nowEpochSeconds - parsedIdentityTimestamp)
  const maxSkewSeconds = Math.max(0, options.maxSkewSeconds ?? 300)
  if (skew > maxSkewSeconds) {
    return {
      ok: false,
      message: 'Auth callback identity timestamp is outside the allowed freshness window.',
    }
  }

  return {
    ok: true,
    loginInput: {
      accountId,
      permissionsCsv: permissions.join(' '),
      panelSessionId,
      signedIdentity: {
        adminKey,
        accountId,
        identityTimestamp,
        identitySignature,
      },
    },
  }
}
