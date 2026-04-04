import { describe, expect, it } from 'vitest'
import { parseAuthHandoff } from './authHandoff'

function encodeBase64Url(input: string) {
  return btoa(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

describe('parseAuthHandoff', () => {
  it('parses required auth payload from query params', () => {
    const result = parseAuthHandoff(
      '?account_id=staff-1&permissions=oauth.client.read,panel.session.issue&panel_session_id=panel-1&admin_key=key-1&identity_ts=1712000000&identity_sig=sig-1&state=state-1',
      '',
      {
        expectedState: 'state-1',
        nowEpochSeconds: 1712000005,
      },
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.loginInput.accountId).toBe('staff-1')
    expect(result.loginInput.permissionsCsv).toContain('oauth.client.read')
    expect(result.loginInput.panelSessionId).toBe('panel-1')
    expect(result.loginInput.signedIdentity?.adminKey).toBe('key-1')
  })

  it('reads payload values from hash params', () => {
    const result = parseAuthHandoff(
      '',
      '#accountId=staff-2&permissions=oauth.token.revoke%20panel.audit.read&adminKey=key-2&identityTimestamp=1712000001&identitySignature=sig-2&state=state-2',
      {
        expectedState: 'state-2',
        nowEpochSeconds: 1712000010,
      },
    )

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.loginInput.accountId).toBe('staff-2')
    expect(result.loginInput.permissionsCsv).toBe('oauth.token.revoke panel.audit.read')
  })

  it('supports base64url encoded session payload', () => {
    const encoded = encodeBase64Url(
      JSON.stringify({
        account_id: 'staff-3',
        permissions: ['oauth.client.read', 'oauth.token.introspect'],
        panel_session_id: 'panel-3',
        admin_key: 'key-3',
        identity_ts: '1712000002',
        identity_sig: 'sig-3',
      }),
    )

    const result = parseAuthHandoff(`?session=${encoded}&state=state-3`, '', {
      expectedState: 'state-3',
      nowEpochSeconds: 1712000007,
    })

    expect(result.ok).toBe(true)
    if (!result.ok) return

    expect(result.loginInput.accountId).toBe('staff-3')
    expect(result.loginInput.permissionsCsv).toBe('oauth.client.read oauth.token.introspect')
    expect(result.loginInput.panelSessionId).toBe('panel-3')
  })

  it('returns a helpful error when required fields are missing', () => {
    const result = parseAuthHandoff('?account_id=staff-4&state=state-4', '', {
      expectedState: 'state-4',
      nowEpochSeconds: 1712000007,
    })

    expect(result.ok).toBe(false)
    if (result.ok) return

    expect(result.message).toMatch(/missing permissions/i)
  })

  it('fails when callback state is missing or mismatched', () => {
    const missingState = parseAuthHandoff(
      '?account_id=staff-5&permissions=oauth.client.read&admin_key=key-5&identity_ts=1712000000&identity_sig=sig-5',
      '',
      {
        expectedState: 'state-5',
        nowEpochSeconds: 1712000002,
      },
    )

    expect(missingState.ok).toBe(false)
    if (!missingState.ok) {
      expect(missingState.message).toMatch(/missing state/i)
    }

    const mismatch = parseAuthHandoff(
      '?account_id=staff-5&permissions=oauth.client.read&admin_key=key-5&identity_ts=1712000000&identity_sig=sig-5&state=wrong',
      '',
      {
        expectedState: 'state-5',
        nowEpochSeconds: 1712000002,
      },
    )

    expect(mismatch.ok).toBe(false)
    if (!mismatch.ok) {
      expect(mismatch.message).toMatch(/state mismatch/i)
    }
  })

  it('fails stale identity timestamps outside skew window', () => {
    const result = parseAuthHandoff(
      '?account_id=staff-6&permissions=oauth.client.read&admin_key=key-6&identity_ts=1712000000&identity_sig=sig-6&state=state-6',
      '',
      {
        expectedState: 'state-6',
        maxSkewSeconds: 30,
        nowEpochSeconds: 1712000100,
      },
    )

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.message).toMatch(/freshness window/i)
    }
  })
})