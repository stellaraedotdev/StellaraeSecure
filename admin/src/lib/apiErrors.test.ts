import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import { isForbidden, isUnauthorized, toUserMessage } from './apiErrors'

describe('apiErrors helpers', () => {
  it('recognizes 401 and 403 statuses', () => {
    const unauthorized = new ApiError(401, 'bad auth', 'corr-1')
    const forbidden = new ApiError(403, 'denied', 'corr-2')

    expect(isUnauthorized(unauthorized)).toBe(true)
    expect(isForbidden(unauthorized)).toBe(false)

    expect(isForbidden(forbidden)).toBe(true)
    expect(isUnauthorized(forbidden)).toBe(false)
  })

  it('maps status-specific user messages', () => {
    const unauthorized = new ApiError(401, 'bad auth', 'corr-1')
    const forbidden = new ApiError(403, 'denied', 'corr-2')
    const serverError = new ApiError(500, 'boom', 'corr-3')

    expect(toUserMessage(unauthorized)).toContain('Authentication failed')
    expect(toUserMessage(forbidden)).toContain('Authorization failed')
    expect(toUserMessage(serverError)).toContain('Request failed (500)')
  })

  it('falls back for non-api errors', () => {
    expect(toUserMessage(new Error('plain'))).toBe('plain')
    expect(toUserMessage('unexpected')).toBe('Unexpected error')
  })
})
