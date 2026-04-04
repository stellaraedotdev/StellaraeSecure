import { ApiError } from './api'

export function asApiError(error: unknown): ApiError | null {
  if (error instanceof ApiError) return error
  return null
}

export function isUnauthorized(error: unknown): boolean {
  return asApiError(error)?.status === 401
}

export function isForbidden(error: unknown): boolean {
  return asApiError(error)?.status === 403
}

export function toUserMessage(error: unknown): string {
  const apiError = asApiError(error)
  if (!apiError) {
    if (error instanceof Error) return error.message
    return 'Unexpected error'
  }

  if (apiError.status === 401) {
    return 'Authentication failed. Re-issue identity headers and sign in again.'
  }

  if (apiError.status === 403) {
    return 'Authorization failed. Check permissions and ensure a fresh panel session for high-risk actions.'
  }

  return `Request failed (${apiError.status}). ${apiError.responseText || 'No details returned.'}`
}
