export const AUTH_HANDOFF_STATE_STORAGE_KEY = 'stellarae.auth.handoff.state'

function randomState() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `state-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

export function createAndStoreHandoffState() {
  const state = randomState()
  window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, state)
  return state
}

export function readExpectedHandoffState() {
  return window.sessionStorage.getItem(AUTH_HANDOFF_STATE_STORAGE_KEY)
}

export function clearHandoffState() {
  window.sessionStorage.removeItem(AUTH_HANDOFF_STATE_STORAGE_KEY)
}

export function appendStateToUrl(inputUrl: string, state: string) {
  const parsed = new URL(inputUrl, window.location.origin)
  parsed.searchParams.set('state', state)
  return parsed.toString()
}