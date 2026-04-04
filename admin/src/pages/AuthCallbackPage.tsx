import { useEffect, useRef } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { parseAuthHandoff } from '../lib/authHandoff'
import { clearHandoffState, readExpectedHandoffState } from '../lib/authFlowState'
import { appConfig } from '../lib/config'

export function AuthCallbackPage() {
  const { session, login } = useAuth()
  const location = useLocation()
  const hasProcessedRef = useRef(false)
  const result = parseAuthHandoff(location.search, location.hash, {
    expectedState: readExpectedHandoffState(),
    requireState: appConfig.authHandoffRequireState,
    maxSkewSeconds: appConfig.authHandoffMaxSkewSeconds,
  })

  useEffect(() => {
    if (hasProcessedRef.current) return

    hasProcessedRef.current = true
    clearHandoffState()

    if (!result.ok) return
    login(result.loginInput)
  }, [result, login])

  if (session) {
    return <Navigate to="/admin" replace />
  }

  if (!result.ok) {
    return (
      <section className="login-card">
        <h2>Sign-In Failed</h2>
        <p className="error-text">{result.message}</p>
        <p className="identity-label">Ref: AUTH_CALLBACK_VALIDATION</p>
        <p>
          Return to <Link to="/login">login</Link> and restart the auth handoff.
        </p>
      </section>
    )
  }

  return (
    <section className="login-card">
      <h2>Completing Sign-In</h2>
      <p>Finalizing session and loading your console permissions.</p>
    </section>
  )
}