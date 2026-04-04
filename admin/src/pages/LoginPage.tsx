import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import { appConfig } from '../lib/config'
import { appendStateToUrl, createAndStoreHandoffState } from '../lib/authFlowState'

export function LoginPage() {
  const { session } = useAuth()

  function startAuthHandoff() {
    if (!appConfig.authHandoffStartUrl) return
    const state = createAndStoreHandoffState()
    const redirectUrl = appendStateToUrl(appConfig.authHandoffStartUrl, state)
    window.location.assign(redirectUrl)
  }

  if (session) {
    return <Navigate to="/admin" replace />
  }

  return (
    <section className="login-card">
      <h2>Staff Sign-In</h2>
      <p>
        Access to this console is initiated by the upstream staff auth handoff. After
        authentication, you will return to <strong>/auth/callback</strong> with your signed
        identity payload.
      </p>

      <div className="form-grid">
        {appConfig.authHandoffStartUrl ? (
          <button
            type="button"
            className="primary-btn inline-btn"
            onClick={startAuthHandoff}
          >
            Continue to Staff Auth
          </button>
        ) : (
          <p className="error-text">
            Missing <strong>VITE_AUTH_HANDOFF_START_URL</strong>. Configure it to enable sign-in.
          </p>
        )}

        {appConfig.allowBootstrapLogin ? (
          <p className="notice warning">
            Bootstrap login is enabled for development mode only. Disable
            <strong> VITE_ALLOW_BOOTSTRAP_LOGIN</strong> in production.
          </p>
        ) : null}
      </div>
    </section>
  )
}
