import { useMemo, useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { appConfig } from '../lib/config'
import { listAdminAuditEvents, validatePanelSession } from '../api/oauth2'
import type {
  AdminAuditEvent,
  PanelSessionValidationResponse,
} from '../types/oauth2'
import { isUnauthorized, toUserMessage } from '../lib/apiErrors'
import { useApiAction } from '../hooks/useApiAction'

const panelCards = [
  {
    title: 'Session Verification',
    description: 'Validate fresh panel sessions before high-risk actions.',
    permission: 'panel.session.issue',
  },
  {
    title: 'Audit Timeline',
    description: 'Trace actor decisions by correlation ID and target resource.',
    permission: 'panel.audit.read',
  },
  {
    title: 'Enforcement Lens',
    description: 'Monitor allow, deny, and observe decisions from policy checks.',
    permission: 'panel.ops.read',
  },
]

export function PanelHomePage() {
  const { session, logout } = useAuth()
  const signedIdentity = session?.signedIdentity
  const [validation, setValidation] = useState<PanelSessionValidationResponse | null>(null)
  const [auditEvents, setAuditEvents] = useState<AdminAuditEvent[]>([])
  const { busy, error, run } = useApiAction({
    onError: (apiError) => {
      if (isUnauthorized(apiError)) {
        logout()
      }
    },
  })

  const hasApiIdentity = useMemo(
    () =>
      Boolean(
        signedIdentity?.adminKey &&
          signedIdentity.accountId &&
          signedIdentity.identityTimestamp &&
          signedIdentity.identitySignature,
      ),
    [signedIdentity],
  )

  async function runValidation() {
    if (!session?.panelSessionId || !signedIdentity) return
    const sessionId = session.panelSessionId
    const result = await run(
      () => validatePanelSession(signedIdentity, sessionId),
      toUserMessage,
    )
    if (result) {
      setValidation(result)
    }
  }

  async function loadAuditEvents() {
    if (!signedIdentity) return
    const result = await run(() => listAdminAuditEvents(signedIdentity), toUserMessage)
    if (result) {
      setAuditEvents(result.events)
    }
  }

  return (
    <section>
      <h2>Panel Surface</h2>
      <p className="lede">
        Internal operations workspace for staff governance and security forensics.
      </p>

      <div className="card-grid">
        {panelCards.map((item) => (
          <article className="surface-card" key={item.title}>
            <p className="chip">{item.permission}</p>
            <h3>{item.title}</h3>
            <p>{item.description}</p>
          </article>
        ))}
      </div>

      <section className="notice">
        <h3>Step-up Context</h3>
        <p>
          Panel Session ID:{' '}
          <strong>{session?.panelSessionId ?? 'Not set in bootstrap yet'}</strong>
        </p>
        <p>staffdb API: {appConfig.staffdbBaseUrl}</p>
        <p>Signed headers ready: {hasApiIdentity ? 'Yes' : 'No'}</p>
        <div className="button-row">
            <button
              type="button"
              className="primary-btn"
              onClick={() => {
                void runValidation()
              }}
              disabled={!session?.panelSessionId || !hasApiIdentity || busy}
            >
              Validate Current Session
            </button>
            <button
              type="button"
              className="ghost-btn"
              onClick={() => {
                void loadAuditEvents()
              }}
              disabled={!hasApiIdentity || busy}
            >
              Load Audit Events
            </button>
        </div>
        {error ? <p className="error-text">{error}</p> : null}
        {validation ? (
          <p>
            Validation: <strong>{validation.active ? 'Active' : 'Inactive'}</strong>
          </p>
        ) : null}
        {auditEvents.length > 0 ? (
          <div className="audit-list">
            <h4>Recent Audit Events</h4>
            <ul>
              {auditEvents.slice(0, 6).map((event) => (
                <li key={event.id}>
                  <strong>{event.operation}</strong> on {event.target_type} ({event.decision})
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>
    </section>
  )
}
