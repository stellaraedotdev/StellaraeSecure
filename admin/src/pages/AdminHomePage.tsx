import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { appConfig } from '../lib/config'
import {
  addCollaborator,
  deleteClient,
  getClient,
  introspectToken,
  listCollaborators,
  removeCollaborator,
  rotateClientSecret,
  revokeToken,
} from '../api/oauth2'
import type {
  ClientResponse,
  CollaboratorsResponse,
  IntrospectResponse,
  RotateClientSecretResponse,
} from '../types/oauth2'
import { isUnauthorized, toUserMessage } from '../lib/apiErrors'
import { useApiAction } from '../hooks/useApiAction'

export function AdminHomePage() {
  const { session, logout } = useAuth()
  const signedIdentity = session?.signedIdentity

  const [clientId, setClientId] = useState('')
  const [tokenValue, setTokenValue] = useState('')
  const [collaboratorAccountId, setCollaboratorAccountId] = useState('')
  const [clientResult, setClientResult] = useState<ClientResponse | null>(null)
  const [collaboratorsResult, setCollaboratorsResult] = useState<CollaboratorsResponse | null>(null)
  const [introspectResult, setIntrospectResult] = useState<IntrospectResponse | null>(null)
  const [revokeStatus, setRevokeStatus] = useState<string | null>(null)
  const [rotateResult, setRotateResult] = useState<RotateClientSecretResponse | null>(null)
  const { busy, error, run, setError } = useApiAction({
    onError: (apiError) => {
      if (isUnauthorized(apiError)) {
        logout()
      }
    },
  })

  async function runWithGuard<T>(fn: () => Promise<T>) {
    if (!signedIdentity) {
      setError('Signed identity headers are required from login.')
      return null
    }

    setRevokeStatus(null)
    return run(fn, toUserMessage)
  }

  async function fetchClient() {
    const result = await runWithGuard(() => getClient(signedIdentity!, clientId))
    if (result) setClientResult(result)
  }

  async function fetchCollaborators() {
    const result = await runWithGuard(() => listCollaborators(signedIdentity!, clientId))
    if (result) setCollaboratorsResult(result)
  }

  async function addClientCollaborator() {
    const stepupSessionId = session?.panelSessionId ?? ''
    const result = await runWithGuard(() =>
      addCollaborator(signedIdentity!, clientId, collaboratorAccountId, stepupSessionId),
    )
    if (result) setCollaboratorsResult(result)
  }

  async function removeClientCollaborator() {
    const stepupSessionId = session?.panelSessionId ?? ''
    const result = await runWithGuard(() =>
      removeCollaborator(signedIdentity!, clientId, collaboratorAccountId, stepupSessionId),
    )
    if (result !== null) {
      const refreshed = await runWithGuard(() => listCollaborators(signedIdentity!, clientId))
      if (refreshed) setCollaboratorsResult(refreshed)
      setRevokeStatus('Collaborator removed.')
    }
  }

  async function runIntrospect() {
    const result = await runWithGuard(() => introspectToken(signedIdentity!, tokenValue))
    if (result) setIntrospectResult(result)
  }

  async function runRevoke() {
    const stepupSessionId = session?.panelSessionId ?? ''
    const result = await runWithGuard(() =>
      revokeToken(signedIdentity!, tokenValue, stepupSessionId),
    )
    if (result !== null) {
      setRevokeStatus('Token revoked successfully.')
    }
  }

  async function runRotateSecret() {
    const stepupSessionId = session?.panelSessionId ?? ''
    const result = await runWithGuard(() =>
      rotateClientSecret(signedIdentity!, clientId, stepupSessionId),
    )
    if (result) {
      setRotateResult(result)
      setRevokeStatus('Client secret rotated successfully.')
    }
  }

  async function runDeleteClient() {
    const stepupSessionId = session?.panelSessionId ?? ''
    const result = await runWithGuard(() =>
      deleteClient(signedIdentity!, clientId, stepupSessionId),
    )
    if (result !== null) {
      setClientResult(null)
      setCollaboratorsResult(null)
      setRotateResult(null)
      setRevokeStatus('Client deleted successfully.')
      setClientId('')
      setCollaboratorAccountId('')
    }
  }

  return (
    <section>
      <h2>Admin Surface</h2>
      <p className="lede">
        Public app lifecycle workspace for owner and collaborator operations.
      </p>

      <article className="surface-card">
          <p className="chip">oauth.client.read / oauth.client.collaborator.manage</p>
          <h3>Client and Collaborator Operations</h3>
          <div className="form-grid">
            <label>
              Client ID
              <input
                value={clientId}
                onChange={(event) => setClientId(event.target.value)}
                placeholder="oauth client id"
              />
            </label>
            <label>
              Collaborator Account ID
              <input
                value={collaboratorAccountId}
                onChange={(event) => setCollaboratorAccountId(event.target.value)}
                placeholder="staff account id"
              />
            </label>
            <div className="button-row">
              <button type="button" className="primary-btn" onClick={() => void fetchClient()} disabled={busy || !clientId.trim()}>
                Fetch Client
              </button>
              <button type="button" className="ghost-btn" onClick={() => void fetchCollaborators()} disabled={busy || !clientId.trim()}>
                List Collaborators
              </button>
              <button
                type="button"
                className="ghost-btn"
                onClick={() => {
                  void addClientCollaborator()
                }}
                disabled={busy || !clientId.trim() || !collaboratorAccountId.trim() || !session?.panelSessionId}
              >
                Add Collaborator
              </button>
              <button
                type="button"
                className="ghost-btn"
                onClick={() => {
                  void removeClientCollaborator()
                }}
                disabled={busy || !clientId.trim() || !collaboratorAccountId.trim() || !session?.panelSessionId}
              >
                Remove Collaborator
              </button>
            </div>
          </div>
      </article>

      <article className="surface-card">
          <p className="chip">oauth.token.introspect / oauth.token.revoke</p>
          <h3>Token Operations</h3>
          <div className="form-grid">
            <label>
              Token
              <input
                value={tokenValue}
                onChange={(event) => setTokenValue(event.target.value)}
                placeholder="access or refresh token"
              />
            </label>
            <div className="button-row">
              <button type="button" className="primary-btn" onClick={() => void runIntrospect()} disabled={busy || !tokenValue.trim()}>
                Introspect Token
              </button>
              <button
                type="button"
                className="ghost-btn"
                onClick={() => {
                  void runRevoke()
                }}
                disabled={busy || !tokenValue.trim() || !session?.panelSessionId}
              >
                Revoke Token
              </button>
            </div>
          </div>
      </article>

      <article className="surface-card">
          <p className="chip">oauth.client.secret.rotate / oauth.client.delete</p>
          <h3>Client Lifecycle Operations</h3>
          <p>High-risk client controls requiring fresh step-up panel sessions.</p>
          <div className="button-row">
            <button
              type="button"
              className="ghost-btn"
              onClick={() => {
                void runRotateSecret()
              }}
              disabled={busy || !clientId.trim() || !session?.panelSessionId}
            >
              Rotate Client Secret
            </button>
            <button
              type="button"
              className="ghost-btn"
              onClick={() => {
                void runDeleteClient()
              }}
              disabled={busy || !clientId.trim() || !session?.panelSessionId}
            >
              Delete Client
            </button>
          </div>
      </article>

      <section className="notice">
        <h3>Current Session Snapshot</h3>
        <p>
          Signed in as <strong>{session?.accountId}</strong>
        </p>
        <p>Permissions loaded: {session?.permissions.length ?? 0}</p>
        <p>OAuth2 API: {appConfig.oauth2BaseUrl}</p>
        <p>Step-up Session ID: {session?.panelSessionId ?? 'Not set'}</p>
        {error ? <p className="error-text">{error}</p> : null}
        {revokeStatus ? <p>{revokeStatus}</p> : null}
        {clientResult ? (
          <p>
            Client: <strong>{clientResult.name}</strong> ({clientResult.client_id})
          </p>
        ) : null}
        {collaboratorsResult ? (
          <p>
            Collaborators: {collaboratorsResult.collaborator_account_ids.length}
          </p>
        ) : null}
        {introspectResult ? (
          <p>
            Introspect: <strong>{introspectResult.active ? 'active' : 'inactive'}</strong>
          </p>
        ) : null}
        {rotateResult ? (
          <p>
            New secret for {rotateResult.client_id}: <strong>{rotateResult.client_secret}</strong>
          </p>
        ) : null}
      </section>
    </section>
  )
}
