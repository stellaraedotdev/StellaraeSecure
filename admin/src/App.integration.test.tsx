import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { AuthProvider } from './auth/AuthContext'
import { ApiError } from './lib/api'
import { AUTH_HANDOFF_STATE_STORAGE_KEY } from './lib/authFlowState'

const apiMocks = vi.hoisted(() => ({
  getClient: vi.fn(),
  listCollaborators: vi.fn(),
  addCollaborator: vi.fn(),
  removeCollaborator: vi.fn(),
  introspectToken: vi.fn(),
  revokeToken: vi.fn(),
  rotateClientSecret: vi.fn(),
  deleteClient: vi.fn(),
  validatePanelSession: vi.fn(),
  listAdminAuditEvents: vi.fn(),
  issuePanelSession: vi.fn(),
}))

vi.mock('./api/oauth2', () => ({
  getClient: apiMocks.getClient,
  listCollaborators: apiMocks.listCollaborators,
  addCollaborator: apiMocks.addCollaborator,
  removeCollaborator: apiMocks.removeCollaborator,
  introspectToken: apiMocks.introspectToken,
  revokeToken: apiMocks.revokeToken,
  rotateClientSecret: apiMocks.rotateClientSecret,
  deleteClient: apiMocks.deleteClient,
  validatePanelSession: apiMocks.validatePanelSession,
  listAdminAuditEvents: apiMocks.listAdminAuditEvents,
  issuePanelSession: apiMocks.issuePanelSession,
}))

const STORAGE_KEY = 'stellarae.admin.session'

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  )
}

function seedSession(overrides: Record<string, unknown> = {}) {
  window.sessionStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      accountId: 'staff-1',
      permissions: [
        'oauth.client.read',
        'oauth.client.collaborator.manage',
        'oauth.token.introspect',
        'oauth.token.revoke',
        'panel.session.issue',
        'panel.session.verify',
        'panel.audit.read',
      ],
      panelSessionId: 'panel-session-1',
      signedIdentity: {
        adminKey: 'admin-key',
        accountId: 'staff-1',
        identityTimestamp: '1712220000',
        identitySignature: 'deadbeef',
      },
      ...overrides,
    }),
  )
}

describe('admin application integration flows', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    vi.clearAllMocks()
  })

  it('logs out and redirects to login when a panel session validation request returns 401', async () => {
    seedSession()
    apiMocks.validatePanelSession.mockRejectedValue(new ApiError(401, 'expired', 'corr-1'))

    renderApp('/panel')

    fireEvent.click(screen.getByRole('button', { name: 'Validate Current Session' }))

    await waitFor(() => {
      expect(screen.getByText('Staff Sign-In')).toBeInTheDocument()
    })
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull()
  })

  it('hydrates session from auth callback payload and lands on admin surface', async () => {
    const identityTs = Math.floor(Date.now() / 1000)
    window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, 'state-9')
    renderApp(
      `/auth/callback?account_id=staff-9&permissions=oauth.client.read,panel.session.issue&panel_session_id=panel-9&admin_key=admin-9&identity_ts=${identityTs}&identity_sig=sig-9&state=state-9`,
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Admin Surface' })).toBeInTheDocument()
      expect(screen.getByText('staff-9', { selector: '.identity-value' })).toBeInTheDocument()
    })

    const rawSession = window.sessionStorage.getItem(STORAGE_KEY)
    expect(rawSession).not.toBeNull()

    const parsed = JSON.parse(rawSession ?? '{}') as {
      accountId?: string
      panelSessionId?: string
    }
    expect(parsed.accountId).toBe('staff-9')
    expect(parsed.panelSessionId).toBe('panel-9')
  })

  it('shows sign-in failure when callback payload is missing signed identity fields', async () => {
    window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, 'state-10')
    renderApp('/auth/callback?account_id=staff-9&permissions=oauth.client.read&state=state-10')

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign-In Failed' })).toBeInTheDocument()
      expect(screen.getByText(/missing signed identity headers/i)).toBeInTheDocument()
      expect(screen.getByText('Ref: AUTH_CALLBACK_VALIDATION')).toBeInTheDocument()
    })

    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull()
  })

  it('shows sign-in failure when callback payload has malformed encoded session', async () => {
    window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, 'state-11')
    renderApp('/auth/callback?session=not_base64_payload&state=state-11')

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign-In Failed' })).toBeInTheDocument()
      expect(screen.getByText(/missing account identifier/i)).toBeInTheDocument()
    })

    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull()
  })

  it('shows sign-in failure when callback state does not match expected value', async () => {
    const identityTs = Math.floor(Date.now() / 1000)
    window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, 'state-expected')
    renderApp(
      `/auth/callback?account_id=staff-9&permissions=oauth.client.read&admin_key=admin-9&identity_ts=${identityTs}&identity_sig=sig-9&state=state-wrong`,
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign-In Failed' })).toBeInTheDocument()
      expect(screen.getByText(/state mismatch/i)).toBeInTheDocument()
    })
  })

  it('shows sign-in failure when callback identity timestamp is stale', async () => {
    const staleTs = Math.floor(Date.now() / 1000) - 3600
    window.sessionStorage.setItem(AUTH_HANDOFF_STATE_STORAGE_KEY, 'state-12')
    renderApp(
      `/auth/callback?account_id=staff-9&permissions=oauth.client.read&admin_key=admin-9&identity_ts=${staleTs}&identity_sig=sig-9&state=state-12`,
    )

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign-In Failed' })).toBeInTheDocument()
      expect(screen.getByText(/freshness window/i)).toBeInTheDocument()
    })
  })

  it('shows authorization messaging when admin client fetch returns 403', async () => {
    seedSession()
    apiMocks.getClient.mockRejectedValue(new ApiError(403, 'denied', 'corr-2'))

    renderApp('/admin')

    fireEvent.change(screen.getByPlaceholderText('oauth client id'), {
      target: { value: 'client-123' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Fetch Client' }))

    await waitFor(() => {
      expect(
        screen.getByText(/Authorization failed\. Check permissions/i),
      ).toBeInTheDocument()
    })
    expect(window.sessionStorage.getItem(STORAGE_KEY)).not.toBeNull()
  })
})
