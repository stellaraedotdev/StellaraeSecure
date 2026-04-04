import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '../auth/AuthContext'
import { PanelHomePage } from './PanelHomePage'

const STORAGE_KEY = 'stellarae.admin.session'

const apiMocks = vi.hoisted(() => ({
  validatePanelSession: vi.fn(),
  listAdminAuditEvents: vi.fn(),
}))

vi.mock('../api/oauth2', () => ({
  validatePanelSession: apiMocks.validatePanelSession,
  listAdminAuditEvents: apiMocks.listAdminAuditEvents,
}))

function seedSession() {
  window.sessionStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      accountId: 'staff-1',
      permissions: ['panel.session.issue', 'panel.audit.read', 'panel.ops.read'],
      panelSessionId: 'panel-session-1',
      signedIdentity: {
        adminKey: 'admin-key',
        accountId: 'staff-1',
        identityTimestamp: '1712220000',
        identitySignature: 'deadbeef',
      },
    }),
  )
}

function renderPage() {
  return render(
    <AuthProvider>
      <PanelHomePage />
    </AuthProvider>,
  )
}

describe('PanelHomePage', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    vi.clearAllMocks()
    seedSession()
  })

  it('validates the current panel session and loads audit events', async () => {
    apiMocks.validatePanelSession.mockResolvedValue({ active: true })
    apiMocks.listAdminAuditEvents.mockResolvedValue({
      events: [
        { id: 'evt-1', operation: 'client.update', target_type: 'client', decision: 'allow' },
        { id: 'evt-2', operation: 'token.revoke', target_type: 'token', decision: 'deny' },
      ],
    })

    renderPage()

    fireEvent.click(screen.getByRole('button', { name: 'Validate Current Session' }))
    await waitFor(() => {
      expect(screen.getByText('Active', { selector: 'strong' })).toBeInTheDocument()
    })

    expect(apiMocks.validatePanelSession).toHaveBeenCalledWith(
      expect.any(Object),
      'panel-session-1',
    )

    fireEvent.click(screen.getByRole('button', { name: 'Load Audit Events' }))
    await waitFor(() => {
      expect(screen.getByText('client.update')).toBeInTheDocument()
      expect(screen.getByText('token.revoke')).toBeInTheDocument()
    })

    expect(apiMocks.listAdminAuditEvents).toHaveBeenCalledWith(expect.any(Object))
  })
})