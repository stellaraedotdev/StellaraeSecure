import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider } from '../auth/AuthContext'
import { ApiError } from '../lib/api'
import { AdminHomePage } from './AdminHomePage'

const STORAGE_KEY = 'stellarae.admin.session'

const apiMocks = vi.hoisted(() => ({
  getClient: vi.fn(),
  listCollaborators: vi.fn(),
  addCollaborator: vi.fn(),
  removeCollaborator: vi.fn(),
  introspectToken: vi.fn(),
  revokeToken: vi.fn(),
  rotateClientSecret: vi.fn(),
  deleteClient: vi.fn(),
}))

vi.mock('../api/oauth2', () => ({
  getClient: apiMocks.getClient,
  listCollaborators: apiMocks.listCollaborators,
  addCollaborator: apiMocks.addCollaborator,
  removeCollaborator: apiMocks.removeCollaborator,
  introspectToken: apiMocks.introspectToken,
  revokeToken: apiMocks.revokeToken,
  rotateClientSecret: apiMocks.rotateClientSecret,
  deleteClient: apiMocks.deleteClient,
}))

function seedSession() {
  window.sessionStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      accountId: 'staff-1',
      permissions: [
        'oauth.client.read',
        'oauth.client.collaborator.manage',
        'oauth.token.introspect',
        'oauth.token.revoke',
      ],
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
      <AdminHomePage />
    </AuthProvider>,
  )
}

describe('AdminHomePage', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    vi.clearAllMocks()
    seedSession()
  })

  it('fetches client data and collaborates with step-up session headers', async () => {
    apiMocks.getClient.mockResolvedValue({ client_id: 'client-123', name: 'Portal' })
    apiMocks.listCollaborators.mockResolvedValueOnce({ collaborator_account_ids: ['staff-2'] })
    apiMocks.listCollaborators.mockResolvedValueOnce({ collaborator_account_ids: ['staff-2'] })
    apiMocks.addCollaborator.mockResolvedValue({ collaborator_account_ids: ['staff-2', 'staff-3'] })
    apiMocks.removeCollaborator.mockResolvedValue(undefined)

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('oauth client id'), {
      target: { value: 'client-123' },
    })
    fireEvent.change(screen.getByPlaceholderText('staff account id'), {
      target: { value: 'staff-3' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Fetch Client' }))
    await waitFor(() => {
      expect(screen.getByText('Portal')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'List Collaborators' }))
    await waitFor(() => {
      expect(screen.getByText('Collaborators: 1')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Add Collaborator' }))
    await waitFor(() => {
      expect(apiMocks.addCollaborator).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'staff-1' }),
        'client-123',
        'staff-3',
        'panel-session-1',
      )
      expect(screen.getByText('Collaborators: 2')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Remove Collaborator' }))
    await waitFor(() => {
      expect(screen.getByText('Collaborator removed.')).toBeInTheDocument()
    })

    expect(apiMocks.removeCollaborator).toHaveBeenCalledWith(
      expect.objectContaining({ accountId: 'staff-1' }),
      'client-123',
      'staff-3',
      'panel-session-1',
    )

    expect(apiMocks.getClient).toHaveBeenCalledWith(
      expect.objectContaining({ adminKey: 'admin-key', accountId: 'staff-1' }),
      'client-123',
    )
  })

  it('introspects and revokes tokens with step-up context', async () => {
    apiMocks.introspectToken.mockResolvedValue({ active: true })
    apiMocks.revokeToken.mockResolvedValue(undefined)

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('access or refresh token'), {
      target: { value: 'token-abc' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Introspect Token' }))
    await waitFor(() => {
      expect(screen.getByText('active', { selector: 'strong' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Revoke Token' }))
    await waitFor(() => {
      expect(apiMocks.revokeToken).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'staff-1' }),
        'token-abc',
        'panel-session-1',
      )
      expect(screen.getByText('Token revoked successfully.')).toBeInTheDocument()
    })
  })

  it('shows a guard error when signed identity is missing', async () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        accountId: 'staff-1',
        permissions: ['oauth.client.read'],
        panelSessionId: 'panel-session-1',
      }),
    )

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('oauth client id'), {
      target: { value: 'client-123' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Fetch Client' }))

    await waitFor(() => {
      expect(
        screen.getByText('Signed identity headers are required from login.'),
      ).toBeInTheDocument()
    })
    expect(apiMocks.getClient).not.toHaveBeenCalled()
  })

  it('surfaces authorization messaging when collaborator add is forbidden', async () => {
    apiMocks.addCollaborator.mockRejectedValue(new ApiError(403, 'denied', 'corr-403'))

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('oauth client id'), {
      target: { value: 'client-123' },
    })
    fireEvent.change(screen.getByPlaceholderText('staff account id'), {
      target: { value: 'staff-7' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Add Collaborator' }))

    await waitFor(() => {
      expect(screen.getByText(/Authorization failed\. Check permissions/i)).toBeInTheDocument()
    })
    expect(window.sessionStorage.getItem(STORAGE_KEY)).not.toBeNull()
  })

  it('logs out when token revoke returns unauthorized', async () => {
    apiMocks.revokeToken.mockRejectedValue(new ApiError(401, 'expired', 'corr-401'))

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('access or refresh token'), {
      target: { value: 'token-abc' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Revoke Token' }))

    await waitFor(() => {
      expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull()
    })
  })

  it('rotates client secret and deletes a client with step-up context', async () => {
    apiMocks.rotateClientSecret.mockResolvedValue({
      client_id: 'client-123',
      client_secret: 'new-secret-value',
    })
    apiMocks.deleteClient.mockResolvedValue(undefined)

    renderPage()

    fireEvent.change(screen.getByPlaceholderText('oauth client id'), {
      target: { value: 'client-123' },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Rotate Client Secret' }))
    await waitFor(() => {
      expect(apiMocks.rotateClientSecret).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'staff-1' }),
        'client-123',
        'panel-session-1',
      )
      expect(screen.getByText(/new-secret-value/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Delete Client' }))
    await waitFor(() => {
      expect(apiMocks.deleteClient).toHaveBeenCalledWith(
        expect.objectContaining({ accountId: 'staff-1' }),
        'client-123',
        'panel-session-1',
      )
      expect(screen.getByText('Client deleted successfully.')).toBeInTheDocument()
    })

    expect((screen.getByPlaceholderText('oauth client id') as HTMLInputElement).value).toBe('')
  })
})