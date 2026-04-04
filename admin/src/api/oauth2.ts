import { requestJson } from '../lib/api'
import { appConfig } from '../lib/config'
import type {
  AdminAuditEventsResponse,
  ClientResponse,
  CollaboratorsResponse,
  IntrospectResponse,
  PanelSessionResponse,
  PanelSessionValidationResponse,
} from '../types/oauth2'

export type AdminSignedHeaders = {
  adminKey: string
  accountId: string
  identityTimestamp: string
  identitySignature: string
}

function buildHeaders(input: AdminSignedHeaders) {
  return {
    'x-admin-key': input.adminKey,
    'x-staff-account-id': input.accountId,
    'x-staff-identity-ts': input.identityTimestamp,
    'x-staff-identity-sig': input.identitySignature,
  }
}

function withStepup(
  input: AdminSignedHeaders,
  panelSessionId?: string,
): Record<string, string> {
  const headers = buildHeaders(input)
  if (panelSessionId?.trim()) {
    return {
      ...headers,
      'x-panel-session-id': panelSessionId.trim(),
    }
  }
  return headers
}

export async function issuePanelSession(input: AdminSignedHeaders) {
  return requestJson<PanelSessionResponse>(
    `${appConfig.oauth2BaseUrl}/api/panel/session`,
    {
      method: 'POST',
      headers: buildHeaders(input),
    },
  )
}

export async function validatePanelSession(
  input: AdminSignedHeaders,
  sessionId: string,
) {
  const encoded = encodeURIComponent(sessionId)
  return requestJson<PanelSessionValidationResponse>(
    `${appConfig.oauth2BaseUrl}/api/panel/session/${encoded}`,
    {
      method: 'GET',
      headers: buildHeaders(input),
    },
  )
}

export async function listAdminAuditEvents(input: AdminSignedHeaders) {
  return requestJson<AdminAuditEventsResponse>(
    `${appConfig.oauth2BaseUrl}/api/admin/audit/events`,
    {
      method: 'GET',
      headers: buildHeaders(input),
    },
  )
}

export async function getClient(input: AdminSignedHeaders, clientId: string) {
  const encoded = encodeURIComponent(clientId)
  return requestJson<ClientResponse>(
    `${appConfig.oauth2BaseUrl}/api/admin/clients/${encoded}`,
    {
      method: 'GET',
      headers: buildHeaders(input),
    },
  )
}

export async function listCollaborators(
  input: AdminSignedHeaders,
  clientId: string,
) {
  const encoded = encodeURIComponent(clientId)
  return requestJson<CollaboratorsResponse>(
    `${appConfig.oauth2BaseUrl}/api/admin/clients/${encoded}/collaborators`,
    {
      method: 'GET',
      headers: buildHeaders(input),
    },
  )
}

export async function addCollaborator(
  input: AdminSignedHeaders,
  clientId: string,
  accountId: string,
  panelSessionId: string,
) {
  const encoded = encodeURIComponent(clientId)
  return requestJson<CollaboratorsResponse>(
    `${appConfig.oauth2BaseUrl}/api/admin/clients/${encoded}/collaborators`,
    {
      method: 'POST',
      headers: withStepup(input, panelSessionId),
      body: {
        account_id: accountId,
      },
    },
  )
}

export async function removeCollaborator(
  input: AdminSignedHeaders,
  clientId: string,
  accountId: string,
  panelSessionId: string,
) {
  const encodedClient = encodeURIComponent(clientId)
  const encodedAccount = encodeURIComponent(accountId)
  return requestJson<void>(
    `${appConfig.oauth2BaseUrl}/api/admin/clients/${encodedClient}/collaborators/${encodedAccount}`,
    {
      method: 'DELETE',
      headers: withStepup(input, panelSessionId),
    },
  )
}

export async function introspectToken(input: AdminSignedHeaders, token: string) {
  return requestJson<IntrospectResponse>(
    `${appConfig.oauth2BaseUrl}/api/admin/tokens/introspect`,
    {
      method: 'POST',
      headers: buildHeaders(input),
      body: { token },
    },
  )
}

export async function revokeToken(
  input: AdminSignedHeaders,
  token: string,
  panelSessionId: string,
) {
  return requestJson<void>(`${appConfig.oauth2BaseUrl}/api/admin/tokens/revoke`, {
    method: 'POST',
    headers: withStepup(input, panelSessionId),
    body: { token },
  })
}
