export type PanelSessionResponse = {
  session_id: string
  account_id: string
  permissions: string[]
  expires_at: string
}

export type PanelSessionValidationResponse = {
  active: boolean
  session_id: string
  account_id: string | null
  permissions: string[] | null
  expires_at: string | null
}

export type AdminAuditEvent = {
  id: string
  actor_account_id: string
  operation: string
  target_type: string
  target_id: string
  decision: string
  correlation_id: string
  timestamp: string
}

export type AdminAuditEventsResponse = {
  events: AdminAuditEvent[]
}

export type ClientResponse = {
  client_id: string
  name: string
  redirect_uris: string[]
  allowed_scopes: string[]
  audience: string
  owner_account_id: string
  collaborator_account_ids: string[]
  created_at: string
}

export type RotateClientSecretResponse = {
  client_id: string
  client_secret: string
}

export type CollaboratorsResponse = {
  client_id: string
  owner_account_id: string
  collaborator_account_ids: string[]
}

export type IntrospectResponse = {
  active: boolean
  client_id: string | null
  sub: string | null
  scope: string | null
  permissions: string[] | null
  exp: number | null
  token_type: string | null
}
