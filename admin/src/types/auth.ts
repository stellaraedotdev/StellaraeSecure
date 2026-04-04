export type AppSurface = 'admin' | 'panel'

export type SignedIdentity = {
  adminKey: string
  accountId: string
  identityTimestamp: string
  identitySignature: string
}

export type AuthSession = {
  accountId: string
  permissions: string[]
  panelSessionId?: string
  signedIdentity?: SignedIdentity
}

export type LoginInput = {
  accountId: string
  permissionsCsv: string
  panelSessionId?: string
  signedIdentity?: SignedIdentity
}
