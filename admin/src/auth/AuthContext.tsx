/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react'
import type { AuthSession, LoginInput, SignedIdentity } from '../types/auth'

type AuthContextValue = {
  session: AuthSession | null
  login: (input: LoginInput) => void
  logout: () => void
  hasPermission: (permission: string) => boolean
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

const STORAGE_KEY = 'stellarae.admin.session'
const PERSIST_SENSITIVE_SESSION_FIELDS =
  !import.meta.env.PROD || import.meta.env.VITE_PERSIST_SENSITIVE_SESSION_FIELDS === 'true'

function parsePermissions(permissionsCsv: string): string[] {
  return permissionsCsv
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean)
}

function normalizeSignedIdentity(input?: SignedIdentity): SignedIdentity | undefined {
  if (!input) return undefined
  const normalized: SignedIdentity = {
    adminKey: input.adminKey.trim(),
    accountId: input.accountId.trim(),
    identityTimestamp: input.identityTimestamp.trim(),
    identitySignature: input.identitySignature.trim(),
  }

  if (
    !normalized.adminKey ||
    !normalized.accountId ||
    !normalized.identityTimestamp ||
    !normalized.identitySignature
  ) {
    return undefined
  }

  return normalized
}

function readStoredSession(): AuthSession | null {
  const raw = window.sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as AuthSession
    if (!parsed.accountId) return null
    return {
      accountId: parsed.accountId,
      permissions: Array.isArray(parsed.permissions) ? parsed.permissions : [],
      panelSessionId: PERSIST_SENSITIVE_SESSION_FIELDS ? parsed.panelSessionId : undefined,
      signedIdentity: PERSIST_SENSITIVE_SESSION_FIELDS
        ? normalizeSignedIdentity(parsed.signedIdentity)
        : undefined,
    }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: PropsWithChildren) {
  const [session, setSession] = useState<AuthSession | null>(() => readStoredSession())

  const login = useCallback((input: LoginInput) => {
    const runtimeSession: AuthSession = {
      accountId: input.accountId.trim(),
      permissions: parsePermissions(input.permissionsCsv),
      panelSessionId: input.panelSessionId?.trim() || undefined,
      signedIdentity: normalizeSignedIdentity(input.signedIdentity),
    }

    const storedSession: AuthSession = {
      accountId: runtimeSession.accountId,
      permissions: runtimeSession.permissions,
      panelSessionId: PERSIST_SENSITIVE_SESSION_FIELDS
        ? runtimeSession.panelSessionId
        : undefined,
      signedIdentity: PERSIST_SENSITIVE_SESSION_FIELDS
        ? runtimeSession.signedIdentity
        : undefined,
    }

    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(storedSession))
    setSession(runtimeSession)
  }, [])

  const logout = useCallback(() => {
    window.sessionStorage.removeItem(STORAGE_KEY)
    setSession(null)
  }, [])

  const hasPermission = useCallback(
    (permission: string) => {
      if (!session) return false
      return session.permissions.includes(permission)
    },
    [session],
  )

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      login,
      logout,
      hasPermission,
    }),
    [session, login, logout, hasPermission],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
