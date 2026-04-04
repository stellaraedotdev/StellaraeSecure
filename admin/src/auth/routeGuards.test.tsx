import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import { AuthProvider } from './AuthContext'
import { RequireSessionRoute } from './RequireSessionRoute'
import { RequirePermissionRoute } from './RequirePermissionRoute'

const STORAGE_KEY = 'stellarae.admin.session'

function SessionProtectedApp() {
  return (
    <MemoryRouter initialEntries={['/admin']}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<div>Login View</div>} />
          <Route element={<RequireSessionRoute />}>
            <Route path="/admin" element={<div>Admin Protected View</div>} />
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  )
}

function PermissionProtectedApp() {
  return (
    <MemoryRouter initialEntries={['/panel']}>
      <AuthProvider>
        <Routes>
          <Route element={<RequireSessionRoute />}>
            <Route element={<RequirePermissionRoute requiredPermission="panel.session.issue" />}>
              <Route path="/panel" element={<div>Panel Protected View</div>} />
            </Route>
          </Route>
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('route guards', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
  })

  it('redirects unauthenticated user to login route', () => {
    render(<SessionProtectedApp />)
    expect(screen.getByText('Login View')).toBeInTheDocument()
  })

  it('allows authenticated user through session guard', () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        accountId: 'staff-1',
        permissions: ['oauth.client.read'],
      }),
    )

    render(<SessionProtectedApp />)
    expect(screen.getByText('Admin Protected View')).toBeInTheDocument()
  })

  it('blocks user missing required permission', () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        accountId: 'staff-1',
        permissions: ['oauth.client.read'],
      }),
    )

    render(<PermissionProtectedApp />)
    expect(screen.getByText('Permission Required')).toBeInTheDocument()
    expect(screen.queryByText('Panel Protected View')).not.toBeInTheDocument()
  })

  it('allows user with required permission', () => {
    window.sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        accountId: 'staff-1',
        permissions: ['panel.session.issue'],
      }),
    )

    render(<PermissionProtectedApp />)
    expect(screen.getByText('Panel Protected View')).toBeInTheDocument()
  })
})
