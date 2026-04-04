import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from './AuthContext'

export function RequireSessionRoute() {
  const { session } = useAuth()

  if (!session) {
    return <Navigate to="/login" replace />
  }

  return <Outlet />
}
