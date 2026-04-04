import { Outlet } from 'react-router-dom'
import { useAuth } from './AuthContext'

type RequirePermissionRouteProps = {
  requiredPermission: string
}

export function RequirePermissionRoute({ requiredPermission }: RequirePermissionRouteProps) {
  const { hasPermission } = useAuth()

  if (!hasPermission(requiredPermission)) {
    return (
      <section className="notice warning">
        <h2>Permission Required</h2>
        <p>
          Missing required permission: <strong>{requiredPermission}</strong>
        </p>
      </section>
    )
  }

  return <Outlet />
}
