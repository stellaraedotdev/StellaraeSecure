import { Link, NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

const navItems = [
  { to: '/admin', label: 'Admin Surface' },
  { to: '/panel', label: 'Panel Surface' },
]

export function AppShell() {
  const { session, logout } = useAuth()

  return (
    <div className="app-frame">
      <header className="topbar">
        <div>
          <p className="eyebrow">StellaraeSecure</p>
          <h1>Operations Console</h1>
        </div>

        <div className="identity-block">
          {session ? (
            <>
              <p className="identity-label">Actor</p>
              <p className="identity-value">{session.accountId}</p>
              <button type="button" onClick={logout} className="ghost-btn">
                Sign Out
              </button>
            </>
          ) : (
            <Link to="/login" className="ghost-btn">
              Sign In
            </Link>
          )}
        </div>
      </header>

      <nav className="primary-nav" aria-label="Primary">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => (isActive ? 'active' : undefined)}
          >
            {item.label}
          </NavLink>
        ))}
      </nav>

      <main className="workspace-panel">
        <Outlet />
      </main>
    </div>
  )
}
