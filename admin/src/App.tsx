import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './layout/AppShell'
import { LoginPage } from './pages/LoginPage'
import { AuthCallbackPage } from './pages/AuthCallbackPage'
import { AdminHomePage } from './pages/AdminHomePage'
import { PanelHomePage } from './pages/PanelHomePage'
import { NotFoundPage } from './pages/NotFoundPage'
import { RequireSessionRoute } from './auth/RequireSessionRoute'
import { RequirePermissionRoute } from './auth/RequirePermissionRoute'
import './App.css'

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/auth/callback" element={<AuthCallbackPage />} />
      <Route path="/" element={<Navigate to="/admin" replace />} />
      <Route element={<RequireSessionRoute />}>
        <Route element={<AppShell />}>
          <Route element={<RequirePermissionRoute requiredPermission="oauth.client.read" />}>
            <Route path="/admin" element={<AdminHomePage />} />
          </Route>
          <Route element={<RequirePermissionRoute requiredPermission="panel.session.issue" />}>
            <Route path="/panel" element={<PanelHomePage />} />
          </Route>
        </Route>
      </Route>
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}

export default App
