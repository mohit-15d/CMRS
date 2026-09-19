import { Navigate, NavLink, Route, Routes, useNavigate } from 'react-router-dom'
import { useAuth } from './auth'
import { Loading } from './ui'

import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import Cases from './pages/Cases'
import CaseDetails from './pages/CaseDetails'
import Evidence from './pages/Evidence'
import EvidenceDetails from './pages/EvidenceDetails'
import AuditLedger from './pages/AuditLedger'
import AnomalyDetection from './pages/AnomalyDetection'
import Alerts from './pages/Alerts'
import Reports from './pages/Reports'
import UserManagement from './pages/UserManagement'
import Security from './pages/Security'

function RequireAuth({ children }) {
  const { user, booting } = useAuth()
  if (booting) return <Loading label="AUTHENTICATING" />
  if (!user) return <Navigate to="/login" replace />
  return children
}

function RequireAdmin({ children }) {
  const { user, booting, isAdmin } = useAuth()
  if (booting) return <Loading label="AUTHENTICATING" />
  if (!user) return <Navigate to="/login" replace />
  if (!isAdmin) return <Navigate to="/" replace />
  return children
}

function Shell({ children }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const admin = user?.role === 'admin'
  const investigator = user?.role === 'investigator'

  async function onLogout() {
    await logout()
    navigate('/login')
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">
          CMRS<small>CHAIN-OF-CUSTODY // SECURE</small>
        </div>
        <nav className="nav">
          <NavLink to="/">DASHBOARD</NavLink>
          <NavLink to="/cases">CASES</NavLink>
          {(investigator || admin) && <NavLink to="/evidence">EVIDENCE</NavLink>}
          {(investigator || admin) && <NavLink to="/reports">REPORTS</NavLink>}
          <NavLink to="/audit">AUDIT LEDGER</NavLink>
          <div className="nav-divider" />
          {admin && (
            <>
              <NavLink to="/anomaly">ANOMALY DETECTION</NavLink>
              <NavLink to="/alerts">ALERTS</NavLink>
              <NavLink to="/users">USER MANAGEMENT</NavLink>
              <NavLink to="/security">SECURITY</NavLink>
            </>
          )}
        </nav>
        <div className="userbox">
          <div className="username">{user?.username}</div>
          <div className="role">[{String(user?.role || '').toUpperCase()}]</div>
          <button type="button" className="btn btn-sm" style={{ marginTop: 8, width: '100%' }} onClick={onLogout}>
            LOGOUT
          </button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/" element={<RequireAuth><Shell><Dashboard /></Shell></RequireAuth>} />
      <Route path="/cases" element={<RequireAuth><Shell><Cases /></Shell></RequireAuth>} />
      <Route path="/cases/:caseId" element={<RequireAuth><Shell><CaseDetails /></Shell></RequireAuth>} />
      <Route path="/reports" element={<RequireAuth><Shell><Reports /></Shell></RequireAuth>} />
      <Route path="/evidence" element={<RequireAuth><Shell><Evidence /></Shell></RequireAuth>} />
      <Route path="/evidence/:evidenceId" element={<RequireAuth><Shell><EvidenceDetails /></Shell></RequireAuth>} />
      <Route path="/audit" element={<RequireAuth><Shell><AuditLedger /></Shell></RequireAuth>} />
      <Route path="/anomaly" element={<RequireAdmin><Shell><AnomalyDetection /></Shell></RequireAdmin>} />
      <Route path="/alerts" element={<RequireAdmin><Shell><Alerts /></Shell></RequireAdmin>} />
      <Route path="/users" element={<RequireAdmin><Shell><UserManagement /></Shell></RequireAdmin>} />
      <Route path="/security" element={<RequireAdmin><Shell><Security /></Shell></RequireAdmin>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
