import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader } from '../ui'

export default function Dashboard() {
  const { user, isAdmin } = useAuth()
  const [cases, setCases] = useState(null)
  const [error, setError] = useState(null)
  const [openAlerts, setOpenAlerts] = useState(null)

  async function load() {
    setError(null)
    try {
      const list = await api('/cases')
      setCases(list)
      if (isAdmin) {
        try {
          const alerts = await api('/admin/alerts?status=open&limit=200')
          setOpenAlerts(alerts.length)
        } catch {
          setOpenAlerts(null)
        }
      }
    } catch (err) {
      setError(err)
    }
  }

  useEffect(() => {
    load()
  }, [])

  if (error && !cases) return <ErrorBox error={error} onRetry={load} />
  if (!cases) return <Loading label="LOADING OPERATIONS" />

  const open = cases.filter((c) => c.status === 'open').length
  const inProgress = cases.filter((c) => c.status === 'in_progress').length
  const closed = cases.filter((c) => c.status === 'closed').length

  return (
    <>
      <PageHeader
        title="OPERATIONS DASHBOARD"
        sub={`Operator: ${user?.username} // Role: ${String(user?.role).toUpperCase()}`}
      />
      {openAlerts !== null && openAlerts > 0 && (
        <div className="notice">
          <strong style={{ color: 'var(--red-soft)' }}>{openAlerts} OPEN SECURITY ALERT(S)</strong> require admin review —{' '}
          <Link to="/alerts">open alert console</Link>
        </div>
      )}
      <div className="stat-tiles">
        <div className="stat-tile"><div className="stat-value">{cases.length}</div><div className="stat-label">CASES VISIBLE</div></div>
        <div className="stat-tile"><div className="stat-value">{open}</div><div className="stat-label">OPEN</div></div>
        <div className="stat-tile"><div className="stat-value">{inProgress}</div><div className="stat-label">IN PROGRESS</div></div>
        <div className="stat-tile"><div className="stat-value">{closed}</div><div className="stat-label">CLOSED</div></div>
        {isAdmin && (
          <div className="stat-tile"><div className="stat-value">{openAlerts ?? '—'}</div><div className="stat-label">OPEN ALERTS</div></div>
        )}
      </div>
      <div className="panel">
        <h2 className="panel-title">RECENT CASES</h2>
        {cases.length === 0 ? (
          <Empty title="NO CASES VISIBLE" hint={isAdmin ? 'Create a case from the CASES page.' : 'Cases assigned to or created by you will appear here.'} />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>CASE #</th><th>TITLE</th><th>STATUS</th><th>CREATED</th><th></th></tr></thead>
              <tbody>
                {cases.slice(0, 8).map((c) => (
                  <tr key={c.id}>
                    <td className="mono nowrap">{c.case_number}</td>
                    <td>{c.title}</td>
                    <td><Badge kind={c.status}>{c.status}</Badge></td>
                    <td className="nowrap muted">{new Date(c.created_at).toLocaleString()}</td>
                    <td className="nowrap"><Link to={`/cases/${c.id}`}>OPEN →</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
