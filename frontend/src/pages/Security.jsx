import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Confirm } from '../ui'

const SECURITY_ACTIONS = [
  'LOGIN_FAILURE',
  'INTEGRITY_MISMATCH',
  'EVIDENCE_NOT_FOUND',
  'ALERT_CREATED',
  'ALERT_REVIEWED',
  'USER_DISABLED',
  'USER_ROLE_CHANGED',
]

export default function Security() {
  const [logs, setLogs] = useState(null)
  const [alerts, setAlerts] = useState(null)
  const [chain, setChain] = useState(null)
  const [error, setError] = useState(null)
  const [chainBusy, setChainBusy] = useState(false)
  const [confirmChain, setConfirmChain] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      const [alertList, logList] = await Promise.all([
        api('/admin/alerts?status=open&limit=200'),
        api('/admin/audit-logs?limit=200'),
      ])
      setAlerts(alertList)
      setLogs(
        logList.filter(
          (l) => SECURITY_ACTIONS.includes(l.action) || l.result !== 'success'
        )
      )
    } catch (err) {
      setError(err)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function verifyChain() {
    setChainBusy(true)
    try {
      setChain(await api('/admin/audit-ledger/verify', { method: 'POST' }))
    } catch (err) {
      setChain({ error: err.message })
    } finally {
      setChainBusy(false)
      setConfirmChain(false)
    }
  }

  if (error && !alerts) return <ErrorBox error={error} onRetry={load} />
  if (!alerts || !logs) return <Loading label="COMPILING SECURITY POSTURE" />

  const criticalOpen = alerts.filter((a) => a.severity === 'critical').length
  const highOpen = alerts.filter((a) => a.severity === 'high').length

  return (
    <>
      <PageHeader
        title="SECURITY CONSOLE"
        sub="Posture overview, tamper-evidence check and recent security events"
        actions={<button className="btn btn-primary" onClick={() => setConfirmChain(true)}>VERIFY AUDIT HASH CHAIN</button>}
      />

      <Confirm
        open={confirmChain}
        title="VERIFY AUDIT HASH CHAIN"
        message="The full ledger will be re-walked and every hash link recomputed and compared. Read-only; the ledger is never repaired automatically."
        confirmLabel="VERIFY"
        busy={chainBusy}
        onCancel={() => setConfirmChain(false)}
        onConfirm={verifyChain}
      />
      {chain && (
        <div className="notice" style={chain.valid === false || chain.error ? { borderColor: 'var(--red)', color: 'var(--red-soft)' } : undefined}>
          {chain.error
            ? `VERIFICATION FAILED: ${chain.error}`
            : chain.valid
              ? 'AUDIT CHAIN VALID — no tampering detected.'
              : `AUDIT CHAIN INVALID at record ${chain.broken_at_record_id ?? '(unknown)'} — investigate immediately.`}
        </div>
      )}

      <div className="stat-tiles">
        <div className="stat-tile"><div className="stat-value">{alerts.length}</div><div className="stat-label">OPEN ALERTS</div></div>
        <div className="stat-tile"><div className="stat-value">{criticalOpen}</div><div className="stat-label">CRITICAL</div></div>
        <div className="stat-tile"><div className="stat-value">{highOpen}</div><div className="stat-label">HIGH</div></div>
        <div className="stat-tile"><div className="stat-value">{logs.length}</div><div className="stat-label">SECURITY EVENTS (200)</div></div>
      </div>

      {alerts.length > 0 && (
        <div className="notice">
          <strong style={{ color: 'var(--red-soft)' }}>{alerts.length} OPEN SECURITY ALERT(S)</strong> —{' '}
          <Link to="/alerts">open the alert console</Link> to review. Alerts are advisory only; a human decides every outcome.
        </div>
      )}

      <div className="panel">
        <h2 className="panel-title">RECENT SECURITY EVENTS</h2>
        {logs.length === 0 ? (
          <Empty title="NO SECURITY EVENTS RECORDED" hint="Failed logins, integrity mismatches and alert activity will appear here." />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>TIMESTAMP</th><th>ACTOR</th><th>ACTION</th><th>RESULT</th><th>DETAILS</th></tr></thead>
              <tbody>
                {logs.slice(0, 50).map((log) => (
                  <tr key={log.id}>
                    <td className="nowrap muted">{new Date(log.created_at).toLocaleString()}</td>
                    <td>{log.actor_username || '—'}</td>
                    <td><Badge kind={log.result === 'success' ? 'review' : 'violation'}>{log.action}</Badge></td>
                    <td><Badge kind={log.result === 'success' ? 'ok' : 'violation'}>{log.result}</Badge></td>
                    <td className="muted" style={{ maxWidth: 340, wordBreak: 'break-word' }}>{log.details ? JSON.stringify(log.details) : '—'}</td>
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
