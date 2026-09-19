import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

export default function AuditLedger() {
  const { isAdmin } = useAuth()
  const [logs, setLogs] = useState(null)
  const [error, setError] = useState(null)
  const [action, setAction] = useState('')
  const [chain, setChain] = useState(null)
  const [chainBusy, setChainBusy] = useState(false)
  const [confirmChain, setConfirmChain] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      setLogs(await api(`/admin/audit-logs${action ? `?action=${action}&limit=100` : '?limit=100'}`))
    } catch (err) {
      setError(err)
    }
  }, [action])

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

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!logs) return <Loading label="READING AUDIT LEDGER" />

  return (
    <>
      <PageHeader
        title="AUDIT LEDGER"
        sub="Chained-hash, tamper-evident record of every security-relevant event"
        actions={isAdmin && <button className="btn btn-primary" onClick={() => setConfirmChain(true)}>VERIFY HASH CHAIN</button>}
      />

      {confirmChain && (
        <Confirm
          open
          title="VERIFY AUDIT HASH CHAIN"
          message="The full ledger will be re-walked and every hash link recomputed and compared. This is read-only and never repairs the ledger."
          confirmLabel="VERIFY"
          busy={chainBusy}
          onCancel={() => setConfirmChain(false)}
          onConfirm={verifyChain}
        />
      )}
      {chain && (
        <div className="notice" style={chain.valid === false || chain.error ? { borderColor: 'var(--red)', color: 'var(--red-soft)' } : undefined}>
          {chain.error
            ? `VERIFICATION FAILED: ${chain.error}`
            : chain.valid
              ? 'AUDIT CHAIN VALID — no tampering detected.'
              : `AUDIT CHAIN INVALID at record ${chain.broken_at_record_id ?? '(unknown)'} — possible tampering.`}
        </div>
      )}

      <div className="toolbar">
        <Field label="FILTER ACTION"><input value={action} onChange={(e) => setAction(e.target.value.toUpperCase())} placeholder="e.g. LOGIN, INTEGRITY_CHECK" /></Field>
      </div>

      <div className="panel">
        {logs.length === 0 ? (
          <Empty title="NO AUDIT EVENTS" />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>TIMESTAMP</th><th>ACTOR</th><th>ACTION</th><th>RESOURCE</th><th>RESULT</th><th>DETAILS</th></tr></thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td className="nowrap muted">{new Date(log.created_at).toLocaleString()}</td>
                    <td>{log.actor_username || '—'}</td>
                    <td><Badge kind="review">{log.action}</Badge></td>
                    <td className="muted">{log.resource_type}{log.resource_id ? `/${String(log.resource_id).slice(0, 8)}…` : ''}</td>
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
