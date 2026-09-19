import { useEffect, useState } from 'react'
import { api } from '../api'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field } from '../ui'

export default function AnomalyDetection() {
  const [users, setUsers] = useState(null)
  const [target, setTarget] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [loadError, setLoadError] = useState(null)

  useEffect(() => {
    api('/admin/users')
      .then(setUsers)
      .catch((err) => setLoadError(err))
  }, [])

  async function analyze() {
    if (!target) return
    setBusy(true)
    setError(null)
    try {
      setResult(await api(`/admin/anomaly/users/${target}`, { method: 'POST' }))
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  if (loadError) return <ErrorBox error={loadError} onRetry={() => setLoadError(null)} />
  if (!users) return <Loading label="LOADING OPERATORS" />

  const byUser = new Map(users.map((u) => [u.id, u]))

  return (
    <>
      <PageHeader title="AI ANOMALY DETECTION" sub="Advisory behavioural analysis — NEVER a conclusion of guilt or misconduct" />
      <div className="notice">
        Results are advisory only. Every anomaly requires human review before any action. Anomalous results raise a security alert for admin review.
      </div>
      <div className="panel">
        <h2 className="panel-title">RUN BEHAVIOURAL ANALYSIS</h2>
        <div className="toolbar">
          <Field label="TARGET OPERATOR">
            <select value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="">— SELECT USER —</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.username} ({u.role})</option>
              ))}
            </select>
          </Field>
          <button className="btn btn-primary" onClick={analyze} disabled={busy || !target}>
            {busy ? 'ANALYZING...' : 'ANALYZE'}
          </button>
        </div>
        {error && <div className="form-error">ANALYSIS UNAVAILABLE: {error.message}</div>}
        {result && (
          <>
            <dl className="kv">
              <dt>TARGET</dt><dd>{byUser.get(result.user_id)?.username || result.user_id}</dd>
              <dt>LABEL</dt><dd><Badge kind={result.label === 'ANOMALOUS' ? 'anomalous' : result.label === 'NORMAL' ? 'normal' : 'dismissed'}>{result.label}</Badge></dd>
              <dt>ANOMALY SCORE</dt><dd className="mono">{result.score != null ? result.score.toFixed(4) : '—'}</dd>
              <dt>SAMPLES</dt><dd>{result.sample_count}</dd>
              <dt>EXPLANATION</dt><dd>{result.explanation}</dd>
            </dl>
            <h3 className="panel-title" style={{ marginTop: 14 }}>BEHAVIOURAL FEATURES (LAST 30 DAYS)</h3>
            <div className="table-wrap">
              <table className="grid">
                <thead><tr><th>FEATURE</th><th>VALUE</th></tr></thead>
                <tbody>
                  {Object.entries(result.features).map(([k, v]) => (
                    <tr key={k}><td className="mono">{k}</td><td>{v}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
        {users.length === 0 && <Empty title="NO USERS" />}
      </div>
    </>
  )
}
