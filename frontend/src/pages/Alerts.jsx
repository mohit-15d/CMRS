import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

const STATUSES = ['open', 'reviewed', 'resolved', 'dismissed']

export default function Alerts() {
  const [alerts, setAlerts] = useState(null)
  const [error, setError] = useState(null)
  const [filters, setFilters] = useState({ status: '', severity: '', alert_type: '' })
  const [review, setReview] = useState(null)
  const [reviewForm, setReviewForm] = useState({ status: 'reviewed', resolution: '' })
  const [reviewBusy, setReviewBusy] = useState(false)
  const [reviewError, setReviewError] = useState(null)
  const [detail, setDetail] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      setAlerts(await api(`/admin/alerts${buildQuery(filters)}`))
    } catch (err) {
      setError(err)
    }
  }, [filters])

  useEffect(() => { load() }, [load])

  function buildQuery(f) {
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(f)) if (v) p.set(k, v)
    const s = p.toString()
    return s ? `?${s}` : ''
  }

  async function submitReview() {
    setReviewBusy(true)
    setReviewError(null)
    try {
      await api(`/admin/alerts/${review.id}/review`, { method: 'PATCH', body: reviewForm })
      setReview(null)
      await load()
    } catch (err) {
      setReviewError(err.message)
    } finally {
      setReviewBusy(false)
    }
  }

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!alerts) return <Loading label="POLLING ALERT CONSOLE" />

  return (
    <>
      <PageHeader title="SECURITY ALERTS" sub="Advisory alerts require human review — the system never takes punitive action automatically" />
      <div className="toolbar">
        <Field label="STATUS">
          <select value={filters.status} onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}>
            <option value="">ALL</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
        </Field>
        <Field label="SEVERITY">
          <select value={filters.severity} onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}>
            <option value="">ALL</option>
            {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
          </select>
        </Field>
        <Field label="TYPE"><input value={filters.alert_type} onChange={(e) => setFilters((f) => ({ ...f, alert_type: e.target.value }))} placeholder="e.g. integrity_mismatch" /></Field>
      </div>

      <div className="panel">
        {alerts.length === 0 ? (
          <Empty title="NO ALERTS" hint="Security events (integrity mismatches, lockouts, anomalies, ledger failures) will appear here." />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>TIMESTAMP</th><th>TYPE</th><th>SEVERITY</th><th>STATUS</th><th>DETAILS</th><th>REVIEWED BY</th><th></th></tr></thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="nowrap muted">{new Date(a.created_at).toLocaleString()}</td>
                    <td className="mono">{a.alert_type}</td>
                    <td><Badge kind={a.severity}>{a.severity}</Badge></td>
                    <td><Badge kind={a.status}>{a.status}</Badge></td>
                    <td style={{ maxWidth: 320, wordBreak: 'break-word' }}>{a.explanation}</td>
                    <td>{a.reviewed_by || '—'}</td>
                    <td className="nowrap">
                      <button className="btn btn-sm" onClick={() => setDetail(a)}>VIEW</button>{' '}
                      <button className="btn btn-sm btn-primary" onClick={() => { setReview(a); setReviewForm({ status: a.status === 'open' ? 'reviewed' : a.status, resolution: a.resolution || '' }); setReviewError(null) }}>
                        REVIEW
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {detail && (
        <Confirm
          open
          title={`ALERT // ${detail.alert_type}`}
          confirmLabel="CLOSE"
          onCancel={() => setDetail(null)}
          onConfirm={() => setDetail(null)}
        >
          <dl className="kv">
            <dt>ALERT ID</dt><dd className="mono">{detail.id}</dd>
            <dt>SEVERITY</dt><dd><Badge kind={detail.severity}>{detail.severity}</Badge></dd>
            <dt>STATUS</dt><dd><Badge kind={detail.status}>{detail.status}</Badge></dd>
            <dt>CREATED</dt><dd>{new Date(detail.created_at).toLocaleString()}</dd>
            <dt>SCORE</dt><dd>{detail.score != null ? detail.score.toFixed(4) : '—'}</dd>
            <dt>CASE</dt><dd className="mono">{detail.case_id || '—'}</dd>
            <dt>EVIDENCE</dt><dd className="mono">{detail.evidence_id || '—'}</dd>
            <dt>USER</dt><dd className="mono">{detail.user_id || '—'}</dd>
            <dt>DESCRIPTION</dt><dd>{detail.explanation}</dd>
            <dt>REVIEWED BY</dt><dd>{detail.reviewed_by || '—'}</dd>
            <dt>REVIEWED AT</dt><dd>{detail.reviewed_at ? new Date(detail.reviewed_at).toLocaleString() : '—'}</dd>
            <dt>RESOLUTION</dt><dd>{detail.resolution || '—'}</dd>
          </dl>
        </Confirm>
      )}

      {review && (
        <Confirm
          open
          title={`REVIEW ALERT // ${review.alert_type}`}
          message="Record your human decision. This action is written to the audit ledger."
          confirmLabel="SUBMIT DECISION"
          busy={reviewBusy}
          onCancel={() => setReview(null)}
          onConfirm={submitReview}
        >
          {reviewError && <div className="form-error">{reviewError}</div>}
          <Field label="DECISION">
            <select value={reviewForm.status} onChange={(e) => setReviewForm((f) => ({ ...f, status: e.target.value }))}>
              {STATUSES.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
            </select>
          </Field>
          <div style={{ marginTop: 10 }}>
            <Field label="RESOLUTION / REMARKS (REQUIRED FOR RESOLVE/DISMISS)">
              <textarea value={reviewForm.resolution} onChange={(e) => setReviewForm((f) => ({ ...f, resolution: e.target.value }))} />
            </Field>
          </div>
        </Confirm>
      )}
    </>
  )
}
