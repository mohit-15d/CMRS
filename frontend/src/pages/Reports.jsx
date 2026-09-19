import { useCallback, useEffect, useState } from 'react'
import { api, apiDownload } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

export default function Reports() {
  const { isAdmin, isInvestigator } = useAuth()
  const [cases, setCases] = useState(null)
  const [caseId, setCaseId] = useState('')
  const [reports, setReports] = useState(null)
  const [error, setError] = useState(null)
  const [actionError, setActionError] = useState(null)
  const [confirmGenerate, setConfirmGenerate] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api('/cases')
      .then((list) => {
        setCases(list)
        if (list.length > 0) setCaseId((id) => id || list[0].id)
      })
      .catch(setError)
  }, [])

  const loadReports = useCallback(async () => {
    if (!caseId) return
    setReports(null)
    setActionError(null)
    try {
      setReports(await api(`/reports/case/${caseId}`))
    } catch (err) {
      setError(err)
    }
  }, [caseId])

  useEffect(() => { loadReports() }, [loadReports])

  async function generate() {
    setBusy(true)
    setActionError(null)
    try {
      await api(`/reports/case/${caseId}`, { method: 'POST' })
      setConfirmGenerate(false)
      await loadReports()
    } catch (err) {
      setActionError(err.message)
      setConfirmGenerate(false)
    } finally {
      setBusy(false)
    }
  }

  if (error && !cases) return <ErrorBox error={error} onRetry={() => window.location.reload()} />
  if (!cases) return <Loading label="LOADING CASES" />

  return (
    <>
      <PageHeader
        title="CUSTODY REPORTS"
        sub="EVIDENCE CHAIN OF CUSTODY TRACKING FORM (PDF) generated from live database records"
        actions={
          isInvestigator || isAdmin ? (
            <button className="btn btn-primary" disabled={!caseId} onClick={() => setConfirmGenerate(true)}>
              GENERATE REPORT
            </button>
          ) : null
        }
      />

      <div className="toolbar">
        <Field label="CASE">
          <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>{c.case_number} — {c.title}</option>
            ))}
          </select>
        </Field>
      </div>

      {actionError && <div className="form-error">REJECTED: {actionError}</div>}

      <Confirm
        open={confirmGenerate}
        title="GENERATE PDF REPORT"
        message="A chain-of-custody tracking form (PDF) will be generated from current database records and a REPORT_GENERATED event written to the audit ledger."
        confirmLabel="GENERATE"
        busy={busy}
        onCancel={() => setConfirmGenerate(false)}
        onConfirm={generate}
      />

      <div className="panel">
        <h2 className="panel-title">GENERATED REPORTS</h2>
        {reports === null ? (
          <Loading label="LISTING REPORTS" />
        ) : reports.length === 0 ? (
          <Empty title="NO REPORTS FOR THIS CASE" hint="Use GENERATE REPORT to produce the custody tracking form PDF." />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>REPORT ID</th><th>STATUS</th><th>GENERATED</th><th>BY</th><th></th></tr></thead>
              <tbody>
                {reports.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.report_identifier}</td>
                    <td><Badge kind={r.status === 'generated' ? 'ok' : 'review'}>{r.status}</Badge></td>
                    <td className="nowrap muted">{new Date(r.generated_at).toLocaleString()}</td>
                    <td>{r.generated_by || '—'}</td>
                    <td className="nowrap">
                      <button className="btn btn-sm" onClick={() => apiDownload(r.download_url, `${r.report_identifier}.pdf`).catch((e) => window.alert(`Download failed: ${e.message}`))}>
                        DOWNLOAD PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <p className="muted" style={{ fontSize: 11 }}>
        PDFs contain case info, evidence descriptions, SHA-256 hashes, integrity status, the full chain of custody and signature blocks. Authorization is enforced by the backend per case.
      </p>
    </>
  )
}
