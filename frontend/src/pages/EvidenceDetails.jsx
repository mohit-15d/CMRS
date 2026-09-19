import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

const ACTIONS = ['transferred', 'received', 'examined', 'returned', 'stored', 'final_disposition']

export default function EvidenceDetails() {
  const { evidenceId } = useParams()
  const { user, isAdmin, isInvestigator } = useAuth()
  const [ev, setEv] = useState(null)
  const [custody, setCustody] = useState(null)
  const [error, setError] = useState(null)
  const [confirmVerify, setConfirmVerify] = useState(false)
  const [verifyBusy, setVerifyBusy] = useState(false)
  const [verifyResult, setVerifyResult] = useState(null)
  const [custForm, setCustForm] = useState({ received_by_id: '', action: 'transferred', comments: '', location: '' })
  const [custBusy, setCustBusy] = useState(false)
  const [custError, setCustError] = useState(null)
  const [custMsg, setCustMsg] = useState(null)
  const [custodians, setCustodians] = useState(null)
  const [custodiansError, setCustodiansError] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      setEv(await api(`/evidence/${evidenceId}`))
      setCustody(await api(`/evidence/${evidenceId}/custody`))
      // Eligible custodians for the "Received By" dropdown: active
      // investigators/admins only - the same set the backend accepts on submit.
      if (isAdmin || isInvestigator) {
        api('/custody/recipients')
          .then((list) => { setCustodians(list); setCustodiansError(false) })
          .catch(() => setCustodiansError(true))
      }
    } catch (err) {
      setError(err)
    }
  }, [evidenceId, isAdmin, isInvestigator])

  // eslint-disable-next-line -- load-on-mount fetch; canonical React effect that sets state.
  useEffect(() => { load() }, [load])

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!ev) return <Loading label="OPENING EVIDENCE RECORD" />

  const canOperate = isAdmin || isInvestigator
  const orig = ev.original_hash
  const latest = ev.latest_verification

  async function verify() {
    setVerifyBusy(true)
    try {
      setVerifyResult(await api(`/evidence/verify/${evidenceId}`, { method: 'POST' }))
      await load()
    } catch (err) {
      setVerifyResult({ error: err.message })
    } finally {
      setVerifyBusy(false)
      setConfirmVerify(false)
    }
  }

  async function addCustody(e) {
    e.preventDefault()
    setCustBusy(true)
    setCustError(null)
    setCustMsg(null)
    try {
      await api(`/evidence/${evidenceId}/custody`, {
        method: 'POST',
        body: {
          received_by_id: custForm.received_by_id,
          action: custForm.action,
          comments: custForm.comments || null,
          location: custForm.location || null,
        },
      })
      setCustMsg('Custody event appended successfully.')
      setCustForm((f) => ({ ...f, comments: '', location: '' }))
      await load()
    } catch (err) {
      setCustError(err.message)
    } finally {
      setCustBusy(false)
    }
  }

  return (
    <>
      <PageHeader
        title={`EVIDENCE // ${ev.original_filename}`}
        sub={`Item #${ev.item_number ?? '—'} // Case: ${ev.case_id}`}
        actions={canOperate && <button className="btn btn-primary" onClick={() => { setVerifyResult(null); setConfirmVerify(true) }}>RUN INTEGRITY VERIFICATION</button>}
      />

      {confirmVerify && (
        <Confirm
          open
          title="INTEGRITY VERIFICATION"
          message="The stored evidence will be decrypted, re-hashed with SHA-256 and compared to its original hash. This action is recorded in the audit ledger."
          confirmLabel="VERIFY NOW"
          busy={verifyBusy}
          onCancel={() => setConfirmVerify(false)}
          onConfirm={verify}
        />
      )}
      {verifyResult && (
        <div className={`notice`} style={verifyResult.match === false ? { borderColor: 'var(--red)', color: 'var(--red-soft)' } : undefined}>
          {verifyResult.error
            ? `VERIFICATION FAILED: ${verifyResult.error}`
            : verifyResult.match
              ? `INTEGRITY VERIFIED — SHA-256 matches at ${new Date(verifyResult.verified_at).toLocaleString()}`
              : 'INTEGRITY VIOLATION — stored evidence does NOT match its original hash. Admin review required.'}
        </div>
      )}

      <div className="panel">
        <h2 className="panel-title">EVIDENCE METADATA</h2>
        <dl className="kv">
          <dt>EVIDENCE ID</dt><dd className="mono">{ev.id}</dd>
          <dt>FILENAME</dt><dd>{ev.original_filename}</dd>
          <dt>SIZE</dt><dd>{ev.file_size != null ? `${ev.file_size} bytes` : 'Not Provided'}</dd>
          <dt>ITEM #</dt><dd>{ev.item_number ?? 'Not Provided'}</dd>
          <dt>DESCRIPTION</dt><dd>{ev.description || 'Not Provided'}</dd>
          <dt>UPLOADED BY</dt><dd>{ev.uploaded_by || '—'}</dd>
          <dt>UPLOADED</dt><dd className="muted">{new Date(ev.created_at).toLocaleString()}</dd>
        </dl>
      </div>

      <div className="panel">
        <h2 className="panel-title">CMRS DIGITAL EVIDENCE INFORMATION</h2>
        <dl className="kv">
          <dt>SHA-256 (ORIGINAL)</dt><dd className="hash">{orig?.sha256_hex || 'Not Provided'}</dd>
          <dt>ALGORITHM</dt><dd>{orig?.algorithm || 'SHA-256'}</dd>
          <dt>ENCRYPTION</dt><dd><Badge kind="verified">AES-256-GCM (AT REST)</Badge></dd>
          <dt>INTEGRITY STATUS</dt>
          <dd>
            {latest ? (
              <Badge kind={latest.match_result ? 'verified' : 'violation'}>
                {latest.match_result ? 'VERIFIED' : 'MISMATCH'}
              </Badge>
            ) : (
              <Badge kind="dismissed">NOT VERIFIED</Badge>
            )}
          </dd>
          {latest && (
            <>
              <dt>LAST VERIFIED</dt><dd className="muted">{latest.verified_at ? new Date(latest.verified_at).toLocaleString() : '—'}</dd>
              <dt>VERIFICATION HASH</dt><dd className="hash">{latest.sha256_hex}</dd>
            </>
          )}
        </dl>
      </div>

      <div className="panel">
        <h2 className="panel-title">CHAIN OF CUSTODY (CHRONOLOGICAL)</h2>
        {custody === null ? (
          <Loading label="READING CUSTODY CHAIN" />
        ) : custody.length === 0 ? (
          <Empty title="NO CUSTODY EVENTS" />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>#</th><th>DATE/TIME</th><th>ACTION</th><th>RELEASED BY</th><th>RECEIVED BY</th><th>COMMENTS/LOCATION</th></tr></thead>
              <tbody>
                {custody.map((c, i) => (
                  <tr key={c.id}>
                    <td>{i + 1}</td>
                    <td className="nowrap">{new Date(c.transferred_at).toLocaleString()}</td>
                    <td><Badge kind="review">{c.action}</Badge></td>
                    <td>{c.released_by || '—'}</td>
                    <td>{c.received_by}</td>
                    <td className="muted">{[c.comments, c.location].filter(Boolean).join(' // ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {canOperate && (
          <form onSubmit={addCustody} style={{ marginTop: 14 }}>
            <h3 className="panel-title">APPEND CUSTODY EVENT (IMMUTABLE)</h3>
            {custError && <div className="form-error">REJECTED: {custError}</div>}
            {custMsg && <div className="notice">{custMsg}</div>}
            <div className="form-grid">
              <Field label="RECEIVED BY *">
                {custodiansError ? (
                  <div className="form-error">Unable to load eligible custodians.</div>
                ) : custodians === null ? (
                  <div className="muted" style={{ fontSize: 12 }}>Loading eligible custodians...</div>
                ) : custodians.length === 0 ? (
                  <div className="muted">No eligible investigators available.</div>
                ) : (
                  <select
                    value={custForm.received_by_id}
                    onChange={(e) => setCustForm((f) => ({ ...f, received_by_id: e.target.value }))}
                    required
                  >
                    <option value="">Select Investigator</option>
                    {custodians.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.username} — {u.role === 'admin' ? 'Admin' : 'Investigator'}
                      </option>
                    ))}
                  </select>
                )}
              </Field>
              <Field label="ACTION">
                <select value={custForm.action} onChange={(e) => setCustForm((f) => ({ ...f, action: e.target.value }))}>
                  {ACTIONS.map((a) => <option key={a} value={a}>{a.toUpperCase()}</option>)}
                </select>
              </Field>
              <Field label="LOCATION"><input value={custForm.location} onChange={(e) => setCustForm((f) => ({ ...f, location: e.target.value }))} /></Field>
            </div>
            <div style={{ marginTop: 10 }}>
              <Field label="COMMENTS"><textarea value={custForm.comments} onChange={(e) => setCustForm((f) => ({ ...f, comments: e.target.value }))} /></Field>
            </div>
            <button
              className="btn btn-primary"
              style={{ marginTop: 10 }}
              disabled={custBusy || !custForm.received_by_id || custodiansError || custodians === null || custodians.length === 0}
            >
              {custBusy ? 'APPENDING...' : 'APPEND CUSTODY EVENT'}
            </button>
            <p className="muted" style={{ marginTop: 8, fontSize: 11 }}>
              Signed in as {user?.username}. Custody history cannot be edited or deleted; every append is audited.
            </p>
          </form>
        )}
      </div>
      <div style={{ marginBottom: 8 }}><Link to="/cases">← BACK TO CASES</Link></div>
    </>
  )
}
