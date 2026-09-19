
import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, apiDownload } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

export default function CaseDetails() {
  const { caseId } = useParams()
  const { user, isAdmin, isInvestigator, isViewer } = useAuth()
  const [data, setData] = useState(null)
  const [reports, setReports] = useState(null)
  const [error, setError] = useState(null)
  const [users, setUsers] = useState(null)
  const [upload, setUpload] = useState(null)
  const [edit, setEdit] = useState(false)
  const [editForm, setEditForm] = useState(null)
  const [editBusy, setEditBusy] = useState(false)
  const [editError, setEditError] = useState(null)
  const [confirmGen, setConfirmGen] = useState(false)
  const [genBusy, setGenBusy] = useState(false)
  const [genMsg, setGenMsg] = useState(null)
  const [sharedViewers, setSharedViewers] = useState(null)
  const [viewerOptions, setViewerOptions] = useState(null)
  const [shareSel, setShareSel] = useState('')
  const [shareBusy, setShareBusy] = useState(false)
  const [shareErr, setShareErr] = useState(null)
  const [revokeTarget, setRevokeTarget] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const c = await api(`/cases/${caseId}`)
      setData(c)
      setEditForm({ title: c.title, description: c.description || '', status: c.status, offense: c.offense || '', victim: c.victim || '', suspect: c.suspect || '', submitting_officer: c.submitting_officer || '', location: c.location || '', assigned_investigator_id: c.assigned_investigator_id || '' })
      if (isAdmin) api('/admin/users').then(setUsers).catch(() => setUsers(null))
      // Evidence + reports are fetched for authenticated users on permitted cases;
      // the backend grants read access to assigned reviewers (any role) and 403s others.
      api(`/evidence?case_id=${caseId}`).then(setUpload).catch(() => setUpload(null))
      api(`/reports/case/${caseId}`).then(setReports).catch(() => setReports([]))
      if (isAdmin || isInvestigator) {
        api(`/cases/${caseId}/viewers`).then(setSharedViewers).catch(() => setSharedViewers(null))
        api('/viewers').then(setViewerOptions).catch(() => setViewerOptions(null))
      }
    } catch (err) {
      setError(err)
    }
  }, [caseId, isAdmin, isInvestigator])

  // eslint-disable-next-line -- load-on-mount fetch; canonical React effect that sets state.
  useEffect(() => { load() }, [load])

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!data || !editForm) return <Loading label="DECRYPTING CASE RECORD" />

  const canManage = isAdmin || isInvestigator
  const assignedToMe = data.assigned_investigator_id === user?.id
  const reader = canManage || assignedToMe || isViewer
  const userName = (id) =>
    (users && users.find((u) => u.id === id)?.username) ||
    (id ? String(id) : 'Not Assigned')
  const set = (key) => (e) => setEditForm((f) => ({ ...f, [key]: e.target.value }))

  async function saveCase() {
    setEditBusy(true)
    setEditError(null)
    try {
      const body = {}
      for (const [k, v] of Object.entries(editForm)) if (v !== '') body[k] = v
      if (!body.description) body.description = null
      await api(`/cases/${caseId}`, { method: 'PATCH', body })
      setEdit(false)
      await load()
    } catch (err) {
      setEditError(err.message)
    } finally {
      setEditBusy(false)
    }
  }

  async function generateReport() {
    setGenBusy(true)
    setGenMsg(null)
    try {
      await api(`/reports/case/${caseId}`, { method: 'POST' })
      setGenMsg('PDF chain-of-custody report generated.')
      setReports(await api(`/reports/case/${caseId}`))
    } catch (err) {
      setGenMsg(`FAILED: ${err.message}`)
    } finally {
      setGenBusy(false)
      setConfirmGen(false)
    }
  }

  async function shareCase() {
    setShareBusy(true)
    setShareErr(null)
    try {
      await api(`/cases/${caseId}/viewers`, { method: 'POST', body: { viewer_id: shareSel } })
      setShareSel('')
      setSharedViewers(await api(`/cases/${caseId}/viewers`))
    } catch (err) {
      setShareErr(err.message)
    } finally {
      setShareBusy(false)
    }
  }

  async function revokeViewer(viewerId) {
    setShareBusy(true)
    setShareErr(null)
    try {
      await api(`/cases/${caseId}/viewers/${viewerId}`, { method: 'DELETE' })
      setSharedViewers(await api(`/cases/${caseId}/viewers`))
    } catch (err) {
      setShareErr(err.message)
    } finally {
      setShareBusy(false)
    }
  }


  return (
    <>
      <PageHeader
        title={`CASE ${data.case_number}`}
        sub={data.title}
        actions={
          <>
            <Badge kind={data.status}>{data.status}</Badge>
            {canManage && <button className="btn" onClick={() => setEdit((v) => !v)}>{edit ? 'CLOSE EDITOR' : 'EDIT CASE'}</button>}
            {canManage && <button className="btn btn-primary" onClick={() => { setGenMsg(null); setConfirmGen(true) }}>GENERATE PDF REPORT</button>}
          </>
        }
      />

      {confirmGen && (
        <Confirm
          open
          title="GENERATE CHAIN-OF-CUSTODY PDF"
          message="A forensic chain-of-custody PDF will be generated from current case, evidence, custody and audit records. This action is recorded in the audit ledger."
          confirmLabel="GENERATE"
          busy={genBusy}
          onCancel={() => setConfirmGen(false)}
          onConfirm={generateReport}
        />
      )}
      {genMsg && <div className="notice">{genMsg}</div>}

      {edit && (
        <div className="panel">
          <h2 className="panel-title">EDIT CASE</h2>
          {editError && <div className="form-error">{editError}</div>}
          <div className="form-grid">
            <Field label="TITLE"><input value={editForm.title} onChange={set('title')} maxLength={200} /></Field>
            <Field label="OFFENSE"><input value={editForm.offense} onChange={set('offense')} /></Field>
            <Field label="VICTIM"><input value={editForm.victim} onChange={set('victim')} /></Field>
            <Field label="SUSPECT"><input value={editForm.suspect} onChange={set('suspect')} /></Field>
            <Field label="SUBMITTING OFFICER"><input value={editForm.submitting_officer} onChange={set('submitting_officer')} /></Field>
            <Field label="LOCATION"><input value={editForm.location} onChange={set('location')} /></Field>
            <Field label="STATUS">
              <select value={editForm.status} onChange={set('status')}>
                <option value="open">OPEN</option>
                <option value="in_progress">IN PROGRESS</option>
                <option value="closed">CLOSED</option>
              </select>
            </Field>
            {isAdmin && (
              <Field label="ASSIGNED USER">
                <select value={editForm.assigned_investigator_id || ''} onChange={set('assigned_investigator_id')}>
                  <option value="">NONE (READ-ONLY REVIEW)</option>
                  {users?.map((u) => (
                    <option key={u.id} value={u.id}>{u.username} — {u.role}{u.full_name ? ` (${u.full_name})` : ''}</option>
                  ))}
                </select>
              </Field>
            )}
          </div>
          <div style={{ marginTop: 12 }}><Field label="DESCRIPTION"><textarea value={editForm.description} onChange={set('description')} /></Field></div>
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={saveCase} disabled={editBusy}>{editBusy ? 'SAVING...' : 'SAVE'}</button>
            <button className="btn" onClick={() => setEdit(false)} disabled={editBusy}>CANCEL</button>
          </div>
        </div>
      )}

      <div className="panel">
        <h2 className="panel-title">CASE INFORMATION</h2>
        <dl className="kv">
          <dt>CASE NUMBER</dt><dd className="mono">{data.case_number}</dd>
          <dt>OFFENSE</dt><dd>{data.offense || 'Not Provided'}</dd>
          <dt>SUBMITTING OFFICER</dt><dd>{data.submitting_officer || 'Not Provided'}</dd>
          <dt>VICTIM</dt><dd>{data.victim || 'Not Provided'}</dd>
          <dt>SUSPECT</dt><dd>{data.suspect || 'Not Provided'}</dd>
          <dt>DATE/TIME SEIZED</dt><dd>{data.seized_at ? new Date(data.seized_at).toLocaleString() : 'Not Provided'}</dd>
          <dt>LOCATION OF SEIZURE</dt><dd>{data.location || 'Not Provided'}</dd>
          <dt>DESCRIPTION</dt><dd>{data.description || 'Not Provided'}</dd>
          <dt>ASSIGNED TO</dt><dd className="mono">{userName(data.assigned_investigator_id)}</dd>
          <dt>CREATED BY</dt><dd className="mono">{userName(data.created_by_id)}</dd>
          <dt>CREATED</dt><dd className="muted">{new Date(data.created_at).toLocaleString()}</dd>
        </dl>
      </div>

      <div className="panel">
        <h2 className="panel-title">EVIDENCE IN THIS CASE</h2>
        {!reader ? (
          <Empty title="ACCESS DENIED" hint="You are not assigned to this case and lack investigator/admin role." />
        ) : upload === null ? (
          <Loading label="LISTING EVIDENCE" />
        ) : upload.length === 0 ? (
          <Empty title="NO EVIDENCE UPLOADED" hint={canManage ? 'Upload evidence below.' : 'No evidence on record.'} />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>ITEM #</th><th>FILENAME</th><th>SIZE</th><th>SHA-256</th><th>UPLOADED</th><th></th></tr></thead>
              <tbody>
                {upload.map((ev) => (
                  <tr key={ev.id}>
                    <td>{ev.item_number}</td>
                    <td>{ev.original_filename}</td>
                    <td className="nowrap">{(ev.file_size / 1024).toFixed(1)} KB</td>
                    <td className="hash">{ev.original_hash?.sha256_hex ? `${ev.original_hash.sha256_hex.slice(0, 24)}...` : '—'}</td>
                    <td className="nowrap muted">{new Date(ev.created_at).toLocaleString()}</td>
                    <td><Link to={`/evidence/${ev.id}`}>DETAILS ?</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {canManage && <EvidenceUploadForm caseId={caseId} onDone={load} />}
      </div>
      {canManage && (
        <div className="panel">
          <h2 className="panel-title">SHARE WITH VIEWER</h2>
          {shareErr && <div className="form-error">{shareErr}</div>}
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
            <Field label="SELECT VIEWER">
              <select value={shareSel} onChange={(e) => setShareSel(e.target.value)}>
                <option value="">SELECT VIEWER</option>
                {(viewerOptions || [])
                  .filter((v) => !(sharedViewers || []).some((s) => s.id === v.id))
                  .map((v) => (
                    <option key={v.id} value={v.id}>{v.username}</option>
                  ))}
              </select>
            </Field>
            <button className="btn btn-primary" disabled={!shareSel || shareBusy} onClick={shareCase}>
              {shareBusy ? 'SHARING...' : 'SHARE CASE'}
            </button>
          </div>
          <h3 className="panel-title" style={{ marginTop: 14 }}>SHARED VIEWERS</h3>
          {sharedViewers === null ? (
            <Loading label="LISTING SHARED VIEWERS" />
          ) : sharedViewers.length === 0 ? (
            <Empty title="NOT SHARED" hint="This case is not shared with any viewer yet." />
          ) : (
            <div className="table-wrap">
              <table className="grid">
                <thead><tr><th>VIEWER</th><th></th></tr></thead>
                <tbody>
                  {sharedViewers.map((v) => (
                    <tr key={v.id}>
                      <td>{v.username}</td>
                      <td className="nowrap">
                        <button className="btn btn-sm" disabled={shareBusy} onClick={() => setRevokeTarget(v)}>REVOKE</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      <Confirm
        open={Boolean(revokeTarget)}
        danger
        title="REVOKE VIEWER ACCESS"
        message={`Revoke read access for "${revokeTarget?.username}"? They will immediately lose access to this case.`}
        confirmLabel="REVOKE"
        busy={shareBusy}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={async () => {
          const target = revokeTarget
          setRevokeTarget(null)
          await revokeViewer(target.id)
        }}
      />
      {reader && (
        <div className="panel">
          <h2 className="panel-title">CHAIN-OF-CUSTODY REPORTS</h2>
          {reports === null ? (
            <Loading label="LISTING REPORTS" />
          ) : reports.length === 0 ? (
            <Empty title="NO REPORTS GENERATED" hint={canManage ? 'Use GENERATE PDF REPORT above.' : 'No reports available.'} />
          ) : (
            <div className="table-wrap">
              <table className="grid">
                <thead><tr><th>REPORT ID</th><th>GENERATED</th><th>BY</th><th></th></tr></thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.id}>
                      <td className="mono">{r.report_identifier}</td>
                      <td className="nowrap muted">{new Date(r.generated_at).toLocaleString()}</td>
                      <td>{r.generated_by || '—'}</td>
                      <td>
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
      )}
    </>
  )
}

function EvidenceUploadForm({ caseId, onDone }) {
  const [file, setFile] = useState(null)
  const [itemNumber, setItemNumber] = useState('')
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [ok, setOk] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (!file) return
    setBusy(true)
    setErr(null)
    setOk(false)
    try {
      const form = new FormData()
      form.append('case_id', caseId)
      form.append('file', file)
      if (itemNumber) form.append('item_number', itemNumber)
      if (description) form.append('description', description)
      await api('/evidence/upload', { method: 'POST', form })
      setFile(null)
      setItemNumber('')
      setDescription('')
      setOk(true)
      onDone()
    } catch (error) {
      setErr(error.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} style={{ marginTop: 14 }}>
      <h3 className="panel-title">UPLOAD EVIDENCE (HASHED + AES-256-GCM ENCRYPTED)</h3>
      {err && <div className="form-error">UPLOAD FAILED: {err}</div>}
      {ok && <div className="notice">Evidence uploaded, hashed and encrypted.</div>}
      <div className="form-grid">
        <Field label="FILE (MAX 25 MB)"><input type="file" onChange={(e) => setFile(e.target.files[0])} /></Field>
        <Field label="ITEM #"><input value={itemNumber} onChange={(e) => setItemNumber(e.target.value)} /></Field>
        <Field label="DESCRIPTION"><input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      </div>
      <button className="btn btn-primary" style={{ marginTop: 10 }} disabled={busy || !file}>
        {busy ? 'ENCRYPTING...' : 'UPLOAD EVIDENCE'}
      </button>
    </form>
  )
}
