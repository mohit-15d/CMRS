import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

const EMPTY = { case_number: '', title: '', description: '', offense: '', victim: '', suspect: '', submitting_officer: '', location: '', status: 'open' }

export default function Cases() {
  const { isAdmin, isInvestigator } = useAuth()
  const canCreate = isAdmin || isInvestigator
  const [cases, setCases] = useState(null)
  const [error, setError] = useState(null)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState(EMPTY)
  const [formError, setFormError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')

  async function load() {
    setError(null)
    try {
      setCases(await api(`/cases${statusFilter ? `?status=${statusFilter}` : ''}`))
    } catch (err) {
      setError(err)
    }
  }

  useEffect(() => { load() }, [statusFilter])

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }))

  async function createCase() {
    setBusy(true)
    setFormError(null)
    try {
      await api('/cases', { method: 'POST', body: form })
      setForm(EMPTY)
      setShowForm(false)
      await load()
    } catch (err) {
      setFormError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (error && !cases) return <ErrorBox error={error} onRetry={load} />
  if (!cases) return <Loading label="SCANNING CASE FILES" />

  return (
    <>
      <PageHeader
        title="CASE FILES"
        sub="All cases you are authorized to see"
        actions={canCreate && <button className="btn btn-primary" onClick={() => setShowForm((s) => !s)}>{showForm ? 'CLOSE FORM' : '+ NEW CASE'}</button>}
      />
      <div className="toolbar">
        <Field label="FILTER STATUS">
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">ALL</option>
            <option value="open">OPEN</option>
            <option value="in_progress">IN PROGRESS</option>
            <option value="closed">CLOSED</option>
          </select>
        </Field>
      </div>

      {canCreate && showForm && (
        <div className="panel">
          <h2 className="panel-title">REGISTER NEW CASE</h2>
          {formError && <div className="form-error">{formError}</div>}
          <div className="form-grid">
            <Field label="CASE NUMBER *"><input value={form.case_number} onChange={set('case_number')} maxLength={50} /></Field>
            <Field label="TITLE *"><input value={form.title} onChange={set('title')} maxLength={200} /></Field>
            <Field label="OFFENSE"><input value={form.offense} onChange={set('offense')} /></Field>
            <Field label="VICTIM"><input value={form.victim} onChange={set('victim')} /></Field>
            <Field label="SUSPECT"><input value={form.suspect} onChange={set('suspect')} /></Field>
            <Field label="SUBMITTING OFFICER"><input value={form.submitting_officer} onChange={set('submitting_officer')} /></Field>
            <Field label="LOCATION OF SEIZURE"><input value={form.location} onChange={set('location')} /></Field>
            <Field label="STATUS">
              <select value={form.status} onChange={set('status')}>
                <option value="open">OPEN</option>
                <option value="in_progress">IN PROGRESS</option>
                <option value="closed">CLOSED</option>
              </select>
            </Field>
          </div>
          <div style={{ marginTop: 12 }}>
            <Field label="DESCRIPTION"><textarea value={form.description} onChange={set('description')} /></Field>
          </div>
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={createCase} disabled={busy || !form.case_number || !form.title}>
              {busy ? 'CREATING...' : 'CREATE CASE'}
            </button>
            <button className="btn" onClick={() => setShowForm(false)} disabled={busy}>CANCEL</button>
          </div>
        </div>
      )}

      <div className="panel">
        {cases.length === 0 ? (
          <Empty title="NO CASES" hint={canCreate ? 'Use + NEW CASE to register the first case.' : 'No cases are visible to your role yet.'} />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>CASE #</th><th>TITLE</th><th>OFFENSE</th><th>STATUS</th><th>CREATED</th><th></th></tr></thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id}>
                    <td className="mono nowrap">{c.case_number}</td>
                    <td>{c.title}</td>
                    <td className="muted">{c.offense || '—'}</td>
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
      <Confirm open={false} />
    </>
  )
}
