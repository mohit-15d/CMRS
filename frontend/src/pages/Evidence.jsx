import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { Loading, ErrorBox, Empty, PageHeader, Field } from '../ui'

export default function Evidence() {
  const [items, setItems] = useState(null)
  const [error, setError] = useState(null)
  const [caseId, setCaseId] = useState('')

  async function load() {
    setError(null)
    try {
      setItems(await api(`/evidence${caseId ? `?case_id=${caseId}` : ''}`))
    } catch (err) {
      setError(err)
    }
  }

  useEffect(() => { load() }, [caseId])

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!items) return <Loading label="INDEXING EVIDENCE VAULT" />

  return (
    <>
      <PageHeader title="EVIDENCE VAULT" sub="All evidence in cases you are authorized to access (encrypted at rest)" />
      <div className="toolbar">
        <Field label="FILTER BY CASE ID (UUID)">
          <input value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="leave empty for all" style={{ minWidth: 280 }} />
        </Field>
      </div>
      <div className="panel">
        {items.length === 0 ? (
          <Empty title="NO EVIDENCE" hint="Upload evidence from a case details page." />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead><tr><th>ITEM #</th><th>FILENAME</th><th>SIZE</th><th>SHA-256</th><th>UPLOADED</th><th></th></tr></thead>
              <tbody>
                {items.map((ev) => (
                  <tr key={ev.id}>
                    <td>{ev.item_number ?? '—'}</td>
                    <td>{ev.original_filename}</td>
                    <td className="nowrap">{ev.file_size != null ? `${(ev.file_size / 1024).toFixed(1)} KB` : '—'}</td>
                    <td className="hash">{ev.original_hash?.sha256_hex ? `${ev.original_hash.sha256_hex.slice(0, 24)}...` : '—'}</td>
                    <td className="nowrap muted">{new Date(ev.created_at).toLocaleString()}</td>
                    <td><Link to={`/evidence/${ev.id}`}>DETAILS →</Link></td>
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
