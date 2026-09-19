import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { Loading, ErrorBox, Empty, Badge, PageHeader, Field, Confirm } from '../ui'

const ROLES = ['admin', 'investigator', 'viewer']

export default function UserManagement() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState(null)
  const [error, setError] = useState(null)
  const [formError, setFormError] = useState(null)
  const [createBusy, setCreateBusy] = useState(false)
  const [form, setForm] = useState({ username: '', email: '', password: '', full_name: '', role: 'viewer' })
  const [roleTarget, setRoleTarget] = useState(null)
  const [activeTarget, setActiveTarget] = useState(null)
  const [resetTarget, setResetTarget] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setError(null)
    try {
      setUsers(await api('/admin/users'))
    } catch (err) {
      setError(err)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function createUser(e) {
    e.preventDefault()
    setCreateBusy(true)
    setFormError(null)
    try {
      await api('/admin/users', {
        method: 'POST',
        body: {
          username: form.username,
          email: form.email,
          password: form.password,
          role: form.role,
          full_name: form.full_name || null,
        },
      })
      setForm({ username: '', email: '', password: '', full_name: '', role: 'viewer' })
      await load()
    } catch (err) {
      setFormError(err.message)
    } finally {
      setCreateBusy(false)
    }
  }

  async function patchUser(userId, body) {
    setBusy(true)
    try {
      await api(`/admin/users/${userId}`, { method: 'PATCH', body })
      await load()
    } finally {
      setBusy(false)
    }
  }

  if (error && !users) return <ErrorBox error={error} onRetry={load} />
  if (!users) return <Loading label="LOADING USER REGISTRY" />

  return (
    <>
      <PageHeader title="USER MANAGEMENT" sub="Create accounts, assign roles, activate/deactivate. All actions are enforced server-side." />

      <div className="panel">
        <h2 className="panel-title">CREATE USER</h2>
        {formError && <div className="form-error">REJECTED: {formError}</div>}
        <form onSubmit={createUser}>
          <div className="form-grid">
            <Field label="USERNAME *">
              <input value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} required minLength={3} maxLength={50} />
            </Field>
            <Field label="EMAIL *">
              <input type="email" value={form.email} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} required />
            </Field>
            <Field label="PASSWORD * (8-64 chars)">
              <input type="password" value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} required minLength={8} maxLength={64} />
            </Field>
            <Field label="FULL NAME">
              <input value={form.full_name} onChange={(e) => setForm((f) => ({ ...f, full_name: e.target.value }))} />
            </Field>
            <Field label="ROLE">
              <select value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
                {ROLES.map((r) => <option key={r} value={r}>{r.toUpperCase()}</option>)}
              </select>
            </Field>
          </div>
          <button className="btn btn-primary" style={{ marginTop: 10 }} disabled={createBusy}>
            {createBusy ? 'CREATING...' : 'CREATE USER'}
          </button>
        </form>
      </div>

      <div className="panel">
        <h2 className="panel-title">USER REGISTRY ({users.length})</h2>
        {users.length === 0 ? (
          <Empty title="NO USERS" />
        ) : (
          <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr><th>USERNAME</th><th>EMAIL</th><th>ROLE</th><th>STATUS</th><th>CREATED</th><th>ACTIONS</th></tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = me?.id === u.id
                  return (
                    <tr key={u.id}>
                      <td className="mono">{u.username}{isSelf && <span className="muted"> (you)</span>}</td>
                      <td className="muted">{u.email}</td>
                      <td>
                        <select
                          value={u.role}
                          disabled={busy || (isSelf && u.role === 'admin')}
                          onChange={(e) => setRoleTarget({ user: u, role: e.target.value })}
                        >
                          {ROLES.map((r) => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                        </select>
                      </td>
                      <td><Badge kind={u.is_active ? 'ok' : 'low'}>{u.is_active ? 'ACTIVE' : 'DISABLED'}</Badge></td>
                      <td className="nowrap muted">{new Date(u.created_at).toLocaleDateString()}</td>
                      <td className="nowrap">
                        <button className="btn btn-sm" disabled={busy || isSelf} onClick={() => setActiveTarget(u)}>
                          {u.is_active ? 'DISABLE' : 'ACTIVATE'}
                        </button>{' '}
                        <button className="btn btn-sm" disabled={busy} onClick={() => setResetTarget({ user: u, password: '' })}>
                          RESET PW
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Confirm
        open={Boolean(roleTarget)}
        title="CHANGE ROLE"
        message={`Set role of "${roleTarget?.user.username}" to ${roleTarget?.role.toUpperCase()}? Role changes are recorded in the audit ledger.`}
        busy={busy}
        onCancel={() => setRoleTarget(null)}
        onConfirm={async () => {
          try { await patchUser(roleTarget.user.id, { role: roleTarget.role }) } finally { setRoleTarget(null) }
        }}
      />
      <Confirm
        open={Boolean(activeTarget)}
        danger
        title={activeTarget?.is_active ? 'DISABLE ACCOUNT' : 'ACTIVATE ACCOUNT'}
        message={activeTarget?.is_active
          ? `Disable "${activeTarget?.user.username}"? They will immediately lose access.`
          : `Re-activate "${activeTarget?.user.username}"?`}
        confirmLabel={activeTarget?.is_active ? 'DISABLE' : 'ACTIVATE'}
        busy={busy}
        onCancel={() => setActiveTarget(null)}
        onConfirm={async () => {
          try { await patchUser(activeTarget.id, { is_active: !activeTarget.is_active }) } finally { setActiveTarget(null) }
        }}
      />
      <Confirm
        open={Boolean(resetTarget)}
        danger
        title="RESET PASSWORD"
        confirmLabel="RESET"
        busy={busy}
        onCancel={() => setResetTarget(null)}
        onConfirm={async () => {
          setBusy(true)
          try {
            await api(`/admin/users/${resetTarget.user.id}/reset-password`, {
              method: 'POST',
              body: { new_password: resetTarget.password },
            })
            setResetTarget(null)
          } catch (err) {
            setError(err)
            setResetTarget(null)
          } finally {
            setBusy(false)
          }
        }}
        message={`Set a new password for "${resetTarget?.user.username}". Share it through a secure channel.`}
      >
        {resetTarget && (
          <Field label="NEW PASSWORD (8-64 chars)">
            <input
              type="password"
              value={resetTarget.password}
              minLength={8}
              maxLength={64}
              onChange={(e) => setResetTarget((t) => ({ ...t, password: e.target.value }))}
            />
          </Field>
        )}
      </Confirm>
    </>
  )
}
