import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'

export default function Register() {
  const { register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', email: '', password: '', full_name: '' })
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }))

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await register({ ...form, full_name: form.full_name || null })
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card panel">
        <div className="logo">CMRS<small>NEW OPERATOR REGISTRATION</small></div>
        {done ? (
          <>
            <p className="notice">Registration complete. Your account is pending administrator activation.</p>
            <Link className="btn" to="/login">GO TO LOGIN</Link>
          </>
        ) : (
          <>
            {error && <div className="form-error">REGISTRATION FAILED: {error}</div>}
            <form onSubmit={onSubmit}>
              <label className="field"><span className="field-label">USERNAME</span>
                <input value={form.username} onChange={set('username')} required minLength={3} maxLength={50} /></label>
              <label className="field"><span className="field-label">EMAIL</span>
                <input type="email" value={form.email} onChange={set('email')} required /></label>
              <label className="field"><span className="field-label">FULL NAME (OPTIONAL)</span>
                <input value={form.full_name} onChange={set('full_name')} /></label>
              <label className="field"><span className="field-label">PASSWORD (8-64 CHARS)</span>
                <input type="password" value={form.password} onChange={set('password')} required minLength={8} maxLength={64} /></label>
              <button className="btn btn-primary" type="submit" disabled={busy}>
                {busy ? 'REGISTERING...' : 'REGISTER'}
              </button>
            </form>
          </>
        )}
        <div className="auth-alt"><Link to="/login">BACK TO LOGIN</Link></div>
      </div>
    </div>
  )
}
