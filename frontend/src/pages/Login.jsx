import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../auth'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function onSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(username.trim(), password)
      navigate('/')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card panel">
        <div className="logo">CMRS<small>CHAIN-OF-CUSTODY // SECURE ACCESS</small></div>
        {error && <div className="form-error">ACCESS DENIED: {error}</div>}
        <form onSubmit={onSubmit}>
          <label className="field">
            <span className="field-label">USERNAME</span>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
          </label>
          <label className="field">
            <span className="field-label">PASSWORD</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </label>
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
          </button>
        </form>
        <div className="auth-alt">
          No account? <Link to="/register">REGISTER</Link>
        </div>
      </div>
    </div>
  )
}
