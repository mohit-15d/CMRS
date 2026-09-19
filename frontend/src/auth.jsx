import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from 'react'
import { api, getToken, setToken } from './api'

const AuthCtx = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [booting, setBooting] = useState(Boolean(getToken()))

  useEffect(() => {
    if (!getToken()) return undefined
    let alive = true
    api('/auth/me')
      .then((me) => alive && setUser(me))
      .catch(() => alive && setToken(null))
      .finally(() => alive && setBooting(false))
    return () => {
      alive = false
    }
  }, [])

  const login = useCallback(async (username, password) => {
    const data = await api('/auth/login', {
      method: 'POST',
      body: { username, password },
    })
    setToken(data.access_token)
    localStorage.setItem('cmrs_expires_at', String(Date.now() + data.expires_in * 1000))
    const me = await api('/auth/me')
    setUser(me)
    return me
  }, [])

  const register = useCallback(
    (payload) => api('/auth/register', { method: 'POST', body: payload }),
    []
  )

  const logout = useCallback(async () => {
    try {
      await api('/auth/logout', { method: 'POST' })
    } catch {
      /* token may already be invalid - clear locally regardless */
    }
    setToken(null)
    localStorage.removeItem('cmrs_expires_at')
    setUser(null)
  }, [])

  useEffect(() => {
    // Session expiry / revocation anywhere in the app -> drop local state.
    // The API client dispatches this on any 401 response.
    const onUnauthorized = () => {
      setToken(null)
      localStorage.removeItem('cmrs_expires_at')
      setUser(null)
    }
    window.addEventListener('cmrs:unauthorized', onUnauthorized)
    return () => window.removeEventListener('cmrs:unauthorized', onUnauthorized)
  }, [])

  const value = {
    user,
    booting,
    login,
    register,
    logout,
    isAdmin: user?.role === 'admin',
    isInvestigator: user?.role === 'investigator',
    isViewer: user?.role === 'viewer',
  }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export function useAuth() {
  return useContext(AuthCtx)
}
