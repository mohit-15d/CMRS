// CMRS API client - all calls go to the real backend. No mock data anywhere.
const API_BASE = '/api'

export function getToken() {
  return localStorage.getItem('cmrs_token')
}

export function setToken(token) {
  if (token) localStorage.setItem('cmrs_token', token)
  else localStorage.removeItem('cmrs_token')
}

// Safe, user-facing messages per HTTP status. Backend `detail` strings are
// preferred when present; raw stack traces are never exposed (FastAPI does
// not send them, and any unexpected body is reduced to a generic message).
const STATUS_MESSAGES = {
  400: 'The request could not be processed.',
  401: 'Not authenticated. Please log in again.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested record was not found.',
  409: 'Conflict - the record already exists or is in an invalid state.',
  413: 'The file is too large.',
  422: 'Validation failed - check the submitted values.',
  429: 'Too many attempts. Please wait and try again.',
  500: 'Unexpected server error. Please try again.',
  503: 'Service temporarily unavailable.',
}

function formatDetail(detail) {
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    // FastAPI/pydantic 422 bodies: [{loc, msg, type}, ...]
    const msgs = detail
      .map((item) => (item && item.msg ? item.msg : null))
      .filter(Boolean)
    return msgs.length ? msgs.join('; ') : STATUS_MESSAGES[422]
  }
  if (detail && typeof detail === 'object') return JSON.stringify(detail)
  return null
}

async function toError(res) {
  const fallback = STATUS_MESSAGES[res.status] || `Request failed (HTTP ${res.status})`
  let detail = fallback
  try {
    const data = await res.json()
    const parsed = formatDetail(data && data.detail)
    if (parsed) detail = parsed
  } catch {
    /* non-JSON error body - keep the safe fallback */
  }
  const err = new Error(detail)
  err.status = res.status
  if (res.status === 401) {
    // Global session-expiry signal; AuthProvider clears state and the router
    // redirects to /login. The caller still receives the 401 error.
    window.dispatchEvent(new CustomEvent('cmrs:unauthorized'))
  }
  return err
}

export function qs(params) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, value)
    }
  }
  const str = search.toString()
  return str ? `?${str}` : ''
}

export async function api(path, { method = 'GET', body, form } = {}) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  let payload
  if (form) {
    payload = form
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    payload = JSON.stringify(body)
  }
  const res = await fetch(API_BASE + path, { method, headers, body: payload })
  if (!res.ok) throw await toError(res)
  if (res.status === 204) return null
  return res.json()
}

// Download a protected file (e.g. a PDF report) with the auth header attached.
// Backend-provided URLs (e.g. ReportRead.download_url) already include the
// /api prefix, so avoid doubling it.
export function resolveUrl(path) {
  return path.startsWith(API_BASE) ? path : API_BASE + path
}

export async function apiDownload(path, filename) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(resolveUrl(path), { headers })
  if (!res.ok) throw await toError(res)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename || 'download'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
