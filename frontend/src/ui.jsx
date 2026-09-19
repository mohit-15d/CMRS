// Shared UI primitives: loading / error / empty states + confirm modal.
import { useEffect } from 'react'

export function Loading({ label = 'LOADING' }) {
  return (
    <div className="state state-loading" role="status">
      <span className="blink">▮</span> {label}...
    </div>
  )
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="state state-error" role="alert">
      <div className="state-title">⚠ ERROR</div>
      <div className="state-body">{String(error.message || error)}</div>
      {onRetry && (
        <button type="button" className="btn" onClick={onRetry}>
          RETRY
        </button>
      )}
    </div>
  )
}

export function Empty({ title = 'NO RECORDS', hint }) {
  return (
    <div className="state state-empty">
      <div className="state-title">◌ {title}</div>
      {hint && <div className="state-body">{hint}</div>}
    </div>
  )
}

export function Badge({ kind, children }) {
  return <span className={`badge badge-${kind}`}>{children}</span>
}

export function PageHeader({ title, sub, actions }) {
  return (
    <header className="page-header">
      <div>
        <h1 className="glitch" data-text={title}>
          {title}
        </h1>
        {sub && <p className="page-sub">{sub}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  )
}

export function Confirm({
  open,
  title = 'CONFIRM ACTION',
  message,
  confirmLabel = 'CONFIRM',
  danger = false,
  busy = false,
  children,
  onCancel,
  onConfirm,
}) {
  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, busy, onCancel])

  if (!open) return null
  return (
    <div className="modal-backdrop" onClick={() => !busy && onCancel()}>
      <div
        className="modal panel"
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="modal-title">{title}</h3>
        {message && <p className="modal-message">{message}</p>}
        {children}
        <div className="modal-actions">
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>
            CANCEL
          </button>
          <button
            type="button"
            className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? 'WORKING...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

export function Field({ label, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
    </label>
  )
}
