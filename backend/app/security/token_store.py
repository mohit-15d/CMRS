"""In-process JWT revocation store (deny-list).

When a user logs out, their access token's ``jti`` is added here so the
current-user dependency rejects it even though the token itself has not
expired.

This is a per-process store. In a multi-worker / horizontally-scaled
deployment a shared store (e.g. Redis or a database table) would be required
for revocation to be consistent across workers; CMRS is single-process for
now, which is documented here and in PROJECT_STATE.md.
"""

import threading
import time


class TokenStore:
    """Thread-safe deny-list of revoked JWT ids keyed by their expiry time."""

    def __init__(self) -> None:
        self._store: set = set()
        self._lock = threading.Lock()

    def _purge_expired(self, now: float | None = None) -> None:
        """Drop entries with no remaining lifetime (bounded memory)."""
        if not self._store:
            return
        now = now if now is not None else time.time()
        with self._lock:
            expired = {jti for jti, exp in list(self._store) if exp <= now}
            self._store.difference_update(expired)

    def revoke(self, jti: str, expires_at: float) -> None:
        """Mark a token id as revoked until ``expires_at`` (epoch seconds)."""
        with self._lock:
            self._store.add((jti, expires_at))

    def is_revoked(self, jti: str) -> bool:
        """Return True if the given ``jti`` has been revoked (and is live)."""
        self._purge_expired()
        with self._lock:
            return any(jid == jti for jid, _ in self._store)

    def reset(self) -> None:
        """Clear all entries (used by tests)."""
        with self._lock:
            self._store.clear()


#: Module-level singleton shared across the application.
token_store = TokenStore()