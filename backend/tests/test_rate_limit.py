"""Rate-limiting tests: sliding-window throttle, failure lockout, unit tests.

The autouse fixture in conftest resets the shared limiter between tests.
"""

from app.core.config import settings
from app.security import rate_limit


class TestRateLimiterUnit:
    def _make(self, monkeypatch, start=1000.0):
        fake_time = [start]
        monkeypatch.setattr(rate_limit.time, "time", lambda: fake_time[0])
        limiter = rate_limit.RateLimiter()
        return limiter, fake_time

    def test_limit_enforced(self, monkeypatch):
        limiter, _ = self._make(monkeypatch)
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is False

    def test_window_expiry(self, monkeypatch):
        limiter, fake_time = self._make(monkeypatch)
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is True
        assert limiter.hit("k", 60, 3) is False
        fake_time[0] += 61  # slide past the window
        assert limiter.hit("k", 60, 3) is True

    def test_clear_and_reset(self, monkeypatch):
        limiter, _ = self._make(monkeypatch)
        for _ in range(3):
            limiter.hit("k", 60, 3)
        limiter.clear("k")
        assert limiter.hit("k", 60, 3) is True
        for _ in range(3):
            limiter.hit("k", 60, 3)
        limiter.reset()
        assert limiter.hit("k", 60, 3) is True


class TestLoginRateLimit:
    def test_ip_throttle_returns_429(self, client):
        """Request-level throttle kicks in after LOGIN_RATELIMIT_MAX attempts.

        Each attempt uses a fresh username so the per-(IP, username) failure
        lockout never triggers; only the per-IP counter is exercised.
        """
        max_attempts = settings.login_ratelimit_max
        for i in range(max_attempts):
            resp = client.post(
                "/api/auth/login",
                json={"username": f"nobody_{i}", "password": "Wrong-1"},
            )
            assert resp.status_code == 401
        # The next attempt is now over the per-IP limit.
        resp = client.post(
            "/api/auth/login",
            json={"username": "nobody_999", "password": "Wrong-1"},
        )
        assert resp.status_code == 429

    def test_failure_lockout_returns_429(self, client, user_factory):
        """After LOCKOUT_MAX_FAILURES wrong passwords, the same user is blocked."""
        user = user_factory(username="lockme")
        failures = settings.login_lockout_max_failures
        for _ in range(failures):
            resp = client.post(
                "/api/auth/login",
                json={"username": user.username, "password": "Wrong-1"},
            )
            assert resp.status_code == 401
        resp = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "Wrong-1"},
        )
        assert resp.status_code == 429

    def test_successful_login_clears_lockout(self, client, user_factory):
        user = user_factory(username="lockclear")
        password = "Passw0rd!x"
        failures = settings.login_lockout_max_failures - 1
        for _ in range(failures):
            assert (
                client.post(
                    "/api/auth/login",
                    json={"username": user.username, "password": "Wrong-1"},
                ).status_code
                == 401
            )
        # Correct password inside the window: succeeds and clears the counter.
        ok = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": password},
        )
        assert ok.status_code == 200
        # A subsequent wrong password is a fresh failure, not an immediate 429.
        after = client.post(
            "/api/auth/login",
            json={"username": user.username, "password": "Wrong-1"},
        )
        assert after.status_code == 401