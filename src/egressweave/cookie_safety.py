"""Cookie-state controls shared by EgressWeave HTTPX client builders."""

from __future__ import annotations

from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy


class _RejectResponseCookiePolicy(DefaultCookiePolicy):
    """Reject response-provided cookies while allowing explicit caller state."""

    def set_ok(self, cookie: Cookie, request: object) -> bool:
        """Refuse automatic response-driven cookie persistence."""
        return False


def _new_explicit_cookie_jar() -> CookieJar:
    """Return a cookie jar that accepts direct caller writes but no responses."""
    return CookieJar(policy=_RejectResponseCookiePolicy())
