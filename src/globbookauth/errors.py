"""Exceptions raised by this SDK."""

from __future__ import annotations

from typing import Optional

# Well-known OAuth error codes returned by Globbook's authorization server.
# These appear as AuthError.code.
ERROR_INVALID_REQUEST = "invalid_request"
ERROR_INVALID_GRANT = "invalid_grant"
ERROR_INVALID_TOKEN = "invalid_token"
ERROR_UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"

# Raised by this SDK itself (never returned by the Globbook API) —
# distinguished from the OAuth-standard codes above so callers can tell a
# real API rejection from a client-side transport failure.
ERROR_TIMEOUT = "timeout"
ERROR_NETWORK_ERROR = "network_error"
ERROR_INVALID_RESPONSE = "invalid_response"


class AuthError(Exception):
    """
    An OAuth-standard error returned by Globbook's authorization server (the
    token and userinfo endpoints), per RFC 6749 §5.2 — or a client-side
    transport failure normalized into the same shape (see the ``ERROR_*``
    module constants for which codes are which).

    Every failure from :meth:`Client.exchange_code_for_token` and
    :meth:`Client.get_user_info` raises this (never a raw
    ``urllib.error.URLError``/timeout/JSON-decode exception), so calling
    code only ever needs to catch one exception type.

    Example::

        try:
            token = client.exchange_code_for_token(code)
        except AuthError as e:
            if e.code == globbookauth.ERROR_INVALID_GRANT:
                ...  # code was invalid, expired, or already used
            else:
                log.error("globbook oauth error: %s: %s", e.code, e.description)
    """

    def __init__(self, code: str, description: str = "", status_code: Optional[int] = None) -> None:
        self.code = code
        self.description = description
        self.status_code = status_code
        super().__init__(f"globbookauth: {code}" + (f" ({description})" if description else ""))

    def __repr__(self) -> str:
        return f"AuthError(code={self.code!r}, description={self.description!r}, status_code={self.status_code!r})"
