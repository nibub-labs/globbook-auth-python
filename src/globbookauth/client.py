"""The OAuth client: builds the consent redirect, exchanges codes, fetches profiles."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, parse_qs

from .errors import (
    AuthError,
    ERROR_INVALID_RESPONSE,
    ERROR_NETWORK_ERROR,
    ERROR_TIMEOUT,
)
from .types import AuthorizationUrlOptions, CallbackParams, Config, Token, UserInfo


def parse_callback_params(url_or_query: str) -> CallbackParams:
    """
    Extracts the authorization code (and CSRF-protection ``state``, if
    present) from the callback request Globbook redirects the user's
    browser to after they approve (or deny) the consent screen (step 2 of
    the flow).

    Framework-agnostic: pass a full URL, a path+query string, or a bare
    query string (with or without a leading ``?``) — works with Django's
    ``request.get_full_path()``, Flask's ``request.url``, FastAPI's
    ``str(request.url)``, or any equivalent.

    Args:
        url_or_query: A full URL, a path with query string, or a bare query
            string.

    Returns:
        A :class:`~globbookauth.types.CallbackParams` — both fields are
        ``None`` if not present. If you passed ``state`` to
        :meth:`Client.get_authorization_url`, compare the returned
        ``state`` against what you stored before redirecting and reject
        the callback on a mismatch.

    Example::

        params = parse_callback_params(request.url)
        if not params.code or params.state != session.pop("oauth_state", None):
            raise ValueError("invalid or missing state — possible CSRF")
    """
    query = urlsplit(url_or_query).query or url_or_query
    parsed = parse_qs(query)
    code = parsed.get("code", [None])[0]
    state = parsed.get("state", [None])[0]
    return CallbackParams(code=code or None, state=state or None)


class Client:
    """
    Server-side client for "Sign in with Globbook" OAuth 2.0.

    Typical flow:
        1. Build a redirect URL with :meth:`get_authorization_url` and send
           the user's browser there.
        2. Globbook redirects back to your ``redirect_url`` with
           ``?code=...`` (and ``?state=...`` if you sent one) — parse it
           with the module-level :func:`parse_callback_params`.
        3. Exchange that code for an access token with
           :meth:`exchange_code_for_token`.
        4. Fetch the user's profile with :meth:`get_user_info`.

    SECURITY: only ever construct this class in server-side code. It
    requires ``client_secret``, which must never be shipped to a browser
    bundle or a mobile app.

    This client is stateless and safe to reuse across multiple
    requests/users — it holds no per-user mutable state after construction.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._base_url = config.base_url.rstrip("/")

    def get_authorization_url(self, options: Optional[AuthorizationUrlOptions] = None) -> str:
        """
        Builds the URL to redirect the user's browser to for the
        Globbook-hosted consent screen. Makes no network request — your
        handler is responsible for issuing the actual redirect.

        After the user approves, Globbook redirects back to this client's
        configured ``redirect_url`` with a ``code`` query parameter (and
        ``state``, if you passed one).

        Args:
            options: See :class:`~globbookauth.types.AuthorizationUrlOptions`.
                Omit for the base profile with no CSRF-protection state.

        Returns:
            The full authorization URL, e.g.
            ``https://globbook.com/api/v2/oauth/authorize?client_id=...``.
        """
        opts = options or AuthorizationUrlOptions()
        params: Dict[str, str] = {"client_id": self._config.client_id}
        if opts.scopes:
            params["scope"] = " ".join(opts.scopes)
        if opts.state:
            params["state"] = opts.state
        return f"{self._base_url}/api/v2/oauth/authorize?{urllib.parse.urlencode(params)}"

    def exchange_code_for_token(self, code: str) -> Token:
        """
        Exchanges an authorization code (from :func:`parse_callback_params`)
        for an access token via ``POST /api/v2/oauth/token``.

        Sent as ``application/x-www-form-urlencoded`` — the only content
        type Globbook's token endpoint accepts.

        Args:
            code: The ``code`` value received in the OAuth callback.

        Returns:
            The issued :class:`~globbookauth.types.Token`.

        Raises:
            AuthError: if ``code`` is empty, the request fails at the
                transport level, or the API rejects it (e.g.
                ``invalid_grant`` for an expired/already-used code).
        """
        if not code or not code.strip():
            raise AuthError("invalid_request", "exchange_code_for_token: 'code' must not be empty")

        form = urllib.parse.urlencode(
            {
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "code": code,
            }
        ).encode("ascii")

        body = self._post(f"{self._base_url}/api/v2/oauth/token", form)
        return Token(
            access_token=str(body.get("access_token", "")),
            token_type=str(body.get("token_type", "")),
            expires_in=int(body.get("expires_in", 0)),
        )

    def get_user_info(self, access_token: str) -> UserInfo:
        """
        Fetches the authenticated user's profile via
        ``GET /api/v2/oauth/userinfo`` using
        ``Authorization: Bearer {access_token}``.

        Args:
            access_token: The access token from
                :meth:`exchange_code_for_token`.

        Returns:
            The user's :class:`~globbookauth.types.UserInfo`.

        Raises:
            AuthError: if ``access_token`` is empty, the request fails at
                the transport level, or the API rejects it
                (``invalid_token`` — missing, malformed, or expired).
        """
        if not access_token or not access_token.strip():
            raise AuthError("invalid_request", "get_user_info: 'access_token' must not be empty")

        req = urllib.request.Request(
            f"{self._base_url}/api/v2/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            method="GET",
        )
        body = self._send(req)

        return UserInfo(
            sub=str(body.get("sub", "")),
            preferred_username=str(body.get("preferred_username", "")),
            profile_verified=bool(body.get("profile_verified", False)),
            email=str(body.get("email", "")),
            name=str(body.get("name", "")),
            given_name=str(body.get("given_name", "")),
            family_name=str(body.get("family_name", "")),
            bio=str(body.get("bio", "")),
            picture=body.get("picture"),
            cover_image=body.get("cover_image"),
            website=str(body.get("website", "")),
            # Restricted claims are omitted from the response entirely (not
            # sent as empty strings) unless the app is verified and the
            # user granted the matching scope — .get(...) already yields
            # None for a missing key, so no extra coercion is needed here.
            birthdate=body.get("birthdate"),
            gender=body.get("gender"),
            phone_number=body.get("phone_number"),
            address=body.get("address"),
        )

    def _post(self, url: str, form_body: bytes) -> Dict[str, Any]:
        req = urllib.request.Request(
            url,
            data=form_body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        return self._send(req)

    def _send(self, req: urllib.request.Request) -> Dict[str, Any]:
        timeout = self._config.timeout_seconds if self._config.timeout_seconds > 0 else None
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return self._decode(raw, resp.status)
        except urllib.error.HTTPError as e:
            raw = e.read()
            raise self._error_from_body(raw, e.code) from e
        except socket.timeout as e:
            raise AuthError(ERROR_TIMEOUT, f"Request to Globbook timed out after {self._config.timeout_seconds}s") from e
        except urllib.error.URLError as e:
            raise AuthError(ERROR_NETWORK_ERROR, f"Request to Globbook failed: {e.reason}") from e

    def _decode(self, raw: bytes, status: int) -> Dict[str, Any]:
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise AuthError(ERROR_INVALID_RESPONSE, f"Globbook API returned a non-JSON response (HTTP {status})") from e
        if not isinstance(decoded, dict):
            raise AuthError(ERROR_INVALID_RESPONSE, f"Globbook API returned an unexpected JSON shape (HTTP {status})")
        return decoded

    def _error_from_body(self, raw: bytes, status: int) -> AuthError:
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return AuthError(ERROR_INVALID_RESPONSE, f"Globbook API returned a non-JSON error response (HTTP {status})", status)
        if not isinstance(decoded, dict) or "error" not in decoded:
            return AuthError(ERROR_INVALID_RESPONSE, f"Globbook API returned an unexpected error shape (HTTP {status})", status)
        return AuthError(str(decoded.get("error")), str(decoded.get("error_description", "")), status)
