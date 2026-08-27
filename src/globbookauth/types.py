"""Value types used by this SDK's public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_BASE_URL = "https://globbook.com"
DEFAULT_TIMEOUT_SECONDS = 10.0

# Restricted OIDC-style scopes you may pass to
# Client.get_authorization_url(scopes=[...]) to request restricted userinfo
# claims. Requesting a scope only has an effect if your app has been
# verified in the Globbook Developer Console — an unverified app's consent
# screen never offers these regardless of what's requested, and
# get_user_info() never returns them either way unless the user actually
# grants them at consent time.
SCOPE_BIRTHDATE = "birthdate"
SCOPE_GENDER = "gender"
SCOPE_PHONE = "phone"
SCOPE_ADDRESS = "address"


@dataclass(frozen=True)
class Config:
    """
    Settings passed to :class:`~globbookauth.client.Client`.

    ``client_id``, ``client_secret``, and ``redirect_url`` are required and
    must correspond to an application already registered in Globbook's
    developer console — this package has no application-registration API
    of its own.

    Attributes:
        client_id: App ID issued when you register the app.
        client_secret: Confidential secret issued alongside ``client_id``.
            SECURITY: server-side only — never embed this in a browser
            bundle or mobile app.
        redirect_url: Your app's callback URL, exactly as registered with
            Globbook.
        base_url: Globbook API origin. Defaults to
            :data:`DEFAULT_BASE_URL`. Override for a staging/self-hosted
            environment.
        timeout_seconds: Timeout applied to every HTTP request this client
            makes (token exchange, userinfo). Defaults to
            :data:`DEFAULT_TIMEOUT_SECONDS` (10s) so a slow or unresponsive
            Globbook endpoint can't hang your request indefinitely. Pass
            ``0`` to disable.
    """

    client_id: str
    client_secret: str
    redirect_url: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __repr__(self) -> str:
        # Redact client_secret so an accidental repr()/log of a Config
        # never leaks it.
        return (
            f"Config(client_id={self.client_id!r}, client_secret='[REDACTED]', "
            f"redirect_url={self.redirect_url!r}, base_url={self.base_url!r}, "
            f"timeout_seconds={self.timeout_seconds!r})"
        )


@dataclass(frozen=True)
class Token:
    """The access token issued by Globbook's token endpoint."""

    access_token: str
    """Bearer token to present to :meth:`Client.get_user_info`. Never log this value."""

    token_type: str
    """Always ``"Bearer"`` for tokens issued by Globbook."""

    expires_in: int
    """Seconds from issuance until expiry. Globbook does not currently issue refresh tokens."""

    def __repr__(self) -> str:
        return f"Token(access_token='[REDACTED]', token_type={self.token_type!r}, expires_in={self.expires_in!r})"


@dataclass(frozen=True)
class CallbackParams:
    """Result of :func:`~globbookauth.client.parse_callback_params`."""

    code: Optional[str]
    """The authorization code to pass to :meth:`Client.exchange_code_for_token`. ``None`` if not present."""

    state: Optional[str] = None
    """
    The CSRF-protection value Globbook echoed back, if you passed one to
    :meth:`Client.get_authorization_url`. ``None`` if you didn't send one,
    or it wasn't present in the callback. If you sent one, compare this
    against what you stored before redirecting and reject the callback on
    a mismatch — see the README's "CSRF protection (state)" section.
    """


@dataclass(frozen=True)
class UserInfo:
    """
    The authenticated user's profile, as returned by
    ``GET /api/v2/oauth/userinfo``. Fields mirror the OIDC top-level claims.
    """

    sub: str
    """OIDC subject identifier — an MD5 hash, NOT the raw numeric user id. Stable per-user."""

    preferred_username: str
    profile_verified: bool
    email: str
    name: str
    """First + last name joined by a space, or just one half if the other is empty."""
    given_name: str
    family_name: str
    bio: str
    """May be an empty string if unset."""
    picture: Optional[str]
    """Signed CDN URL, or ``None`` if the user has no avatar. Time-limited — don't cache long-term."""
    cover_image: Optional[str]
    """Signed CDN URL, or ``None``. Time-limited — don't cache long-term."""
    website: str

    # Restricted claims — None unless BOTH are true: your app is verified
    # in the Globbook Developer Console, and the user granted the matching
    # scope on the consent screen (see SCOPE_* module constants). An
    # unverified app never receives these regardless of what's requested
    # or approved.
    birthdate: Optional[str] = None
    """``YYYY-MM-DD``, or ``None`` — see the class docstring on restricted claims."""
    gender: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    """``"city country"`` — this platform stores no street-level address."""


@dataclass(frozen=True)
class AuthorizationUrlOptions:
    """
    Options for :meth:`Client.get_authorization_url`.

    Attributes:
        scopes: Restricted scopes to request in addition to the base
            profile (see the ``SCOPE_*`` module constants), rendered as a
            space-delimited ``scope`` query parameter. Requesting a scope
            only has an effect if this app is verified in the Globbook
            Developer Console.
        state: An opaque value you generate before redirecting the user
            here — Globbook echoes it back unchanged in the ``state`` query
            parameter on the redirect to your ``redirect_url``, so
            :func:`parse_callback_params` can hand it back to you to
            compare against what you stored before the redirect (RFC 6749
            §10.12 CSRF protection). Globbook never interprets this value
            itself. Optional; leave ``None`` to omit it.
    """

    scopes: List[str] = field(default_factory=list)
    state: Optional[str] = None
