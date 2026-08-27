# Changelog

All notable changes to this project are documented in this file.

## 1.1.0 - Initial release

Initial release of `globbook-auth`, a dependency-free Python client SDK for
"Sign in with Globbook". Versioned at 1.1.0 from the start to match the
current generation of the sibling Go/JS/PHP SDKs, which include this
version's restricted-claims and CSRF-state support natively rather than
as a later addition.

- `Client(Config)` — server-side OAuth client, validated via `Config`
  (a frozen dataclass) at construction time.
- `Client.get_authorization_url(options)` to build the redirect URL for
  step 1 of the OAuth flow (`GET /api/v2/oauth/authorize`), supporting:
  - `AuthorizationUrlOptions.scopes` — request restricted claims
    (`SCOPE_BIRTHDATE`, `SCOPE_GENDER`, `SCOPE_PHONE`, `SCOPE_ADDRESS`).
  - `AuthorizationUrlOptions.state` — optional CSRF protection (RFC 6749
    §10.12), echoed back by `parse_callback_params`.
- `parse_callback_params(url_or_query)` to extract `code`/`state` from a
  callback request — accepts a full URL, path+query, or bare query string.
- `Client.exchange_code_for_token(code)` implementing the token exchange
  (`POST /api/v2/oauth/token`, `application/x-www-form-urlencoded`),
  returning a `Token`.
- `Client.get_user_info(access_token)` implementing the userinfo fetch
  (`GET /api/v2/oauth/userinfo`), returning a `UserInfo` with OIDC-style
  top-level fields plus nullable restricted claims (`birthdate`, `gender`,
  `phone_number`, `address`) — `None` unless the app is verified and the
  user granted the matching scope.
- `AuthError` carrying the OAuth `error`/`error_description`/HTTP status,
  plus SDK-raised codes (`timeout`, `network_error`, `invalid_response`)
  for transport-level failures.
- Configurable `base_url` (defaults to `https://globbook.com`) and
  `timeout_seconds` (defaults to 10s) bounding every request.
- Secret redaction: `Config.__repr__`/`Token.__repr__` never leak
  `client_secret`/`access_token`.
- Zero third-party runtime dependencies — standard library
  (`urllib`) only. Fully typed, `py.typed` marker included, passes
  `mypy --strict`.
