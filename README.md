# globbook-auth-python

A dependency-free Python client SDK for **"Sign in with Globbook"** — the
OAuth 2.0-style authorization-code flow exposed by Globbook's backend at
`/api/v2/oauth/*`.

Use this package to let users of your Python server-side application
(Django, Flask, FastAPI, or plain WSGI/ASGI) sign in with their Globbook
account. It wraps the three real HTTP calls the flow requires
(authorization redirect, token exchange, userinfo fetch) behind a small,
idiomatic Python API, with zero third-party runtime dependencies —
standard library only.

> **Note**: this package does not register applications with Globbook.
> Before using it you must create an app in Globbook's developer console
> to obtain a `client_id`, `client_secret`, and register your app's
> `redirect_url` — that is a one-time manual step, unrelated to this SDK.

## Installation

```sh
pip install globbook-auth
```

Requires Python 3.9 or later.

## Quickstart

The full flow has three steps: redirect the user to Globbook, receive the
callback and exchange the code for a token, then fetch the user's profile.
Here's a Flask example:

```python
import os
from flask import Flask, redirect, request, session

from globbookauth import AuthorizationUrlOptions, Client, Config, parse_callback_params
import secrets

app = Flask(__name__)
client = Client(Config(
    client_id=os.environ["GLOBBOOK_CLIENT_ID"],
    client_secret=os.environ["GLOBBOOK_CLIENT_SECRET"],
    redirect_url="https://yourapp.com/auth/globbook/callback",
    # base_url is optional; defaults to https://globbook.com.
    # base_url="https://staging.globbook.com",
))

@app.route("/login")
def login():
    state = secrets.token_hex(32)
    session["oauth_state"] = state
    return redirect(client.get_authorization_url(AuthorizationUrlOptions(state=state)))

@app.route("/auth/globbook/callback")
def callback():
    params = parse_callback_params(request.url)
    if not params.code or params.state != session.pop("oauth_state", None):
        return "Invalid or missing state -- possible CSRF.", 400

    token = client.exchange_code_for_token(params.code)
    user = client.get_user_info(token.access_token)

    # Look up or create a local account keyed on user.sub, then establish
    # your own session. user.sub is a stable md5 hash identifying the
    # Globbook user -- not their raw numeric ID.
    session["user_id"] = user.sub
    return redirect("/dashboard")
```

A runnable stdlib-only version of this example lives in
[`example/app.py`](./example/app.py).

## API reference

### `class Config`

Settings passed to `Client`:

| Field             | Required | Description                                                                 |
| ----------------- | -------- | ---------------------------------------------------------------------------- |
| `client_id`       | yes      | App ID from Globbook's developer console.                                    |
| `client_secret`   | yes      | Confidential secret from Globbook's developer console. Server-side only.    |
| `redirect_url`    | yes      | Your app's callback URL, exactly as registered with Globbook.               |
| `base_url`        | no       | Globbook API origin. Defaults to `https://globbook.com`.                    |
| `timeout_seconds` | no       | Timeout for every request. Defaults to `10.0`; pass `0` to disable.         |

```python
config = Config(
    client_id="...",
    client_secret="...",
    redirect_url="https://yourapp.com/auth/globbook/callback",
)
```

### `class Client`

```python
client = Client(config)
```

#### `Client.get_authorization_url(options: AuthorizationUrlOptions | None = None) -> str`

Builds the URL to redirect the user's browser to, to start the sign-in
flow. Does not make an HTTP request itself — your handler is responsible
for issuing the actual redirect.

```python
class AuthorizationUrlOptions:
    scopes: list[str] = []   # restricted scopes to request -- see "Restricted claims" below
    state: str | None = None  # opaque CSRF-protection value -- see "CSRF protection (state)" below
```

```python
from globbookauth import SCOPE_BIRTHDATE, SCOPE_GENDER

url = client.get_authorization_url(AuthorizationUrlOptions(
    scopes=[SCOPE_BIRTHDATE, SCOPE_GENDER],
    state=csrf_token,
))
```

#### `parse_callback_params(url_or_query: str) -> CallbackParams`

Module-level function. Extracts the authorization code (and CSRF state, if
present) from a callback request's URL/query string. Framework-agnostic —
pass a full URL, a path+query string, or a bare query string.

```python
class CallbackParams:
    code: str | None
    state: str | None  # None if you didn't send one -- see "CSRF protection (state)" below
```

#### `Client.exchange_code_for_token(code: str) -> Token`

Exchanges an authorization code for an access token via
`POST /api/v2/oauth/token` (sent as `application/x-www-form-urlencoded`,
the only content type Globbook's token endpoint accepts). Raises
`AuthError` on failure.

```python
class Token:
    access_token: str
    token_type: str   # "Bearer"
    expires_in: int   # seconds, typically 3600
```

#### `Client.get_user_info(access_token: str) -> UserInfo`

Fetches the authenticated user's profile via `GET /api/v2/oauth/userinfo`.
Raises `AuthError` on failure.

```python
class UserInfo:
    sub: str  # OIDC "sub" -- an md5 hash, not the numeric user id
    preferred_username: str
    profile_verified: bool
    email: str
    name: str
    given_name: str
    family_name: str
    bio: str
    picture: str | None       # signed CDN URL, or None
    cover_image: str | None   # signed CDN URL, or None
    website: str

    # Restricted claims -- see "Restricted claims" below
    birthdate: str | None    # YYYY-MM-DD, or None
    gender: str | None
    phone_number: str | None
    address: str | None      # "city country" -- this platform has no street address
```

### Restricted claims

`birthdate`, `gender`, `phone_number`, and `address` are gated separately
from the rest of the profile. Globbook only populates them — the field is
`None` otherwise — when **both** are true:

1. Your app has been verified in the Globbook Developer Console.
2. You requested the scope via `get_authorization_url`'s `scopes` option,
   **and** the signed-in user granted it on the consent screen —
   requesting a scope is not the same as receiving it; the user can
   uncheck any scope individually.

An unverified app never receives these fields, regardless of what scopes
it requests or what the user approves on consent. Always check for `None`
before use:

```python
if user.birthdate is not None:
    print("birthdate:", user.birthdate)
```

### CSRF protection (state)

Pass `state` to `AuthorizationUrlOptions` to protect against login CSRF
(RFC 6749 §10.12): an attacker who obtains their own valid authorization
code could otherwise trick a victim's browser into completing the
attacker's login on the victim's session.

```python
# Before redirecting -- generate an unguessable value and store it
# (session, signed cookie) tied to the current browser session.
csrf_token = secrets.token_hex(32)
session["oauth_state"] = csrf_token

url = client.get_authorization_url(AuthorizationUrlOptions(state=csrf_token))
return redirect(url)

# In your callback handler -- compare before exchanging the code.
params = parse_callback_params(request.url)
if not params.code or params.state != session.pop("oauth_state", None):
    return "Invalid or missing state -- possible CSRF.", 400
```

`state` is entirely optional and Globbook never interprets it — it's
echoed back unchanged, per the RFC 6749 `state` parameter. Omitting it
does not change any other behavior; this is opt-in hardening, not a
required step.

## Error handling

Every failed API call (`exchange_code_for_token`, `get_user_info`) raises
an `AuthError`:

```python
from globbookauth import AuthError, ERROR_INVALID_GRANT, ERROR_INVALID_REQUEST

try:
    token = client.exchange_code_for_token(code)
except AuthError as e:
    if e.code == ERROR_INVALID_GRANT:
        pass  # code was invalid, expired, or already used -- restart the flow
    elif e.code == ERROR_INVALID_REQUEST:
        pass  # a required field was missing -- almost certainly a bug in your integration
    else:
        log.error("globbook oauth error: %s: %s", e.code, e.description)
```

Known error codes (all exported as module constants):

| Code                       | Meaning                                                                 |
| --------------------------- | ------------------------------------------------------------------------ |
| `invalid_request`           | A required field was missing/malformed.                                  |
| `invalid_grant`              | `client_id`/`client_secret`/`code` combination rejected.                 |
| `invalid_token`              | The access token given to `get_user_info` is missing/malformed/expired.  |
| `unsupported_media_type`     | The request wasn't sent as `application/x-www-form-urlencoded`. Should never occur from this SDK itself. |
| `timeout`                    | The request exceeded `timeout_seconds`. Raised by this SDK, not the API. |
| `network_error`              | The request failed before reaching the API (DNS, TLS, connection refused). Raised by this SDK. |
| `invalid_response`           | Globbook returned a non-JSON or unexpectedly-shaped body.                |

## Security notes

- **`client_secret` is a server-side secret.** Never embed it in a mobile
  app, browser bundle, or any client-side code — only call this SDK from
  your backend. `Config.__repr__`/`Token.__repr__` redact their secret
  field, but that is a safety net, not a substitute for keeping it out of
  client-side code in the first place.
- **`Token.access_token` is a bearer credential.** Treat it like a
  password: don't log it, don't put it in a URL, transmit it only over
  HTTPS.
- Every request made by this SDK is bounded by `Config.timeout_seconds`
  (default 10s) so a slow or unresponsive Globbook endpoint can't hang
  your request handler indefinitely.

## Testing

The package has no external test dependencies beyond `pytest` (a dev-only
dependency) — `pytest` runs entirely offline using `unittest.mock` to
patch `urllib.request.urlopen` for the token-exchange and userinfo tests.

```sh
pip install -e ".[dev]"
mypy src/globbookauth
pytest
```

## License

MIT — see [LICENSE](./LICENSE).
