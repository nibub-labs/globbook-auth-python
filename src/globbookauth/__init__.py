"""
globbookauth — a dependency-free Python client SDK for "Sign in with
Globbook", the OAuth 2.0-style authorization-code flow exposed by
Globbook's backend at ``/api/v2/oauth/*``.

Flow:
    1. Redirect the user's browser to :meth:`Client.get_authorization_url`.
    2. Extract the code (and state) from the callback with
       :func:`parse_callback_params`, then call
       :meth:`Client.exchange_code_for_token`.
    3. Call :meth:`Client.get_user_info` with the access token.

Minimal usage::

    from globbookauth import Client, Config

    client = Client(Config(
        client_id=os.environ["GLOBBOOK_CLIENT_ID"],
        client_secret=os.environ["GLOBBOOK_CLIENT_SECRET"],
        redirect_url="https://yourapp.com/auth/globbook/callback",
    ))

    # Step 1
    return redirect(client.get_authorization_url())

    # Step 2 + 3 (callback handler)
    params = parse_callback_params(request.url)
    token = client.exchange_code_for_token(params.code)
    user = client.get_user_info(token.access_token)
"""

from .client import Client, parse_callback_params
from .errors import (
    AuthError,
    ERROR_INVALID_GRANT,
    ERROR_INVALID_REQUEST,
    ERROR_INVALID_RESPONSE,
    ERROR_INVALID_TOKEN,
    ERROR_NETWORK_ERROR,
    ERROR_TIMEOUT,
    ERROR_UNSUPPORTED_MEDIA_TYPE,
)
from .types import (
    AuthorizationUrlOptions,
    CallbackParams,
    Config,
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT_SECONDS,
    SCOPE_ADDRESS,
    SCOPE_BIRTHDATE,
    SCOPE_GENDER,
    SCOPE_PHONE,
    Token,
    UserInfo,
)

__version__ = "1.1.0"

__all__ = [
    "Client",
    "parse_callback_params",
    "AuthError",
    "ERROR_INVALID_GRANT",
    "ERROR_INVALID_REQUEST",
    "ERROR_INVALID_RESPONSE",
    "ERROR_INVALID_TOKEN",
    "ERROR_NETWORK_ERROR",
    "ERROR_TIMEOUT",
    "ERROR_UNSUPPORTED_MEDIA_TYPE",
    "AuthorizationUrlOptions",
    "CallbackParams",
    "Config",
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "SCOPE_ADDRESS",
    "SCOPE_BIRTHDATE",
    "SCOPE_GENDER",
    "SCOPE_PHONE",
    "Token",
    "UserInfo",
    "__version__",
]
