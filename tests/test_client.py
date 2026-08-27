from __future__ import annotations

import json
import socket
import urllib.error
from typing import Any, Dict, Optional
from unittest.mock import patch

import pytest

from globbookauth import (
    AuthError,
    AuthorizationUrlOptions,
    Client,
    Config,
    SCOPE_BIRTHDATE,
    SCOPE_GENDER,
    parse_callback_params,
)


def make_client(**overrides: Any) -> Client:
    defaults: Dict[str, Any] = {
        "client_id": "client-123",
        "client_secret": "secret-abc",
        "redirect_url": "https://example.com/callback",
    }
    defaults.update(overrides)
    return Client(Config(**defaults))


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def json_bytes(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# get_authorization_url
# ---------------------------------------------------------------------------


def test_get_authorization_url_default() -> None:
    client = make_client()
    assert client.get_authorization_url() == "https://globbook.com/api/v2/oauth/authorize?client_id=client-123"


def test_get_authorization_url_custom_base_url() -> None:
    client = make_client(base_url="https://staging.globbook.com")
    assert (
        client.get_authorization_url()
        == "https://staging.globbook.com/api/v2/oauth/authorize?client_id=client-123"
    )


def test_get_authorization_url_strips_trailing_slash_from_base_url() -> None:
    client = make_client(base_url="https://staging.globbook.com/")
    assert (
        client.get_authorization_url()
        == "https://staging.globbook.com/api/v2/oauth/authorize?client_id=client-123"
    )


def test_get_authorization_url_with_scopes() -> None:
    client = make_client()
    url = client.get_authorization_url(AuthorizationUrlOptions(scopes=[SCOPE_BIRTHDATE, SCOPE_GENDER]))
    assert url == "https://globbook.com/api/v2/oauth/authorize?client_id=client-123&scope=birthdate+gender"


def test_get_authorization_url_with_state() -> None:
    client = make_client()
    url = client.get_authorization_url(AuthorizationUrlOptions(state="csrf-token-123"))
    assert url == "https://globbook.com/api/v2/oauth/authorize?client_id=client-123&state=csrf-token-123"


def test_get_authorization_url_with_scopes_and_state() -> None:
    client = make_client()
    url = client.get_authorization_url(
        AuthorizationUrlOptions(scopes=[SCOPE_BIRTHDATE, SCOPE_GENDER], state="csrf-token-123")
    )
    assert url == (
        "https://globbook.com/api/v2/oauth/authorize?"
        "client_id=client-123&scope=birthdate+gender&state=csrf-token-123"
    )


def test_get_authorization_url_no_options_matches_empty_options() -> None:
    client = make_client()
    assert client.get_authorization_url() == client.get_authorization_url(AuthorizationUrlOptions())


# ---------------------------------------------------------------------------
# parse_callback_params
# ---------------------------------------------------------------------------


def test_parse_callback_params_full_url() -> None:
    params = parse_callback_params("https://example.com/callback?code=abc123&state=xyz789")
    assert params.code == "abc123"
    assert params.state == "xyz789"


def test_parse_callback_params_path_and_query() -> None:
    params = parse_callback_params("/callback?code=abc123")
    assert params.code == "abc123"
    assert params.state is None


def test_parse_callback_params_bare_query_string() -> None:
    params = parse_callback_params("code=abc123&state=xyz789")
    assert params.code == "abc123"
    assert params.state == "xyz789"


def test_parse_callback_params_missing_code() -> None:
    params = parse_callback_params("https://example.com/callback?state=xyz789")
    assert params.code is None
    assert params.state == "xyz789"


def test_parse_callback_params_empty_input() -> None:
    params = parse_callback_params("")
    assert params.code is None
    assert params.state is None


# ---------------------------------------------------------------------------
# exchange_code_for_token
# ---------------------------------------------------------------------------


def test_exchange_code_for_token_success() -> None:
    client = make_client()
    body = json_bytes({"access_token": "tok-xyz", "token_type": "Bearer", "expires_in": 3600})

    captured: Dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: Optional[float] = None) -> FakeResponse:
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        return FakeResponse(200, body)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        token = client.exchange_code_for_token("auth-code-1")

    assert token.access_token == "tok-xyz"
    assert token.token_type == "Bearer"
    assert token.expires_in == 3600
    assert captured["method"] == "POST"
    assert captured["url"] == "https://globbook.com/api/v2/oauth/token"
    ct_header = next(v for k, v in captured["headers"].items() if k.lower() == "content-type")
    assert ct_header == "application/x-www-form-urlencoded"
    assert b"client_id=client-123" in captured["data"]
    assert b"client_secret=secret-abc" in captured["data"]
    assert b"code=auth-code-1" in captured["data"]


def test_exchange_code_for_token_invalid_grant() -> None:
    client = make_client()
    err_body = json_bytes({"error": "invalid_grant", "error_description": "code expired"})

    def raising_urlopen(req: Any, timeout: Optional[float] = None) -> Any:
        import io

        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(err_body))

    with patch("urllib.request.urlopen", side_effect=raising_urlopen):
        with pytest.raises(AuthError) as exc_info:
            client.exchange_code_for_token("stale-code")

    assert exc_info.value.code == "invalid_grant"
    assert exc_info.value.description == "code expired"
    assert exc_info.value.status_code == 401


def test_exchange_code_for_token_empty_code() -> None:
    client = make_client()
    with pytest.raises(AuthError) as exc_info:
        client.exchange_code_for_token("   ")
    assert exc_info.value.code == "invalid_request"


def test_exchange_code_for_token_timeout() -> None:
    client = make_client()

    def fake_urlopen(req: Any, timeout: Optional[float] = None) -> Any:
        raise socket.timeout("timed out")

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        with pytest.raises(AuthError) as exc_info:
            client.exchange_code_for_token("some-code")
    assert exc_info.value.code == "timeout"


def test_exchange_code_for_token_network_error() -> None:
    client = make_client()

    def fake_urlopen(req: Any, timeout: Optional[float] = None) -> Any:
        raise urllib.error.URLError("connection refused")

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        with pytest.raises(AuthError) as exc_info:
            client.exchange_code_for_token("some-code")
    assert exc_info.value.code == "network_error"


# ---------------------------------------------------------------------------
# get_user_info
# ---------------------------------------------------------------------------


def _full_userinfo_body(**overrides: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "sub": "md5hash",
        "preferred_username": "janedoe",
        "profile_verified": True,
        "email": "jane@example.com",
        "name": "Jane Doe",
        "given_name": "Jane",
        "family_name": "Doe",
        "bio": "",
        "picture": None,
        "cover_image": None,
        "website": "",
    }
    body.update(overrides)
    return body


def test_get_user_info_success() -> None:
    client = make_client()
    body = json_bytes(_full_userinfo_body())

    captured: Dict[str, Any] = {}

    def fake_urlopen(req: Any, timeout: Optional[float] = None) -> FakeResponse:
        captured["headers"] = dict(req.header_items())
        return FakeResponse(200, body)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        info = client.get_user_info("tok-xyz")

    assert info.sub == "md5hash"
    assert info.email == "jane@example.com"
    assert info.picture is None
    assert info.profile_verified is True
    assert info.birthdate is None
    assert info.gender is None
    assert info.phone_number is None
    assert info.address is None
    auth_header = next(v for k, v in captured["headers"].items() if k.lower() == "authorization")
    assert auth_header == "Bearer tok-xyz"


def test_get_user_info_restricted_claims_granted() -> None:
    client = make_client()
    body = json_bytes(
        _full_userinfo_body(
            birthdate="1990-01-02",
            gender="female",
            phone_number="+15551234567",
            address="Colombo Sri Lanka",
        )
    )

    def fake_urlopen(req: Any, timeout: Optional[float] = None) -> FakeResponse:
        return FakeResponse(200, body)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        info = client.get_user_info("tok-xyz")

    assert info.birthdate == "1990-01-02"
    assert info.gender == "female"
    assert info.phone_number == "+15551234567"
    assert info.address == "Colombo Sri Lanka"


def test_get_user_info_invalid_token() -> None:
    client = make_client()
    err_body = json_bytes({"error": "invalid_token", "error_description": "token expired"})

    def raising_urlopen(req: Any, timeout: Optional[float] = None) -> Any:
        import io

        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(err_body))

    with patch("urllib.request.urlopen", side_effect=raising_urlopen):
        with pytest.raises(AuthError) as exc_info:
            client.get_user_info("expired-token")

    assert exc_info.value.code == "invalid_token"


def test_get_user_info_empty_access_token() -> None:
    client = make_client()
    with pytest.raises(AuthError) as exc_info:
        client.get_user_info("")
    assert exc_info.value.code == "invalid_request"


# ---------------------------------------------------------------------------
# Config repr redaction
# ---------------------------------------------------------------------------


def test_config_repr_redacts_secret() -> None:
    config = Config(client_id="id", client_secret="super-secret-value", redirect_url="https://example.com/cb")
    r = repr(config)
    assert "super-secret-value" not in r
    assert "[REDACTED]" in r


def test_token_repr_redacts_access_token() -> None:
    from globbookauth import Token

    token = Token(access_token="secret-token-value", token_type="Bearer", expires_in=3600)
    r = repr(token)
    assert "secret-token-value" not in r
    assert "[REDACTED]" in r
