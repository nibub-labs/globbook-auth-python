"""
Runnable demonstration of a complete "Sign in with Globbook" flow using
Python's stdlib http.server — a "/login" handler that redirects to
Globbook's consent page, and a "/auth/globbook/callback" handler that
exchanges the returned code for an access token and fetches the user's
profile.

This is a demonstration, not a production auth system: it prints the
resulting profile instead of establishing a session, uses a plain
in-memory dict for the pending CSRF state (a real app should use a signed
cookie or server-side session store), and reads credentials from
environment variables for convenience.

Run it with:

    GLOBBOOK_CLIENT_ID=your-client-id \
    GLOBBOOK_CLIENT_SECRET=your-client-secret \
    GLOBBOOK_REDIRECT_URL=http://localhost:8080/auth/globbook/callback \
    python example/app.py

Then open http://localhost:8080/login in a browser.
"""

from __future__ import annotations

import html
import os
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer

from globbookauth import AuthError, AuthorizationUrlOptions, Client, Config, parse_callback_params

client = Client(
    Config(
        client_id=os.environ["GLOBBOOK_CLIENT_ID"],
        client_secret=os.environ["GLOBBOOK_CLIENT_SECRET"],
        redirect_url=os.environ["GLOBBOOK_REDIRECT_URL"],
        # base_url="https://staging.globbook.com",  # uncomment to target staging
    )
)

# Demonstration only — a real app stores this server-side (session/signed
# cookie) keyed per browser session, not a single global value.
_pending_state: str = ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.startswith("/login"):
            self._login()
        elif self.path.startswith("/auth/globbook/callback"):
            self._callback()
        else:
            self.send_response(404)
            self.end_headers()

    def _login(self) -> None:
        global _pending_state
        _pending_state = secrets.token_hex(32)
        url = client.get_authorization_url(AuthorizationUrlOptions(state=_pending_state))
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def _callback(self) -> None:
        params = parse_callback_params(self.path)
        if not params.code or params.state != _pending_state:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid or missing state -- possible CSRF.")
            return

        try:
            token = client.exchange_code_for_token(params.code)
            user = client.get_user_info(token.access_token)
        except AuthError as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"sign-in failed: {e.code}".encode("utf-8"))
            return

        # A real app would look up or create a local account keyed on
        # user.sub and establish its own session here.
        body = (
            f"<h1>Signed in with Globbook</h1>"
            f"<p>Welcome, {html.escape(user.name)} (@{html.escape(user.preferred_username)})</p>"
            f"<p>{html.escape(user.email)}</p>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("listening on http://localhost:8080 -- visit /login to start the flow")
    HTTPServer(("localhost", 8080), Handler).serve_forever()
