"""Personal OAuth 2.0 provider for Claude.ai remote MCP connections.

Implements authorization code + PKCE flow with:
- Dynamic client registration (Claude.ai self-registers)
- PIN-protected authorization page
- In-memory token storage (tokens live as long as the process)
"""

import secrets
import time
from urllib.parse import urlencode

from fastmcp.server.auth import OAuthProvider, AccessToken
from mcp.server.auth.provider import AuthorizationCode, RefreshToken, AuthorizationParams
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

_ACCESS_TTL = 365 * 24 * 3600  # 1 year — personal use, no refresh pressure
_REFRESH_TTL = 365 * 24 * 3600
_CODE_TTL = 300  # 5 minutes to complete the browser round-trip

_AUTHORIZE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Qualys MCP — Authorize</title>
  <style>
    *{{box-sizing:border-box}} body{{font-family:system-ui,sans-serif;background:#f5f5f5;
    display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
    .card{{background:#fff;border-radius:8px;box-shadow:0 2px 12px #0002;padding:32px;
    width:100%;max-width:420px}} h2{{margin:0 0 4px;color:#b00020}} .sub{{color:#555;
    font-size:.9em;margin:0 0 24px}} label{{display:block;font-weight:600;margin-bottom:6px}}
    input[type=password]{{width:100%;padding:10px;font-size:1em;border:1px solid #ccc;
    border-radius:4px}} button{{margin-top:16px;width:100%;background:#b00020;color:#fff;
    border:none;padding:12px;font-size:1em;border-radius:4px;cursor:pointer}}
    button:hover{{background:#8a0018}} .err{{color:#b00020;font-size:.9em;margin-top:8px}}
    .client{{font-weight:600}}
  </style>
</head>
<body>
<div class="card">
  <h2>Qualys MCP</h2>
  <p class="sub"><span class="client">{client_name}</span> is requesting access to your Qualys data.</p>
  <form method="post">
    <input type="hidden" name="client_id"      value="{client_id}">
    <input type="hidden" name="state"          value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="redirect_uri"   value="{redirect_uri}">
    <input type="hidden" name="scopes"         value="{scopes}">
    <label for="pin">PIN</label>
    <input type="password" id="pin" name="pin" autofocus placeholder="Enter your MCP_OAUTH_PIN">
    {error}
    <button type="submit">Authorize</button>
  </form>
</div>
</body>
</html>"""

_ERROR_FRAG = '<p class="err">Incorrect PIN — try again.</p>'


class PersonalOAuthProvider(OAuthProvider):
    """Minimal OAuth 2.0 server for single-user personal MCP deployments.

    All state lives in memory; tokens are valid for 1 year so day-to-day
    use doesn't require re-authorization.
    """

    def __init__(self, base_url: str, pin: str):
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )
        self._pin = pin
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    # ------------------------------------------------------------------
    # Client registry
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    # ------------------------------------------------------------------
    # Authorization — redirect user to our PIN page
    # ------------------------------------------------------------------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        base = str(self.base_url).rstrip("/")
        qp = urlencode({
            "client_id":      client.client_id,
            "state":          params.state or "",
            "code_challenge": params.code_challenge or "",
            "redirect_uri":   str(params.redirect_uri or ""),
            "scopes":         " ".join(params.scopes or []),
        })
        return f"{base}/authorize/page?{qp}"

    # ------------------------------------------------------------------
    # Authorization code lifecycle
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code and code.expires_at > time.time():
            return code
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._codes.pop(authorization_code.code, None)

        at = secrets.token_urlsafe(32)
        rt = secrets.token_urlsafe(32)
        now = int(time.time())

        self._access_tokens[at] = AccessToken(
            token=at,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + _ACCESS_TTL,
        )
        self._refresh_tokens[rt] = RefreshToken(
            token=rt,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + _REFRESH_TTL,
        )
        return OAuthToken(
            access_token=at,
            token_type="bearer",
            expires_in=_ACCESS_TTL,
            scope=" ".join(authorization_code.scopes or []),
            refresh_token=rt,
        )

    # ------------------------------------------------------------------
    # Refresh token lifecycle
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rt = self._refresh_tokens.get(refresh_token)
        if rt and rt.client_id == client.client_id and rt.expires_at > time.time():
            return rt
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)
        effective = scopes or refresh_token.scopes

        at = secrets.token_urlsafe(32)
        new_rt = secrets.token_urlsafe(32)
        now = int(time.time())

        self._access_tokens[at] = AccessToken(
            token=at,
            client_id=client.client_id,
            scopes=effective,
            expires_at=now + _ACCESS_TTL,
        )
        self._refresh_tokens[new_rt] = RefreshToken(
            token=new_rt,
            client_id=client.client_id,
            scopes=effective,
            expires_at=now + _REFRESH_TTL,
        )
        return OAuthToken(
            access_token=at,
            token_type="bearer",
            expires_in=_ACCESS_TTL,
            scope=" ".join(effective or []),
            refresh_token=new_rt,
        )

    # ------------------------------------------------------------------
    # Access token verification
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self._access_tokens.get(token)
        if at and (at.expires_at is None or at.expires_at > time.time()):
            return at
        return None

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        else:
            self._refresh_tokens.pop(token.token, None)

    # ------------------------------------------------------------------
    # Authorization page route (/authorize/page)
    # ------------------------------------------------------------------

    def _issue_code(self, client_id: str, scopes: list[str],
                    code_challenge: str, redirect_uri: str) -> str:
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            client_id=client_id,
            scopes=scopes,
            expires_at=time.time() + _CODE_TTL,
            code_challenge=code_challenge,
            redirect_uri=redirect_uri,  # type: ignore[arg-type]
            redirect_uri_provided_explicitly=bool(redirect_uri),
        )
        return code

    def build_authorize_route(self) -> Route:
        """Return the Starlette Route for the PIN authorization page."""
        provider = self

        async def authorize_page(request: Request) -> HTMLResponse | RedirectResponse:
            if request.method == "GET":
                p = dict(request.query_params)
                client = await provider.get_client(p.get("client_id", ""))
                return HTMLResponse(_AUTHORIZE_HTML.format(
                    client_name=client.client_name if client else "Unknown",
                    client_id=p.get("client_id", ""),
                    state=p.get("state", ""),
                    code_challenge=p.get("code_challenge", ""),
                    redirect_uri=p.get("redirect_uri", ""),
                    scopes=p.get("scopes", ""),
                    error="",
                ))

            form = await request.form()
            pin = str(form.get("pin", ""))

            if not secrets.compare_digest(pin, provider._pin):
                client = await provider.get_client(str(form.get("client_id", "")))
                return HTMLResponse(_AUTHORIZE_HTML.format(
                    client_name=client.client_name if client else "Unknown",
                    client_id=form.get("client_id", ""),
                    state=form.get("state", ""),
                    code_challenge=form.get("code_challenge", ""),
                    redirect_uri=form.get("redirect_uri", ""),
                    scopes=form.get("scopes", ""),
                    error=_ERROR_FRAG,
                ), status_code=401)

            scopes = [s for s in str(form.get("scopes", "")).split() if s]
            code = provider._issue_code(
                client_id=str(form.get("client_id", "")),
                scopes=scopes,
                code_challenge=str(form.get("code_challenge", "")),
                redirect_uri=str(form.get("redirect_uri", "")),
            )
            redirect_uri = str(form.get("redirect_uri", ""))
            state = str(form.get("state", ""))
            sep = "&" if "?" in redirect_uri else "?"
            return RedirectResponse(
                f"{redirect_uri}{sep}code={code}&state={state}",
                status_code=302,
            )

        return Route("/authorize/page", authorize_page, methods=["GET", "POST"])
