import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

DOCS_DIR = Path(__file__).parent / "docs"

# The public HTTPS URL of this deployed service, e.g. https://your-app.onrender.com
BASE_URL = os.environ["BASE_URL"].rstrip("/")
# The one passphrase that gates the /login page. Only whoever knows this can
# ever complete the OAuth flow and get a working access token.
PASSPHRASE = os.environ.get("MCP_PASSPHRASE", "changeme")

CODE_TTL_SECONDS = 300
TOKEN_TTL_SECONDS = 3600


def _list_docs() -> dict:
    return {p.stem: p.name for p in sorted(DOCS_DIR.glob("*.md"))}


class SingleUserOAuthProvider(OAuthAuthorizationServerProvider):
    """Minimal OAuth authorization server for exactly one user (you).

    Dynamic Client Registration is open (any MCP client can register itself,
    that's just how the client app identifies itself). The actual gate is the
    /login passphrase step: nobody gets an authorization code, and therefore
    nobody gets an access token, without typing PASSPHRASE correctly.
    """

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.pending: dict[str, dict] = {}  # login_id -> {client_id, params}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = secrets.token_urlsafe(16)
        self.pending[login_id] = {"client_id": client.client_id, "params": params}
        return f"{BASE_URL}/login?login_id={login_id}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self.auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id or code.expires_at < time.time():
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        token = secrets.token_urlsafe(32)
        self.access_tokens[token] = AccessToken(
            token=token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + TOKEN_TTL_SECONDS,
        )
        self.auth_codes.pop(authorization_code.code, None)
        return OAuthToken(
            access_token=token,
            token_type="bearer",
            expires_in=TOKEN_TTL_SECONDS,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_refresh_token(self, client, refresh_token: str):
        return None  # not supported; client must re-authorize

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        raise TokenError(error="unsupported_grant_type", error_description="Refresh tokens are not supported")

    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self.access_tokens.get(token)
        if at is None or (at.expires_at and at.expires_at < time.time()):
            return None
        return at

    async def revoke_token(self, token) -> None:
        self.access_tokens.pop(token.token, None)


provider = SingleUserOAuthProvider()

# The public hostname this server is reached at, e.g. "myapp.onrender.com".
# The MCP SDK's DNS-rebinding protection rejects any Host header not listed
# here, so the deployed host must be allowed explicitly or every /mcp request
# gets a 421 Misdirected Request.
_public_host = urlparse(BASE_URL).netloc

mcp = FastMCP(
    "MyPrivateDocs",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(f"{BASE_URL}/mcp"),
        client_registration_options=ClientRegistrationOptions(enabled=True),
    ),
    # Stateless avoids in-memory session-continuity requirements, which are
    # fragile behind a reverse proxy and on hosts that spin the process down.
    stateless_http=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[_public_host, f"{_public_host}:*", "127.0.0.1:*", "localhost:*"],
        allowed_origins=[BASE_URL, f"{BASE_URL}:*", "http://127.0.0.1:*", "http://localhost:*"],
    ),
)


@mcp.tool()
def list_docs() -> dict:
    """List the available private documents by short name."""
    return _list_docs()


@mcp.tool()
def read_doc(name: str) -> str:
    """Read the full text of one private document.

    Args:
        name: One of the short names returned by list_docs (e.g. 'doc1_azure_lighthouse').
    """
    docs = _list_docs()
    if name not in docs:
        return f"Unknown doc '{name}'. Available: {', '.join(docs.keys())}"
    return (DOCS_DIR / docs[name]).read_text()


@mcp.tool()
def search_docs(query: str) -> dict:
    """Search all private documents for a keyword and return matching lines.

    Args:
        query: Word or phrase to search for, case-insensitive.
    """
    results = {}
    q = query.lower()
    for stem, filename in _list_docs().items():
        text = (DOCS_DIR / filename).read_text()
        hits = [line.strip() for line in text.splitlines() if q in line.lower()]
        if hits:
            results[stem] = hits
    return results or {"message": "No matches found."}


LOGIN_FORM = """<!doctype html>
<html><body style="font-family: sans-serif; max-width: 400px; margin: 80px auto;">
<h2>Sign in to MyPrivateDocs</h2>
{error}
<form method="post">
<input type="hidden" name="login_id" value="{login_id}">
<label>Passphrase<br>
<input type="password" name="passphrase" autofocus style="width: 100%; padding: 8px;">
</label><br><br>
<button type="submit" style="padding: 8px 16px;">Continue</button>
</form>
</body></html>"""


@mcp.custom_route("/login", methods=["GET", "POST"])
async def login(request: Request) -> Response:
    if request.method == "GET":
        login_id = request.query_params.get("login_id", "")
        if login_id not in provider.pending:
            return HTMLResponse("Invalid or expired login link.", status_code=400)
        return HTMLResponse(LOGIN_FORM.format(error="", login_id=login_id))

    form = await request.form()
    login_id = str(form.get("login_id", ""))
    passphrase = str(form.get("passphrase", ""))
    pending = provider.pending.get(login_id)
    if pending is None:
        return HTMLResponse("Invalid or expired login link.", status_code=400)

    if passphrase != PASSPHRASE:
        return HTMLResponse(
            LOGIN_FORM.format(error="<p style='color:red'>Incorrect passphrase.</p>", login_id=login_id),
            status_code=401,
        )

    provider.pending.pop(login_id, None)
    client_id = pending["client_id"]
    params: AuthorizationParams = pending["params"]

    code = secrets.token_urlsafe(24)
    provider.auth_codes[code] = AuthorizationCode(
        code=code,
        scopes=params.scopes or [],
        expires_at=time.time() + CODE_TTL_SECONDS,
        client_id=client_id,
        code_challenge=params.code_challenge,
        redirect_uri=params.redirect_uri,
        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        resource=params.resource,
    )
    redirect_url = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
    return RedirectResponse(url=redirect_url, status_code=302)


app = mcp.streamable_http_app()

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
