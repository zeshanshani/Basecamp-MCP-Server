"""
Railway entry point.

Combines the Basecamp OAuth Flask app, the MCP-spec OAuth 2.1 authorisation
server, and the FastMCP Streamable HTTP transport into a single ASGI
process served by Uvicorn.

Route ownership at the root:

    /.well-known/oauth-authorization-server         MCP SDK (metadata)
    /.well-known/oauth-protected-resource/mcp       MCP SDK (metadata)
    /authorize, /token, /register                   MCP SDK (OAuth endpoints)
    /mcp                                            FastMCP streamable HTTP
                                                      (requires Bearer issued
                                                      by /token)
    everything else                                 Flask (Basecamp OAuth +
                                                      admin UI + /oauth/consent)

Basecamp's own OAuth tokens (used by the MCP tools to call Basecamp) are
stored at $BASECAMP_MCP_TOKEN_FILE on the Railway volume. The MCP server's
OAuth state (clients, codes, access/refresh tokens issued to Claude.ai)
lives at $MCP_OAUTH_STATE_FILE, also on the volume.
"""

import os
from urllib.parse import urlparse

from a2wsgi import WSGIMiddleware
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.routing import Mount

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings

from oauth_app import app as flask_oauth_app, attach_mcp_oauth_provider
from basecamp_fastmcp import mcp
from mcp_oauth_provider import FileOAuthProvider

# ----- Derive public origin from BASECAMP_REDIRECT_URI ---------------------

_redirect_uri = os.environ.get("BASECAMP_REDIRECT_URI", "")
_parsed = urlparse(_redirect_uri)
if not _parsed.scheme or not _parsed.netloc:
    raise RuntimeError(
        "BASECAMP_REDIRECT_URI must be a fully-qualified URL "
        "(e.g. https://<host>/auth/callback)."
    )
_public_origin = f"{_parsed.scheme}://{_parsed.netloc}"
_public_host = _parsed.hostname

# ----- DNS rebinding protection -------------------------------------------

_existing_security = mcp.settings.transport_security
_allowed_hosts = list(_existing_security.allowed_hosts) if _existing_security else []
_allowed_origins = list(_existing_security.allowed_origins) if _existing_security else []
_allowed_hosts.extend([_public_host, f"{_public_host}:*"])
_allowed_origins.append(_public_origin)
mcp.settings.transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=_allowed_hosts,
    allowed_origins=_allowed_origins,
)

# ----- OAuth authorisation server -----------------------------------------

_oauth_state_file = os.environ.get("MCP_OAUTH_STATE_FILE", "/data/mcp_oauth_state.json")
oauth_provider = FileOAuthProvider(
    state_file=_oauth_state_file,
    consent_url_base=_public_origin,
)

mcp._auth_server_provider = oauth_provider
mcp._token_verifier = ProviderTokenVerifier(oauth_provider)
mcp.settings.auth = AuthSettings(
    issuer_url=AnyHttpUrl(_public_origin),
    resource_server_url=AnyHttpUrl(f"{_public_origin}/mcp"),
    required_scopes=None,
    client_registration_options=ClientRegistrationOptions(enabled=True),
    revocation_options=RevocationOptions(enabled=False),
)

# Let Flask reach into the provider to complete the consent flow.
attach_mcp_oauth_provider(oauth_provider)

# ----- Build the combined ASGI app ----------------------------------------

mcp_app = mcp.streamable_http_app()
oauth_asgi = WSGIMiddleware(flask_oauth_app)

# The MCP SDK auth middleware (AuthenticationMiddleware + AuthContextMiddleware)
# is registered on mcp_app at construction time; propagate it to the outer
# app so /mcp continues to see request.user. The middleware is harmless on
# Flask routes — Flask never reads request.user.
app = Starlette(
    routes=[
        # Specific MCP/OAuth routes first so they win over the Flask catch-all.
        *mcp_app.routes,
        Mount("/", app=oauth_asgi),
    ],
    middleware=mcp_app.user_middleware,
    lifespan=mcp_app.router.lifespan_context,
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
