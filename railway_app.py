"""
Railway entry point.

Mounts the existing Flask OAuth app at / and the FastMCP server (Streamable
HTTP transport) at /mcp on the same ASGI server. Tokens are persisted to the
mounted Railway Volume so OAuth refresh survives container restarts.

The /mcp endpoint is protected by a bearer-token check against MCP_API_KEY.
The Flask OAuth surface uses Flask sessions, hardened in oauth_app.py.
"""

import hmac
import os
from urllib.parse import urlparse

from a2wsgi import WSGIMiddleware
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount

from mcp.server.transport_security import TransportSecuritySettings

from oauth_app import app as flask_oauth_app
from basecamp_fastmcp import mcp

MCP_API_KEY = os.environ.get("MCP_API_KEY")
if not MCP_API_KEY:
    raise RuntimeError(
        "MCP_API_KEY environment variable is required. "
        "Generate one with: openssl rand -hex 32"
    )


def require_bearer_token(asgi_app, expected_key):
    """
    Raw ASGI middleware that requires `Authorization: Bearer <expected_key>`.

    Implemented at the ASGI layer rather than via Starlette's BaseHTTPMiddleware
    so it does not buffer streaming responses (the MCP transport streams SSE).
    """

    async def wrapper(scope, receive, send):
        if scope["type"] != "http":
            await asgi_app(scope, receive, send)
            return

        provided = None
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                provided = value.decode("latin-1", "replace")
                break

        if provided:
            scheme, _, token = provided.partition(" ")
            if scheme.lower() == "bearer" and hmac.compare_digest(
                token, expected_key
            ):
                await asgi_app(scope, receive, send)
                return

        response = JSONResponse(
            {"error": "unauthorized", "message": "Valid bearer token required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="mcp"'},
        )
        await response(scope, receive, send)

    return wrapper


# FastMCP's Streamable HTTP route lives at this path on its own Starlette app.
# Set to "/" because we mount the whole app at /mcp below.
mcp.settings.streamable_http_path = "/"

# MCP's transport security middleware validates the Host header against an
# allow-list to defend against DNS rebinding. FastMCP only auto-allows
# localhost, so we extend the list with the deployment's public host, derived
# from BASECAMP_REDIRECT_URI to avoid a second env var.
_public_host = urlparse(os.environ.get("BASECAMP_REDIRECT_URI", "")).hostname
if _public_host:
    _existing = mcp.settings.transport_security
    _allowed_hosts = list(_existing.allowed_hosts) if _existing else []
    _allowed_origins = list(_existing.allowed_origins) if _existing else []
    _allowed_hosts.extend([_public_host, f"{_public_host}:*"])
    _allowed_origins.append(f"https://{_public_host}")
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_allowed_hosts,
        allowed_origins=_allowed_origins,
    )

mcp_app = mcp.streamable_http_app()
protected_mcp_app = require_bearer_token(mcp_app, MCP_API_KEY)

# Wrap the Flask (WSGI) app so Starlette can mount it alongside the ASGI MCP app.
oauth_asgi = WSGIMiddleware(flask_oauth_app)

# The inner MCP app's lifespan must run so its session manager initialises.
app = Starlette(
    routes=[
        Mount("/mcp", app=protected_mcp_app),
        Mount("/", app=oauth_asgi),
    ],
    lifespan=mcp_app.router.lifespan_context,
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
