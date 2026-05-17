"""
Railway entry point.

Mounts the existing Flask OAuth app at / and the FastMCP server (Streamable
HTTP transport) at /mcp on the same ASGI server. Tokens are persisted to the
mounted Railway Volume so OAuth refresh survives container restarts.
"""

import os

from a2wsgi import WSGIMiddleware
from starlette.applications import Starlette
from starlette.routing import Mount

from oauth_app import app as flask_oauth_app
from basecamp_fastmcp import mcp

# FastMCP's Streamable HTTP route lives at this path on its own Starlette app.
# Set to "/" because we mount the whole app at /mcp below.
mcp.settings.streamable_http_path = "/"
mcp_app = mcp.streamable_http_app()

# Wrap the Flask (WSGI) app so Starlette can mount it alongside the ASGI MCP app.
oauth_asgi = WSGIMiddleware(flask_oauth_app)

# The inner MCP app's lifespan must run so its session manager initialises.
app = Starlette(
    routes=[
        Mount("/mcp", app=mcp_app),
        Mount("/", app=oauth_asgi),
    ],
    lifespan=mcp_app.router.lifespan_context,
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
