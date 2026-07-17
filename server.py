import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

DOCS_DIR = Path(__file__).parent / "docs"
API_KEY = os.environ.get("MCP_API_KEY", "changeme")

mcp = FastMCP("MyPrivateDocs")


def _list_docs() -> dict:
    return {p.stem: p.name for p in sorted(DOCS_DIR.glob("*.md"))}


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


class ApiKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Accept the key either as a header (for clients that support it)
        # or as a ?key= query param (for the Claude.ai connector URL field).
        supplied = request.headers.get("x-api-key") or request.query_params.get("key")
        if supplied != API_KEY:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


# FastMCP's ASGI app for streamable HTTP, wrapped with our auth check
app = mcp.streamable_http_app()
app.add_middleware(ApiKeyMiddleware)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
