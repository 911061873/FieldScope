from __future__ import annotations

import uvicorn

from fieldscope.core.config import get_settings


def main() -> None:
    """CLI entry point to start the FieldScope FastAPI server."""
    settings = get_settings()
    uvicorn.run(
        "fieldscope.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
