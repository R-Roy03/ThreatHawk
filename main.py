"""
ThreatHawk - Main Entry Point

Run the entire application:
    python main.py

This starts:
    1. API Server (FastAPI)
    2. Dashboard (Web UI)
    3. All monitoring in background
"""

import uvicorn

from src.core.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


def main():
    """Start ThreatHawk."""
    settings = get_settings()

    print()
    print("=" * 50)
    print("  🦅 ThreatHawk - Starting...")
    print("=" * 50)
    print(f"  Dashboard: http://localhost:{settings.api_port}/dashboard")
    print(f"  API Docs:  http://localhost:{settings.api_port}/docs")
    print(f"  Health:    http://localhost:{settings.api_port}/health")
    print("=" * 50)
    print()

    uvicorn.run(
        "src.api.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()