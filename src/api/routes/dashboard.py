"""
Dashboard Route - Serves the HTML dashboard page.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard" / "templates"


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard page."""
    html_path = TEMPLATES_DIR / "base.html"

    if not html_path.exists():
        return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    return HTMLResponse(html_content)