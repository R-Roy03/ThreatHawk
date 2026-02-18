"""
FastAPI Application - The API server for ThreatHawk.

This is the entry point for the REST API.
Frontend/Dashboard calls these endpoints to get data.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.database.connection import db_manager
from src.api.routes.routes import router
from src.api.routes.dashboard import router as dashboard_router
from src.utils.logger import get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ThreatHawk API starting...")
    await db_manager.initialize()
    logger.info("API ready!")
    
    yield
    
    await db_manager.shutdown()
    logger.info("API stopped.")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="ThreatHawk",
        description="AI-Powered Endpoint Detection & Response",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register routes
    app.include_router(router, prefix="/api")
    app.include_router(dashboard_router)

    @app.get("/")
    async def root():
        return {
            "name": "ThreatHawk",
            "status": "running",
            "version": "1.0.0",
        }

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    return app


app = create_app()