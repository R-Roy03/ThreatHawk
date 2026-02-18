"""
Logging setup for SentinelEye Agent.

Uses Python's built-in logging + Rich for beautiful output.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler

from src.core.config import get_settings

_is_setup_done = False


def setup_logging():
    """Configure logging. Call once at app startup."""
    global _is_setup_done

    if _is_setup_done:
        return

    settings = get_settings()

    # Create logs folder if not exists
    log_path = Path(settings.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.log_level.upper()))
    root_logger.handlers.clear()

    # Console handler (pretty output)
    console_handler = RichHandler(
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
    )
    console_handler.setLevel(getattr(logging, settings.log_level.upper()))
    root_logger.addHandler(console_handler)

    # File handler (rotating log files)
    file_handler = RotatingFileHandler(
        filename=settings.log_file,
        maxBytes=50 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_format = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)

    _is_setup_done = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for any module.

    Usage:
        logger = get_logger(__name__)
        logger.info("Agent started")
    """
    setup_logging()
    return logging.getLogger(name)