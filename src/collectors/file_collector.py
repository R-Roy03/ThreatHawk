"""
File Collector - Monitors file system for suspicious changes.

Detects:
- New suspicious files (.exe, .bat, .ps1 etc)
- Modified critical files
- Files created in temp directories

This is how EDR tools catch malware being downloaded!
"""

import os
from pathlib import Path

from src.collectors.base_collector import BaseCollector
from src.core.constants import (
    EventType,
    Severity,
    SUSPICIOUS_EXTENSIONS,
)
from src.utils.helpers import now_utc, generate_id, calculate_file_hash


class FileCollector(BaseCollector):
    """Monitors file system for suspicious activity."""

    def __init__(self, interval: int = 15, watch_paths: list[str] | None = None):
        super().__init__(interval=interval)

        # Default paths to watch (Windows friendly)
        if watch_paths is None:
            self.watch_paths = [
                os.path.expanduser("~/Downloads"),
                os.environ.get("TEMP", "C:\\Temp"),
            ]
        else:
            self.watch_paths = watch_paths

        # Store file hashes to detect changes
        self.known_files: dict[str, str] = {}

    def get_name(self) -> str:
        return "File"

    async def collect(self) -> list[dict]:
        """
        Scan watched directories for suspicious files.

        Returns list of suspicious events found.
        """
        events = []

        for watch_path in self.watch_paths:
            path = Path(watch_path)

            if not path.exists():
                continue

            try:
                for file_path in path.iterdir():
                    # Skip directories, only check files
                    if not file_path.is_file():
                        continue

                    # Check 1: Suspicious extension?
                    ext_event = self._check_extension(file_path)
                    if ext_event:
                        events.append(ext_event)

                    # Check 2: File modified?
                    change_event = self._check_file_change(file_path)
                    if change_event:
                        events.append(change_event)

            except PermissionError:
                self.logger.warning(f"No permission to scan: {watch_path}")
                continue

        return events

    def _check_extension(self, file_path: Path) -> dict | None:
        """Check if file has a suspicious extension."""
        extension = file_path.suffix.lower()

        if extension in SUSPICIOUS_EXTENSIONS:
            # Only alert for NEW files (not already known)
            file_key = str(file_path)
            if file_key in self.known_files:
                return None

            self.logger.warning(
                f"SUSPICIOUS FILE: {file_path.name}"
            )

            # Remember this file so we don't alert again
            try:
                self.known_files[file_key] = calculate_file_hash(file_path)
            except Exception:
                self.known_files[file_key] = "unknown"

            return {
                "id": generate_id(),
                "event_type": EventType.FILE_CHANGE.value,
                "severity": Severity.HIGH.value,
                "title": f"Suspicious file found: {file_path.name}",
                "description": f"File with suspicious extension '{extension}' found at {file_path}",
                "source": self.get_name(),
                "file_path": str(file_path),
                "threat_score": 0.7,
                "created_at": now_utc().isoformat(),
                "raw_data": {
                    "filename": file_path.name,
                    "extension": extension,
                    "size_bytes": file_path.stat().st_size,
                    "directory": str(file_path.parent),
                },
            }

        return None

    def _check_file_change(self, file_path: Path) -> dict | None:
        """Detect if a known file has been modified."""
        file_key = str(file_path)

        # Skip if file is not being tracked yet
        if file_key not in self.known_files:
            return None

        try:
            current_hash = calculate_file_hash(file_path)
        except Exception:
            return None

        old_hash = self.known_files[file_key]

        # Hash changed = file was modified!
        if current_hash != old_hash:
            self.logger.warning(
                f"FILE MODIFIED: {file_path.name}"
            )

            # Update stored hash
            self.known_files[file_key] = current_hash

            return {
                "id": generate_id(),
                "event_type": EventType.FILE_CHANGE.value,
                "severity": Severity.MEDIUM.value,
                "title": f"File modified: {file_path.name}",
                "description": f"File hash changed for {file_path}",
                "source": self.get_name(),
                "file_path": str(file_path),
                "threat_score": 0.5,
                "created_at": now_utc().isoformat(),
                "raw_data": {
                    "filename": file_path.name,
                    "old_hash": old_hash,
                    "new_hash": current_hash,
                },
            }

        return None