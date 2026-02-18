"""
Process Collector - Monitors all running processes.

Detects:
- Suspicious process names (mimikatz, keylogger etc)
- High CPU usage processes
- High memory usage processes

This is how real EDR tools catch malware running on system!
"""

import psutil

from src.collectors.base_collector import BaseCollector
from src.core.constants import (
    EventType,
    Severity,
    SUSPICIOUS_PROCESSES,
)
from src.utils.helpers import now_utc, generate_id


class ProcessCollector(BaseCollector):
    """Monitors running processes for suspicious activity."""

    def __init__(
        self,
        interval: int = 10,
        cpu_threshold: float = 90.0,
        memory_threshold: float = 85.0,
    ):
        super().__init__(interval=interval)
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold

    def get_name(self) -> str:
        return "Process"

    async def collect(self) -> list[dict]:
        """
        Scan all running processes and find suspicious ones.
        
        Returns list of suspicious events found.
        """
        events = []

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "username"]
        ):
            try:
                info = proc.info

                # Check 1: Is process name suspicious?
                suspicious_event = self._check_suspicious_name(info)
                if suspicious_event:
                    events.append(suspicious_event)

                # Check 2: Is CPU usage too high?
                cpu_event = self._check_high_cpu(info)
                if cpu_event:
                    events.append(cpu_event)

                # Check 3: Is memory usage too high?
                memory_event = self._check_high_memory(info)
                if memory_event:
                    events.append(memory_event)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process ended or we don't have permission
                continue

        return events

    def _check_suspicious_name(self, info: dict) -> dict | None:
        """Check if process name matches known malicious tools."""
        process_name = (info.get("name") or "").lower()

        for suspicious in SUSPICIOUS_PROCESSES:
            if suspicious in process_name:
                self.logger.warning(
                    f"SUSPICIOUS PROCESS: {info['name']} (PID: {info['pid']})"
                )
                return {
                    "id": generate_id(),
                    "event_type": EventType.SUSPICIOUS_PROCESS.value,
                    "severity": Severity.CRITICAL.value,
                    "title": f"Suspicious process detected: {info['name']}",
                    "description": f"Process '{info['name']}' matches known threat tool '{suspicious}'",
                    "source": self.get_name(),
                    "process_name": info["name"],
                    "process_id": info["pid"],
                    "threat_score": 0.9,
                    "created_at": now_utc().isoformat(),
                    "raw_data": info,
                }

        return None

    def _check_high_cpu(self, info: dict) -> dict | None:
        """Detect processes using too much CPU."""
        cpu = info.get("cpu_percent") or 0.0

        if cpu > self.cpu_threshold:
            return {
                "id": generate_id(),
                "event_type": EventType.HIGH_RESOURCE.value,
                "severity": Severity.MEDIUM.value,
                "title": f"High CPU usage: {info['name']} ({cpu}%)",
                "description": f"Process '{info['name']}' using {cpu}% CPU",
                "source": self.get_name(),
                "process_name": info["name"],
                "process_id": info["pid"],
                "threat_score": 0.4,
                "created_at": now_utc().isoformat(),
                "raw_data": info,
            }

        return None

    def _check_high_memory(self, info: dict) -> dict | None:
        """Detect processes using too much memory."""
        memory = info.get("memory_percent") or 0.0

        if memory > self.memory_threshold:
            return {
                "id": generate_id(),
                "event_type": EventType.HIGH_RESOURCE.value,
                "severity": Severity.MEDIUM.value,
                "title": f"High memory usage: {info['name']} ({memory:.1f}%)",
                "description": f"Process '{info['name']}' using {memory:.1f}% memory",
                "source": self.get_name(),
                "process_name": info["name"],
                "process_id": info["pid"],
                "threat_score": 0.3,
                "created_at": now_utc().isoformat(),
                "raw_data": info,
            }

        return None