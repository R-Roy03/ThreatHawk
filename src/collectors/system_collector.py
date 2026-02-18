"""
System Collector - Monitors overall system health.

Collects:
- CPU usage
- Memory usage
- Disk usage
- Network bandwidth

This data is used for ML anomaly detection later!
"""

import psutil

from src.collectors.base_collector import BaseCollector
from src.utils.helpers import now_utc, generate_id


class SystemCollector(BaseCollector):
    """Collects system health metrics."""

    def __init__(self, interval: int = 10):
        super().__init__(interval=interval)

    def get_name(self) -> str:
        return "System"

    async def collect(self) -> list[dict]:
        """Collect current system metrics."""

        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        network = psutil.net_io_counters()

        metric = {
            "id": generate_id(),
            "cpu_percent": cpu,
            "memory_percent": memory.percent,
            "disk_percent": disk.percent,
            "network_bytes_sent": network.bytes_sent,
            "network_bytes_recv": network.bytes_recv,
            "active_processes": len(psutil.pids()),
            "created_at": now_utc().isoformat(),
        }

        self.logger.info(
            f"CPU: {cpu}% | RAM: {memory.percent}% | Disk: {disk.percent}%"
        )

        return [metric]