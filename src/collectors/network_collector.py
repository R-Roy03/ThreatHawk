"""
Network Collector - Monitors all network connections.

Detects:
- Connections to suspicious ports
- Unusual number of connections (port scan)
- Unknown external connections

This is how EDR tools detect hackers communicating with your system!
"""

import psutil
from collections import Counter

from src.collectors.base_collector import BaseCollector
from src.core.constants import (
    EventType,
    Severity,
    SUSPICIOUS_PORTS,
)
from src.utils.helpers import now_utc, generate_id


class NetworkCollector(BaseCollector):
    """Monitors network connections for suspicious activity."""

    def __init__(self, interval: int = 5):
        super().__init__(interval=interval)
        self.previous_connections = set()

    def get_name(self) -> str:
        return "Network"

    async def collect(self) -> list[dict]:
        """
        Scan all active network connections.
        
        Returns list of suspicious events found.
        """
        events = []

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.logger.warning("Need admin access for full network monitoring")
            return events

        # Track remote ports being connected to
        remote_ports = []

        for conn in connections:
            # Only check established connections
            if conn.status != "ESTABLISHED":
                continue

            # Check if connecting to suspicious port
            suspicious_event = self._check_suspicious_port(conn)
            if suspicious_event:
                events.append(suspicious_event)

            # Collect remote ports for port scan detection
            if conn.raddr:
                remote_ports.append(conn.raddr.port)

        # Check for port scanning behavior
        scan_event = self._check_port_scan(remote_ports)
        if scan_event:
            events.append(scan_event)

        return events

    def _check_suspicious_port(self, conn) -> dict | None:
        """Check if connection uses a known suspicious port."""

        # Check remote port (where we're connecting TO)
        if conn.raddr:
            remote_port = conn.raddr.port
            remote_ip = conn.raddr.ip

            if remote_port in SUSPICIOUS_PORTS:
                self.logger.warning(
                    f"SUSPICIOUS PORT: {remote_ip}:{remote_port}"
                )
                return {
                    "id": generate_id(),
                    "event_type": EventType.NETWORK_ANOMALY.value,
                    "severity": Severity.HIGH.value,
                    "title": f"Connection to suspicious port {remote_port}",
                    "description": f"Outgoing connection to {remote_ip}:{remote_port}",
                    "source": self.get_name(),
                    "source_ip": conn.laddr.ip if conn.laddr else None,
                    "destination_ip": remote_ip,
                    "process_id": conn.pid,
                    "threat_score": 0.8,
                    "created_at": now_utc().isoformat(),
                    "raw_data": {
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote": f"{remote_ip}:{remote_port}",
                        "status": conn.status,
                        "pid": conn.pid,
                    },
                }

        # Check local port (what's listening on our machine)
        if conn.laddr:
            local_port = conn.laddr.port

            if local_port in SUSPICIOUS_PORTS:
                return {
                    "id": generate_id(),
                    "event_type": EventType.NETWORK_ANOMALY.value,
                    "severity": Severity.CRITICAL.value,
                    "title": f"Suspicious port {local_port} is active",
                    "description": f"Local machine listening on suspicious port {local_port}",
                    "source": self.get_name(),
                    "source_ip": conn.laddr.ip,
                    "threat_score": 0.85,
                    "created_at": now_utc().isoformat(),
                    "raw_data": {
                        "local": f"{conn.laddr.ip}:{local_port}",
                        "status": conn.status,
                        "pid": conn.pid,
                    },
                }

        return None

    def _check_port_scan(self, remote_ports: list) -> dict | None:
        """
        Detect port scanning behavior.
        
        If someone is connecting to many different ports
        in short time = likely a port scan!
        """
        if len(remote_ports) < 20:
            return None

        unique_ports = set(remote_ports)

        # If connecting to 20+ unique ports = suspicious
        if len(unique_ports) >= 20:
            self.logger.warning(
                f"POSSIBLE PORT SCAN: {len(unique_ports)} unique ports"
            )
            return {
                "id": generate_id(),
                "event_type": EventType.PORT_SCAN.value,
                "severity": Severity.HIGH.value,
                "title": f"Possible port scan detected ({len(unique_ports)} ports)",
                "description": f"System connecting to {len(unique_ports)} unique ports",
                "source": self.get_name(),
                "threat_score": 0.7,
                "created_at": now_utc().isoformat(),
                "raw_data": {
                    "unique_ports": len(unique_ports),
                    "total_connections": len(remote_ports),
                },
            }

        return None