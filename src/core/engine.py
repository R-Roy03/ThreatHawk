"""
SentinelEye Engine - The Heart of the Agent.

This connects EVERYTHING together:
- Starts all collectors
- Feeds events to analyzer
- Saves results to database
- Runs continuously in background

Think of it as the MAIN CONTROL ROOM!
"""

import asyncio

from src.core.config import get_settings
from src.database.connection import db_manager
from src.collectors.process_collector import ProcessCollector
from src.collectors.network_collector import NetworkCollector
from src.collectors.file_collector import FileCollector
from src.collectors.system_collector import SystemCollector
from src.analyzers.event_analyzer import analyze_batch
from src.utils.logger import get_logger
from src.utils.helpers import get_system_info

logger = get_logger(__name__)


class SentinelEngine:
    """
    Main engine that runs the entire agent.

    Lifecycle:
    1. initialize() - Setup database, collectors
    2. start()      - Begin monitoring
    3. stop()       - Graceful shutdown
    """

    def __init__(self):
        self.is_running = False
        self.settings = get_settings()

        # Initialize all collectors
        self.collectors = {
            "process": ProcessCollector(interval=10),
            "network": NetworkCollector(interval=5),
            "file": FileCollector(interval=15),
            "system": SystemCollector(interval=10),
        }

        # Stats tracking
        self.total_events = 0
        self.total_alerts = 0

    async def initialize(self):
        """Setup everything before starting."""
        logger.info("=" * 50)
        logger.info("  SentinelEye Agent Starting...")
        logger.info("=" * 50)

        # Show system info
        info = get_system_info()
        logger.info(f"Host: {info['hostname']} | IP: {info['ip_address']}")
        logger.info(f"OS: {info['os']} | CPU: {info['cpu_count']} cores")

        # Connect to database
        await db_manager.initialize()

        logger.info("Engine initialized successfully!")

    async def start(self):
        """Start all collectors and begin monitoring."""
        self.is_running = True
        logger.info("Starting all collectors...")

        # Run all collectors together using asyncio
        tasks = [
            self._run_collector("process"),
            self._run_collector("network"),
            self._run_collector("file"),
            self._run_collector("system"),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Engine stopped.")

    async def stop(self):
        """Gracefully shutdown everything."""
        logger.info("Stopping SentinelEye Agent...")
        self.is_running = False
        await db_manager.shutdown()
        logger.info(
            f"Shutdown complete. "
            f"Total events: {self.total_events} | "
            f"Total alerts: {self.total_alerts}"
        )

    async def _run_collector(self, name: str):
        """Run a single collector in a loop."""
        collector = self.collectors[name]
        logger.info(f"  ✓ {collector.get_name()} collector started")

        while self.is_running:
            try:
                # Step 1: Collect data
                events = await collector.collect()

                if events and name != "system":
                    # Step 2: Analyze events
                    self.total_events += len(events)
                    alerts = await analyze_batch(events)
                    self.total_alerts += len(alerts)

            except Exception as e:
                logger.error(f"Collector '{name}' error: {e}")

            # Wait before next scan
            await asyncio.sleep(collector.interval)

    async def run_single_scan(self):
        """Run one scan cycle (useful for testing)."""
        await self.initialize()

        all_events = []
        for name, collector in self.collectors.items():
            if name == "system":
                continue
            events = await collector.collect()
            all_events.extend(events)

        logger.info(f"Single scan found {len(all_events)} events")

        if all_events:
            alerts = await analyze_batch(all_events)
            logger.info(f"Created {len(alerts)} alerts")

        return all_events