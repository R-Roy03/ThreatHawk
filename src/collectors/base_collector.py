"""
Base Collector - Abstract class for all collectors.

Why abstract class?
- Forces all collectors to follow same structure
- Common logic ek jagah likhte hai
- New collector banana easy ho jata hai

Every collector (process, network, file) inherits from this.
"""

import asyncio
from abc import ABC, abstractmethod

from src.utils.logger import get_logger


class BaseCollector(ABC):
    """
    Blueprint for all data collectors.
    
    Every collector MUST implement:
    - collect() -> actually gather data
    - get_name() -> return collector name
    """

    def __init__(self, interval: int = 10):
        self.interval = interval
        self.is_running = False
        self.logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def collect(self) -> list[dict]:
        """
        Collect data and return list of events.
        
        Each child class implements this differently:
        - ProcessCollector checks running processes
        - NetworkCollector checks connections
        - FileCollector checks file changes
        """
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Return the name of this collector."""
        pass

    async def start(self):
        """Start collecting data in a loop."""
        self.is_running = True
        self.logger.info(f"{self.get_name()} collector started!")

        while self.is_running:
            try:
                events = await self.collect()
                if events:
                    self.logger.info(
                        f"{self.get_name()}: Found {len(events)} events"
                    )
            except Exception as e:
                self.logger.error(f"{self.get_name()} error: {e}")

            await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop the collector."""
        self.is_running = False
        self.logger.info(f"{self.get_name()} collector stopped.")