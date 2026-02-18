"""
Custom exceptions for SentinelEye Agent.

Why custom exceptions?
- Better error messages
- Easier debugging
- Catch specific errors, not generic ones
"""


class SentinelEyeError(Exception):
    """Base exception for all SentinelEye errors."""

    def __init__(self, message: str, code: str = "UNKNOWN_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)

    def __str__(self):
        return f"[{self.code}] {self.message}"


class ConfigError(SentinelEyeError):
    """Configuration file me kuch galat hai."""

    def __init__(self, message: str):
        super().__init__(message, code="CONFIG_ERROR")


class DatabaseError(SentinelEyeError):
    """Database se related koi problem."""

    def __init__(self, message: str):
        super().__init__(message, code="DB_ERROR")


class CollectorError(SentinelEyeError):
    """Data collector me koi issue."""

    def __init__(self, collector_name: str, message: str):
        self.collector_name = collector_name
        super().__init__(
            f"Collector '{collector_name}': {message}",
            code="COLLECTOR_ERROR",
        )


class AnalyzerError(SentinelEyeError):
    """Analyzer module me problem."""

    def __init__(self, analyzer_name: str, message: str):
        self.analyzer_name = analyzer_name
        super().__init__(
            f"Analyzer '{analyzer_name}': {message}",
            code="ANALYZER_ERROR",
        )


class AuthError(SentinelEyeError):
    """Authentication failure."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, code="AUTH_ERROR")