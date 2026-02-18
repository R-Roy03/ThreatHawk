"""
All constants for SentinelEye Agent.

Why constants file?
- No magic numbers in code
- Change once, reflects everywhere
- Clean and professional codebase
"""

from enum import Enum


# App Info
APP_NAME = "ThreatHawk"
APP_VERSION = "1.0.0"


# Threat Severity Levels
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Alert Status
class AlertStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# Event Types
class EventType(str, Enum):
    SUSPICIOUS_PROCESS = "suspicious_process"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_CHANGE = "file_change"
    HIGH_RESOURCE = "high_resource"
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    USB_DEVICE = "usb_device"


# Suspicious Ports (hackers commonly use these)
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 12345, 9999}

# Suspicious Process Names
SUSPICIOUS_PROCESSES = {
    "mimikatz", "keylogger", "pwdump",
    "lazagne", "meterpreter", "netcat",
}

# File Extensions That Are Suspicious
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".vbs", ".dll", ".scr",
}