"""
Helper functions used across the entire project.

Small reusable functions that prevent code duplication.
"""

import hashlib
import math
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psutil


def now_utc() -> datetime:
    """Get current time in UTC."""
    return datetime.now(timezone.utc)


def generate_id() -> str:
    """Generate a unique ID."""
    return str(uuid.uuid4())


def get_system_info() -> dict:
    """Collect basic system information."""
    return {
        "hostname": socket.gethostname(),
        "os": __import__("platform").system(),
        "cpu_count": psutil.cpu_count(),
        "total_memory_gb": round(
            psutil.virtual_memory().total / (1024 ** 3), 2
        ),
        "ip_address": _get_local_ip(),
    }


def _get_local_ip() -> str:
    """Get machine's local IP address."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return "127.0.0.1"


def calculate_file_hash(file_path: str | Path) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    
    High entropy = encrypted/compressed data (suspicious!)
    Low entropy = normal text
    """
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    length = len(data)
    entropy = 0.0

    for count in byte_counts:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def format_bytes(num_bytes: int | float) -> str:
    """Convert bytes to human-readable format."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"