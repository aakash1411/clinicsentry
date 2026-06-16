"""Shared helper: detect whether a Docker daemon is reachable.

Tests using testcontainers should skip — not error — when the local Docker
daemon isn't running, so a developer can still run the rest of the suite
without spinning up Docker Desktop.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path


def docker_daemon_reachable() -> bool:
    """Return True if a Docker daemon (or compatible socket) is reachable."""
    # Honor explicit DOCKER_HOST first.
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("tcp://"):
        try:
            host_only = host.removeprefix("tcp://").split("/")[0]
            hostname, _, port = host_only.partition(":")
            with socket.create_connection((hostname, int(port or 2375)), timeout=1):
                return True
        except OSError:
            return False
    # Default to the Unix socket.
    socket_paths = [
        host.removeprefix("unix://") if host.startswith("unix://") else None,
        "/var/run/docker.sock",
        str(Path.home() / ".docker" / "run" / "docker.sock"),
        str(Path.home() / ".colima" / "docker.sock"),
    ]
    for path in filter(None, socket_paths):
        if Path(path).exists():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    sock.connect(path)
                    return True
            except OSError:
                continue
    return False
