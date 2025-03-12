"""
API routes package.

This package contains all the API routes for the network scanner.
"""

from network_scanner.backend.api.routes import (
    network_routes,
    scan_routes,
    device_routes,
    service_routes,
    health
)

__all__ = [
    "network_routes",
    "scan_routes",
    "device_routes",
    "service_routes",
    "health"
] 