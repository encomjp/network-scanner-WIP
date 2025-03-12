"""
Health check API endpoints for monitoring the API server status.
"""

import time
from fastapi import APIRouter, Depends, Request
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models.responses import ApiResponse

# Get version from package or set a default
try:
    from network_scanner import __version__
except ImportError:
    __version__ = "1.0.0"

router = APIRouter(prefix="/health", tags=["health"])

@router.get("/", response_model=ApiResponse)
async def health_check(
    request: Request,
    scanner_service=Depends(get_scanner_service)
):
    """
    Check the health status of the API server.
    
    Returns:
        ApiResponse: Response containing the health status of the API server.
    """
    # Check if the scanner service is initialized
    initialized = scanner_service.is_initialized()
    
    # Get the status of the scanner service
    if not initialized:
        status = "initializing"
    else:
        status = "ok"
    
    # Get uptime information
    start_time = getattr(request.app.state, "start_time", time.time())
    uptime = time.time() - start_time
    
    # Get active scans and queue size
    active_scans = getattr(scanner_service, "_active_scans", 0)
    queue_size = 0
    if hasattr(scanner_service, "_scan_queue"):
        try:
            queue_size = scanner_service._scan_queue.qsize()
        except:
            pass
    
    # Check scanner availability
    scanners = {}
    if initialized:
        for scanner_type in ['network', 'ping', 'port', 'nmap', 'ttl']:
            try:
                scanner = scanner_service._get_scanner(scanner_type)
                scanners[scanner_type] = "available" if scanner else "unavailable"
            except:
                scanners[scanner_type] = "error"
    
    return ApiResponse(
        success=True,
        message=f"API is {'operational' if initialized else 'initializing'}",
        data={
            "status": status,
            "initialized": initialized,
            "version": __version__,
            "timestamp": time.time(),
            "uptime": uptime,
            "active_scans": active_scans,
            "queue_size": queue_size,
            "scanners": scanners
        }
    ) 