"""
Scan-related API endpoints.
"""

from fastapi import APIRouter, Depends, Request
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models.responses import ApiResponse

router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/discover", response_model=ApiResponse)
async def discover_devices(
    request: Request,
    scanner_service=Depends(get_scanner_service)
):
    """
    Discover devices on the network.
    
    Returns:
        ApiResponse: Response containing discovered devices.
    """
    try:
        # Get request body
        body = await request.json()
        target = body.get("target", "")
        timeout = body.get("timeout", 10)
        stealth = body.get("stealth", False)
        
        if not target:
            return ApiResponse(
                success=False,
                error="Target is required"
            )
        
        result = await scanner_service.discover_devices(
            target=target,
            timeout=timeout,
            stealth=stealth
        )
        
        return ApiResponse(
            success=True,
            message=f"Discovered {len(result)} devices",
            data=result
        )
    except Exception as e:
        return ApiResponse(
            success=False,
            error=f"Error discovering devices: {str(e)}"
        ) 