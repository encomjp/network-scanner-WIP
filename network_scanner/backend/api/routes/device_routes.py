"""
Device-related API endpoints.
"""

from fastapi import APIRouter, Depends, Request
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models.responses import ApiResponse

router = APIRouter(prefix="/devices", tags=["devices"])

@router.get("/", response_model=ApiResponse)
async def get_devices(
    request: Request,
    scanner_service=Depends(get_scanner_service)
):
    """
    Get all discovered devices.
    
    Returns:
        ApiResponse: Response containing all discovered devices.
    """
    try:
        # This is a placeholder - implement actual device retrieval based on your data model
        devices = []  # scanner_service.get_devices()
        
        return ApiResponse(
            success=True,
            message=f"Retrieved {len(devices)} devices",
            data=devices
        )
    except Exception as e:
        return ApiResponse(
            success=False,
            error=f"Error retrieving devices: {str(e)}"
        ) 