"""
Network-related API endpoints.
"""

from fastapi import APIRouter, Depends, Request
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models.responses import ApiResponse

router = APIRouter(prefix="/network-info", tags=["network"])

@router.get("/", response_model=ApiResponse)
async def get_network_info(
    request: Request,
    scanner_service=Depends(get_scanner_service)
):
    """
    Get network information.
    
    Returns:
        ApiResponse: Response containing network information.
    """
    try:
        result = await scanner_service.get_network_info()
        return ApiResponse(
            success=True,
            message="Network information retrieved successfully",
            data=result
        )
    except Exception as e:
        return ApiResponse(
            success=False,
            error=f"Error getting network info: {str(e)}"
        ) 