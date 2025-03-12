"""
Service-related API endpoints.
"""

from fastapi import APIRouter, Depends, Request
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models.responses import ApiResponse

router = APIRouter(prefix="/services", tags=["services"])

@router.post("/port-scan", response_model=ApiResponse)
async def port_scan(
    request: Request,
    scanner_service=Depends(get_scanner_service)
):
    """
    Scan ports on a target.
    
    Returns:
        ApiResponse: Response containing port scan results.
    """
    try:
        # Get request body
        body = await request.json()
        target = body.get("target", "")
        ports = body.get("ports", "1-1000")
        timeout = body.get("timeout", 10)
        stealth = body.get("stealth", False)
        randomize = body.get("randomize", False)
        
        if not target:
            return ApiResponse(
                success=False,
                error="Target is required"
            )
        
        result = await scanner_service.scan_ports(
            target=target,
            ports=ports,
            timeout=timeout,
            stealth=stealth,
            randomize=randomize
        )
        
        return ApiResponse(
            success=True,
            message=f"Port scan completed for {target}",
            data=result
        )
    except Exception as e:
        return ApiResponse(
            success=False,
            error=f"Error scanning ports: {str(e)}"
        ) 