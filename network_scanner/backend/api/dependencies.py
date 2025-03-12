"""
API dependencies for FastAPI.

This module provides dependencies for FastAPI routes.
"""

from fastapi import Depends
from network_scanner.backend.services.scanner_service import ScannerService

# Global scanner service instance
_scanner_service = None

def get_scanner_service() -> ScannerService:
    """
    Get the scanner service instance.
    
    This is a dependency that can be injected into FastAPI routes.
    
    Returns:
        ScannerService: The scanner service instance.
    """
    global _scanner_service
    
    if _scanner_service is None:
        _scanner_service = ScannerService()
    
    return _scanner_service 