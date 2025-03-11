"""
API data models.

This module defines Pydantic models for API requests and responses.
"""

from typing import List, Optional, Union
from pydantic import BaseModel, Field


class NmapScanRequest(BaseModel):
    """Request model for Nmap scan."""
    target: str = Field(..., description="Target IP address or hostname")
    ports: Optional[str] = Field(None, description="Ports to scan (comma-separated or range)")
    vuln: bool = Field(False, description="Enable vulnerability scanning")


class DiscoverRequest(BaseModel):
    """Request model for network discovery."""
    target: str = Field(..., description="Target to scan (IP, range, or CIDR notation)")
    passive: bool = Field(False, description="Use only passive discovery methods")
    stealth: bool = Field(False, description="Use stealth mode (slower but less detectable)")
    timeout: float = Field(1.0, description="Timeout for network operations in seconds")


class PortScanRequest(BaseModel):
    """Request model for port scanning."""
    target: str = Field(..., description="Target to scan (IP or hostname)")
    ports: Optional[str] = Field(None, description="Ports to scan (comma-separated or range)")
    stealth: bool = Field(False, description="Use stealth mode (slower but less detectable)")
    timeout: float = Field(1.0, description="Timeout for network operations in seconds")
    randomize: bool = Field(False, description="Randomize the order of ports scanned")


class FingerprintRequest(BaseModel):
    """Request model for OS fingerprinting."""
    target: str = Field(..., description="Target to fingerprint (IP or hostname)")
    confidence: float = Field(0.7, description="Confidence threshold (0.0-1.0) for fingerprinting results")


class ServiceResult(BaseModel):
    """Model for service detection results."""
    ip: str
    port: int
    protocol: str
    service: Optional[str] = None
    state: str
    banner: Optional[str] = None
    timestamp: str


class DeviceResult(BaseModel):
    """Model for device discovery results."""
    ip: str
    status: str
    method: str
    timestamp: str


class FingerprintResult(BaseModel):
    """Model for fingerprinting results."""
    ip: str
    os: Optional[str] = None
    confidence: Optional[float] = None
    ttl: Optional[int] = None
    timestamp: str


class ApiResponse(BaseModel):
    """Generic API response model."""
    success: bool
    message: str
    data: Optional[Union[List[ServiceResult], List[DeviceResult], List[FingerprintResult], dict]] = None 