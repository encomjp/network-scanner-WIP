"""
API data models.

This module defines Pydantic models for API requests and responses.
"""

import ipaddress
from typing import List, Optional, Union, Dict
from pydantic import BaseModel, Field, validator


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


class NetworkInfoResult(BaseModel):
    """Model for network information results."""
    interfaces: List[Dict] = Field(
        ...,
        description="List of network interfaces with their properties",
        example=[{
            "name": "eth0",
            "ip": "192.168.1.100",
            "netmask": "255.255.255.0",
            "network": "192.168.1.0/24"
        }]
    )
    default_gateway: Optional[Dict] = Field(
        None,
        description="Default gateway information",
        example={"ip": "192.168.1.1", "interface": "eth0"}
    )
    routing: List[Dict] = Field(
        ...,
        description="Network routing information",
        example=[{"network": "192.168.1.0/24"}]
    )
    connected_networks: List[str] = Field(
        ...,
        description="List of directly connected networks in CIDR notation",
        example=["192.168.1.0/24", "10.0.0.0/24"]
    )
    recommended_targets: List[str] = Field(
        ...,
        description="List of recommended networks to scan",
        example=["192.168.1.0/24"]
    )
    nmap: Optional[Dict] = Field(
        None,
        description="Additional network information from nmap scans"
    )

    @validator('interfaces')
    def validate_interfaces(cls, v):
        for iface in v:
            if 'name' not in iface:
                raise ValueError("Interface must have a name")
            if 'ip' not in iface:
                raise ValueError(f"Interface {iface['name']} must have an IP")
        return v

    @validator('connected_networks', 'recommended_targets')
    def validate_network_cidrs(cls, v):
        for network in v:
            try:
                ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid network CIDR: {network} - {str(e)}")
        return v

    @validator('default_gateway')
    def validate_gateway(cls, v):
        if v is not None:
            if 'ip' not in v:
                raise ValueError("Gateway must have an IP address")
            try:
                ipaddress.ip_address(v['ip'])
            except ValueError as e:
                raise ValueError(f"Invalid gateway IP: {v['ip']} - {str(e)}")
        return v

class ApiResponse(BaseModel):
    """Generic API response model."""
    success: bool
    message: str
    data: Optional[Union[List[ServiceResult], List[DeviceResult], List[FingerprintResult], NetworkInfoResult, dict]] = None
