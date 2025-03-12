"""
API request models.

This module contains the request models for the API.
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class NmapScanRequest(BaseModel):
    """
    Request model for Nmap scan.
    """
    
    target: str = Field(
        ...,
        description="The target to scan. Can be a single IP, a CIDR range, or a hostname."
    )
    ports: Optional[str] = Field(
        None,
        description="The ports to scan. Can be a single port, a range (e.g., 1-1000), or a comma-separated list."
    )
    vuln: Optional[bool] = Field(
        False,
        description="Whether to scan for vulnerabilities."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "target": "192.168.1.0/24",
                "ports": "22,80,443",
                "vuln": False
            }
        }


class DiscoverRequest(BaseModel):
    """
    Request model for device discovery.
    """
    
    target: str = Field(
        ...,
        description="The target to scan. Can be a single IP, a CIDR range, or a hostname."
    )
    method: Optional[str] = Field(
        "ping",
        description="The discovery method to use. Can be 'ping', 'arp', or 'all'."
    )
    timeout: Optional[float] = Field(
        1.0,
        description="The timeout in seconds for each scan."
    )
    stealth: Optional[bool] = Field(
        False,
        description="Whether to use stealth scanning techniques."
    )
    passive: Optional[bool] = Field(
        False,
        description="Whether to use only passive discovery methods."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "target": "192.168.1.0/24",
                "method": "ping",
                "timeout": 1.0,
                "stealth": False,
                "passive": False
            }
        }


class PortScanRequest(BaseModel):
    """
    Request model for port scan.
    """
    
    target: str = Field(
        ...,
        description="The target to scan. Can be a single IP, a CIDR range, or a hostname."
    )
    ports: Optional[str] = Field(
        None,
        description="The ports to scan. Can be a single port, a range (e.g., 1-1000), or a comma-separated list."
    )
    timeout: Optional[float] = Field(
        1.0,
        description="The timeout in seconds for each scan."
    )
    stealth: Optional[bool] = Field(
        False,
        description="Whether to use stealth scanning techniques."
    )
    randomize: Optional[bool] = Field(
        False,
        description="Whether to randomize the port scan order."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "target": "192.168.1.1",
                "ports": "1-1000",
                "timeout": 1.0,
                "stealth": False,
                "randomize": False
            }
        }


class FingerprintRequest(BaseModel):
    """
    Request model for OS fingerprinting.
    """
    
    target: str = Field(
        ...,
        description="The target to fingerprint. Can be a single IP or a hostname."
    )
    confidence: Optional[float] = Field(
        0.7,
        description="The minimum confidence level for OS detection."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "target": "192.168.1.1",
                "confidence": 0.7
            }
        }


class NetworkInfoResult(BaseModel):
    """
    Result model for network information.
    """
    
    interfaces: List[Dict[str, Any]] = Field(
        ...,
        description="List of network interfaces."
    )
    default_gateway: Optional[Dict[str, Any]] = Field(
        None,
        description="Default gateway information."
    )
    recommended_targets: Optional[List[str]] = Field(
        None,
        description="Recommended targets for scanning."
    )
    
    class Config:
        """Pydantic model configuration."""
        
        schema_extra = {
            "example": {
                "interfaces": [
                    {
                        "name": "eth0",
                        "ip": "192.168.1.100",
                        "network": "192.168.1.0/24"
                    }
                ],
                "default_gateway": {
                    "ip": "192.168.1.1",
                    "interface": "eth0"
                },
                "recommended_targets": [
                    "192.168.1.0/24"
                ]
            }
        } 