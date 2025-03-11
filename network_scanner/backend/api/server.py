"""
API server implementation.

This module provides a FastAPI server for the network scanner.
"""

import logging
import os
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path
from logging.handlers import RotatingFileHandler

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from network_scanner import __version__
from network_scanner.core.logging_setup import setup_logging, get_logger
from network_scanner.backend.services.scanner_service import ScannerService
from network_scanner.backend.api.models import (
    ApiResponse,
    NmapScanRequest,
    DiscoverRequest,
    PortScanRequest,
    FingerprintRequest,
)

# Setup logging
if 'LOG_FILE' in os.environ:
    log_file = os.environ['LOG_FILE']
    setup_logging(debug_mode=True, log_to_file=True, log_file=log_file)
    logger = get_logger(__name__)
    logger.info(f"API server logging to file: {log_file}")
else:
    setup_logging(debug_mode=True)
    logger = get_logger(__name__)

# Create scanner service
scanner_service = ScannerService()
scanner_service.initialize()

# Create FastAPI app
app = FastAPI(
    title="Network Scanner API",
    description="API for the Network Scanner tool",
    version=__version__,
)

# Add CORS middleware with explicit settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"],
    max_age=3600,
)

# Add CORS headers to all responses
@app.middleware("http")
async def add_cors_headers(request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "*"
    # Ensure no caching for API responses
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.get("/", response_model=ApiResponse)
async def root():
    """Root endpoint that returns basic information about the API."""
    return ApiResponse(
        success=True,
        message="Network Scanner API",
        data={"version": __version__},
    )


@app.post("/api/nmap-scan", response_model=ApiResponse)
async def nmap_scan(request: NmapScanRequest):
    """Perform an Nmap scan on the specified target."""
    try:
        results = scanner_service.nmap_scan(
            target=request.target,
            ports=request.ports,
            vuln=request.vuln
        )
        
        return ApiResponse(
            success=True,
            message=f"Nmap scan completed for {request.target}",
            data=results,
        )
    except Exception as e:
        logger.error(f"Error during Nmap scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/discover", response_model=ApiResponse)
async def discover(request: DiscoverRequest):
    """Discover devices on the network using ping scan."""
    try:
        results = scanner_service.discover_devices(
            target=request.target,
            timeout=request.timeout,
            stealth=request.stealth
        )
        
        return ApiResponse(
            success=True,
            message=f"Discovery completed for {request.target}",
            data=results,
        )
    except Exception as e:
        logger.error(f"Error during discovery: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/port-scan", response_model=ApiResponse)
async def port_scan(request: PortScanRequest):
    """Scan ports on the specified target."""
    try:
        results = scanner_service.scan_ports(
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
            stealth=request.stealth,
            randomize=request.randomize
        )
        
        return ApiResponse(
            success=True,
            message=f"Port scan completed for {request.target}",
            data=results,
        )
    except Exception as e:
        logger.error(f"Error during port scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/fingerprint", response_model=ApiResponse)
async def fingerprint(request: FingerprintRequest):
    """Perform OS fingerprinting on the specified target."""
    try:
        result = scanner_service.fingerprint_os(
            target=request.target,
            confidence=request.confidence
        )
        
        return ApiResponse(
            success=True,
            message=f"Fingerprinting completed for {request.target}",
            data=[result],  # Wrap in list to match response model
        )
    except Exception as e:
        logger.error(f"Error during fingerprinting: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health", response_model=ApiResponse)
async def health_check():
    """Health check endpoint - optimized for quick response."""
    # This is a lightweight endpoint that doesn't perform any heavy operations
    # It should respond immediately without accessing any shared resources
    
    # Check if there are any active scans by checking the scanner service state
    # but don't wait for any operations to complete
    active_operations = False
    try:
        # Non-blocking check for active operations
        if hasattr(scanner_service, '_active_scans') and scanner_service._active_scans > 0:
            active_operations = True
    except Exception:
        # Ignore any errors - health check should always respond
        pass
    
    if active_operations:
        return ApiResponse(
            success=True,
            message="API is healthy but busy",
            data={
                "status": "busy",
                "active_operations": True
            }
        )
    else:
        return ApiResponse(
            success=True,
            message="API is healthy",
            data={"status": "ok"}
        )