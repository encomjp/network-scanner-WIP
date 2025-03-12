"""
API server implementation.

This module provides a FastAPI server for the network scanner.
"""

import logging
import os
import sys
import time
import asyncio
import traceback
from typing import Dict, List, Optional, Any
from pathlib import Path
from logging.handlers import RotatingFileHandler
import datetime

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from network_scanner import __version__
from network_scanner.core.logging_setup import setup_logging, get_logger
from network_scanner.backend.services.scanner_service import ScannerService
from network_scanner.backend.api.dependencies import get_scanner_service
from network_scanner.backend.api.models import (
    ApiResponse,
    NmapScanRequest,
    DiscoverRequest,
    PortScanRequest,
    FingerprintRequest,
    NetworkInfoResult,
)
from network_scanner.backend.api.routes import (
    network_routes,
    scan_routes,
    device_routes,
    service_routes,
    health,
)
from network_scanner.core.network_detector import NetworkDetector

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
scanner_service = get_scanner_service()

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

# Add Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

class RequestMonitorMiddleware(BaseHTTPMiddleware):
    """Middleware to monitor request timing and add request ID."""
    
    async def dispatch(self, request: Request, call_next):
        request_id = str(time.time())
        start_time = time.time()
        
        # Add request ID to logger context
        logger.debug(f"Processing request {request_id}: {request.method} {request.url.path}")
        
        try:
            response = await call_next(request)
            
            # Add timing headers
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Request-ID"] = request_id
            
            logger.debug(f"Request {request_id} completed in {process_time:.3f}s")
            return response
            
        except Exception as e:
            logger.error(f"Error processing request {request_id}: {str(e)}")
            logger.error(traceback.format_exc())
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": str(e),
                    "request_id": request_id
                }
            )

# Add request monitoring
app.add_middleware(RequestMonitorMiddleware)

# Include API routers
app.include_router(network_routes.router, prefix="/api")
app.include_router(scan_routes.router, prefix="/api")
app.include_router(device_routes.router, prefix="/api")
app.include_router(service_routes.router, prefix="/api")
app.include_router(health.router, prefix="/api")

# Store startup time
app.state.start_time = time.time()
app.state.initialized = False

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    try:
        logger.info("Initializing API server...")
        
        # Initialize scanner service with retry
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                success = await scanner_service.initialize()
                if success:
                    app.state.initialized = True
                    logger.info("API server started successfully")
                    break
                else:
                    logger.error("Failed to initialize scanner service, retrying...")
                    retry_count += 1
                    await asyncio.sleep(2)  # Wait before retrying
            except Exception as e:
                logger.error(f"Error during scanner service initialization: {e}")
                logger.error(traceback.format_exc())
                retry_count += 1
                await asyncio.sleep(2)  # Wait before retrying
        
        if not app.state.initialized:
            logger.error("Failed to initialize scanner service after multiple retries")
            # Don't exit here, let the server start anyway and handle errors at runtime
    except Exception as e:
        logger.error(f"Unexpected error during startup: {e}")
        logger.error(traceback.format_exc())

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    try:
        # Cancel any pending tasks
        if hasattr(scanner_service, '_scan_processor_task'):
            scanner_service._scan_processor_task.cancel()
            try:
                await scanner_service._scan_processor_task
            except asyncio.CancelledError:
                pass
        
        # Clear any queued scans
        if hasattr(scanner_service, '_scan_queue'):
            while not scanner_service._scan_queue.empty():
                try:
                    scanner_service._scan_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
        
        logger.info("API server shutdown complete")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
        logger.error(traceback.format_exc())

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
        if not app.state.initialized:
            return ApiResponse(
                success=False,
                error="API server is still initializing. Please try again in a moment."
            )
            
        results = await scanner_service.nmap_scan(
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
        logger.error(traceback.format_exc())
        return ApiResponse(success=False, error=str(e))

@app.post("/api/discover", response_model=ApiResponse)
async def discover_devices(request: DiscoverRequest) -> ApiResponse:
    """Discover devices on the network."""
    try:
        # Log the incoming request
        logger.info(f"[DEBUG] Received discover request: target={request.target}, timeout={request.timeout}, stealth={request.stealth}, passive={request.passive}")
        
        if not app.state.initialized:
            logger.warning(f"[DEBUG] API server not initialized, rejecting discover request for {request.target}")
            return ApiResponse(
                success=False,
                error="API server is still initializing. Please try again in a moment."
            )
        
        logger.info(f"[DEBUG] Processing discover request for target: {request.target}")
        
        # Call the scanner service
        devices = await scanner_service.discover_devices(
            target=request.target,
            timeout=request.timeout,
            stealth=request.stealth,
            passive=request.passive
        )
        
        # Log the response
        logger.info(f"[DEBUG] Discover request completed for {request.target}, found {len(devices)} devices")
        
        return ApiResponse(success=True, data=devices)
    except Exception as e:
        logger.error(f"[DEBUG] Error processing discover request for {request.target}: {e}")
        logger.error(traceback.format_exc())
        return ApiResponse(success=False, error=str(e))

@app.post("/api/port-scan", response_model=ApiResponse)
async def port_scan(request: PortScanRequest):
    """Scan ports on the specified target."""
    try:
        if not app.state.initialized:
            return ApiResponse(
                success=False,
                error="API server is still initializing. Please try again in a moment."
            )
            
        results = await scanner_service.scan_ports(
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
        logger.error(traceback.format_exc())
        return ApiResponse(success=False, error=str(e))

@app.post("/api/fingerprint", response_model=ApiResponse)
async def fingerprint(request: FingerprintRequest):
    """Perform OS fingerprinting on the specified target."""
    try:
        if not app.state.initialized:
            return ApiResponse(
                success=False,
                error="API server is still initializing. Please try again in a moment."
            )
            
        result = await scanner_service.fingerprint_os(
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
        logger.error(traceback.format_exc())
        return ApiResponse(success=False, error=str(e))

@app.get("/api/network-info", response_model=ApiResponse)
async def get_network_info(request: Request) -> ApiResponse:
    """Get network information."""
    try:
        if not app.state.initialized:
            return ApiResponse(
                success=False,
                error="API server is still initializing. Please try again in a moment."
            )
            
        result = await scanner_service.get_network_info()
        return ApiResponse(success=True, data=result)
    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        logger.error(traceback.format_exc())
        return ApiResponse(success=False, error=str(e))
