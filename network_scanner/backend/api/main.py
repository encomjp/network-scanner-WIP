"""
API server entry point.

This module provides an entry point for running the API server.
"""

import uvicorn
import argparse
import logging
import sys
import os
import traceback
import importlib
import socket
import time
from network_scanner.core.logging_setup import setup_logging, get_logger
from network_scanner.backend.api.routes import (
    network_routes,
    scan_routes,
    device_routes,
    service_routes,
    health,
)

logger = get_logger(__name__)

def check_dependencies():
    """Check if all required dependencies are installed."""
    required_packages = [
        "fastapi", "uvicorn", "pydantic", "starlette"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.error(f"Missing required dependencies: {', '.join(missing_packages)}")
        logger.error("Please install them using: pip install " + " ".join(missing_packages))
        return False
    
    return True

def check_port_available(host, port):
    """Check if the specified port is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            return True
    except socket.error:
        return False

def main():
    """Run the API server."""
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description="Network Scanner API Server")
        parser.add_argument(
            "--host", 
            type=str, 
            default="127.0.0.1", 
            help="Host to bind the server to"
        )
        parser.add_argument(
            "--port", 
            type=int, 
            default=8000, 
            help="Port to bind the server to"
        )
        parser.add_argument(
            "--reload", 
            action="store_true", 
            help="Enable auto-reload for development"
        )
        parser.add_argument(
            "--debug", 
            action="store_true", 
            help="Enable debug mode"
        )
        
        args = parser.parse_args()
        
        # Setup logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        setup_logging(log_level=log_level, log_to_console=True)
        
        # Check dependencies
        if not check_dependencies():
            sys.exit(1)
        
        # Check if port is available
        if not check_port_available(args.host, args.port):
            logger.error(f"Port {args.port} is already in use. Please choose a different port.")
            sys.exit(1)
        
        logger.info(f"Starting Network Scanner API server on {args.host}:{args.port}")
        logger.info(f"Debug mode: {'enabled' if args.debug else 'disabled'}")
        logger.info(f"Auto-reload: {'enabled' if args.reload else 'disabled'}")
        
        # Set environment variables for the server
        os.environ["API_HOST"] = args.host
        os.environ["API_PORT"] = str(args.port)
        os.environ["API_DEBUG"] = "true" if args.debug else "false"
        
        # Run the server with exception handling
        try:
            uvicorn.run(
                "network_scanner.backend.api.server:app",
                host=args.host,
                port=args.port,
                reload=args.reload,
                log_level="debug" if args.debug else "info",
            )
        except Exception as e:
            logger.error(f"Error starting uvicorn server: {str(e)}")
            logger.error(traceback.format_exc())
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Unexpected error in API server startup: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main() 