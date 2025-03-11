"""
API server entry point.

This module provides an entry point for running the API server.
"""

import uvicorn
import argparse
import logging
from network_scanner.core.logging_setup import setup_logging, get_logger

logger = get_logger(__name__)


def main():
    """Run the API server."""
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
    
    logger.info(f"Starting Network Scanner API server on {args.host}:{args.port}")
    
    # Run the server
    uvicorn.run(
        "network_scanner.backend.api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="debug" if args.debug else "info",
    )


if __name__ == "__main__":
    main() 