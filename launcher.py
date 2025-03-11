#!/usr/bin/env python3
"""
Launcher for the Network Scanner Application.

This script concurrently launches the FastAPI backend and the Flask web frontend.

API Server (FastAPI) runs on http://127.0.0.1:8000
Web Server (Flask) runs on http://127.0.0.1:5000

Usage:
    python launcher.py
"""

import threading
import uvicorn
import time
import signal
import sys
import logging
import os
import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Create log directory if it doesn't exist
log_dir = Path("log")
log_dir.mkdir(exist_ok=True)

# Generate timestamped log filename
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = log_dir / f"{timestamp}.log"

# Configure logging to both console and file
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),  # Log to console
        RotatingFileHandler(  # Log to file
            filename=log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding='utf-8'
        )
    ]
)
logger = logging.getLogger("launcher")
logger.info(f"Logging to file: {log_file}")

# Global flags for server status
api_server_running = False
web_server_running = False
api_server_thread = None
web_server_thread = None

def start_api():
    """Start the FastAPI server."""
    global api_server_running
    try:
        # Import the FastAPI app directly to avoid module resolution issues
        from network_scanner.backend.api.server import app
        import uvicorn
        
        logger.info("Starting FastAPI server on http://127.0.0.1:8000")
        
        # Initialize the scanner service
        from network_scanner.backend.services.scanner_service import ScannerService
        scanner_service = ScannerService()
        success = scanner_service.initialize()
        logger.info(f"Scanner service initialization: {'Success' if success else 'Failed'}")
        
        # Configure Uvicorn with appropriate settings for better performance
        config = uvicorn.Config(
            app=app,
            host="127.0.0.1",
            port=8000,
            log_level="info",
            timeout_keep_alive=120,  # Increase keep-alive timeout
            workers=1,  # Single worker for development
            limit_concurrency=20,  # Increase concurrent connections limit
            timeout_graceful_shutdown=10,  # Graceful shutdown timeout
            log_config=None,  # Disable uvicorn's own logging
        )
        
        api_server_running = True
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        logger.error(f"Error starting API server: {str(e)}", exc_info=True)
        api_server_running = False
        raise

def start_web():
    """Start the Flask web server."""
    global web_server_running
    try:
        # Set environment variables for Flask
        os.environ['FLASK_APP'] = 'network_scanner.frontend.web.app'
        os.environ['FLASK_DEBUG'] = 'true'
        os.environ['API_BASE_URL'] = 'http://127.0.0.1:8000'
        os.environ['LOG_FILE'] = str(log_file)  # Pass the log file to Flask
        
        logger.info("Starting Flask web server on http://127.0.0.1:5002")
        
        # Import the Flask app
        from network_scanner.frontend.web.app import app
        
        web_server_running = True
        app.run(host="127.0.0.1", port=5002, debug=True, use_reloader=False)
    except Exception as e:
        logger.error(f"Error starting web server: {str(e)}", exc_info=True)
        web_server_running = False
        raise

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully shut down servers."""
    logger.info("Shutting down servers...")
    global api_server_running, web_server_running
    api_server_running = False
    web_server_running = False
    
    # Give servers a moment to shut down
    time.sleep(1)
    logger.info("Shutdown complete. Log file: %s", log_file)
    sys.exit(0)

if __name__ == "__main__":
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    logger.info("Starting Network Scanner...")
    
    # Start API server in a separate thread
    logger.info("Starting API server thread...")
    api_server_thread = threading.Thread(target=start_api)
    api_server_thread.daemon = True
    api_server_thread.start()
    
    # Start web server in a separate thread
    logger.info("Starting Web server thread...")
    web_server_thread = threading.Thread(target=start_web)
    web_server_thread.daemon = True
    web_server_thread.start()
    
    # Wait for API server to start
    logger.info("Waiting for API server to start...")
    time.sleep(2)
    
    # Check if API server started successfully
    if not api_server_running:
        logger.error("API server failed to start. Web server may not function correctly.")
    
    logger.info("Both servers started. Press Ctrl+C to exit.")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None) 