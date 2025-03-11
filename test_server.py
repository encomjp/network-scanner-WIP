#!/usr/bin/env python3
"""
Test server to diagnose 403 errors.

This script creates a simple Flask server that logs all requests and responses.
"""

import os
import sys
import logging
import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler
from flask import Flask, request, jsonify, make_response

# Create log directory if it doesn't exist
log_dir = Path("log")
log_dir.mkdir(exist_ok=True)

# Generate timestamped log filename
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = log_dir / f"test_server_{timestamp}.log"

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
logger = logging.getLogger("test_server")
logger.info(f"Logging to file: {log_file}")

app = Flask(__name__)

@app.before_request
def log_request_info():
    """Log details about the incoming request."""
    logger.debug('Request Headers: %s', dict(request.headers))
    logger.debug('Request Method: %s', request.method)
    logger.debug('Request URL: %s', request.url)
    logger.debug('Request Remote Address: %s', request.remote_addr)
    
    # Log request body for non-GET requests
    if request.method != 'GET' and request.is_json:
        logger.debug('Request Body: %s', request.get_json())

@app.after_request
def add_cors_headers(response):
    """Add CORS headers to all responses and log response details."""
    # Log response details before adding CORS headers
    logger.debug(f"Response Status before CORS: {response.status_code}")
    logger.debug(f"Response Headers before CORS: {dict(response.headers)}")
    
    # Add CORS headers
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Log final response headers after adding CORS headers
    logger.debug(f"Response Status after CORS: {response.status_code}")
    logger.debug(f"Response Headers after CORS: {dict(response.headers)}")
    
    # Log detailed information for 4xx and 5xx responses
    if 400 <= response.status_code < 600:
        logger.warning(f"Response failed with status {response.status_code}")
        logger.warning(f"Request URL: {request.url}")
        logger.warning(f"Request Method: {request.method}")
        logger.warning(f"Request Headers: {dict(request.headers)}")
        logger.warning(f"Response Headers: {dict(response.headers)}")
        
    return response

@app.route('/')
def index():
    """Test endpoint that returns a success response."""
    logger.info("Index endpoint called")
    return jsonify({"success": True, "message": "Test server is running"})

@app.route('/api/health')
def health():
    """Test health endpoint that returns a success response."""
    logger.info("Health endpoint called")
    return jsonify({"success": True, "message": "Test server is healthy"})

@app.route('/api/error')
def error():
    """Test endpoint that returns a 403 error."""
    logger.info("Error endpoint called")
    response = jsonify({"success": False, "message": "Access forbidden"})
    response.status_code = 403
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Log all exceptions."""
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    logger.error(f"Request URL: {request.url}")
    logger.error(f"Request Method: {request.method}")
    logger.error(f"Request Headers: {dict(request.headers)}")
    
    # Return a generic error response
    response = jsonify({
        "success": False,
        "message": "An internal server error occurred."
    })
    response.status_code = 500
    return response

@app.errorhandler(403)
def handle_forbidden(e):
    """Log 403 errors."""
    logger.warning(f"403 Forbidden: {str(e)}")
    logger.warning(f"Request URL: {request.url}")
    logger.warning(f"Request Method: {request.method}")
    logger.warning(f"Request Headers: {dict(request.headers)}")
    
    # Return a more helpful error response
    response = jsonify({
        "success": False,
        "message": "Access forbidden. This may be due to CORS restrictions or insufficient permissions."
    })
    response.status_code = 403
    return response

if __name__ == '__main__':
    logger.info("Starting test server on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=True) 