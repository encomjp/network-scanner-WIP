"""
Web UI application.

This module provides a Flask web application for the network scanner.
"""

import os
import json
import requests
import datetime
import logging
import sys
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_cors import CORS
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Get the log file from the environment or use a default
log_dir = Path("log")
log_dir.mkdir(exist_ok=True)

# If no log file is specified in the environment, create a new one with timestamp
if 'LOG_FILE' not in os.environ:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_file = log_dir / f"flask_{timestamp}.log"
else:
    log_file = Path(os.environ['LOG_FILE'])

# Configure more detailed logging
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
logger = logging.getLogger('network_scanner.web')
logger.info(f"Flask application logging to file: {log_file}")

app = Flask(__name__)

# Configure CORS - make it completely permissive again
CORS(app, 
    resources={"*": {"origins": "*"}},  # Allow all origins
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"]
)

# Configuration
API_BASE_URL = os.environ.get('API_BASE_URL', 'http://127.0.0.1:8000')

# Log all requests for debugging
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

def proxy_request(method, path, json=None):
    """Generic proxy function for API requests."""
    try:
        headers = {
            "Content-Type": "application/json",
            "Origin": request.headers.get("Origin", "http://127.0.0.1:5000"),
            "Access-Control-Request-Method": method,
            "Access-Control-Request-Headers": "Content-Type, Authorization, X-Requested-With, Accept"
        }
        
        url = f"{API_BASE_URL}{path}"
        logger.debug(f"Sending {method} request to {url}")
        logger.debug(f"Request Headers: {headers}")
        if json:
            logger.debug(f"Request Body: {json}")
        
        # Use different timeouts based on the endpoint
        if path == "/api/health":
            timeout = 3  # Quick timeout for health checks (reduced from 5)
        elif path == "/api/discover" or path == "/api/port-scan":
            timeout = 30  # Longer timeout for scanning operations
        else:
            timeout = 10  # Default timeout
        
        # For OPTIONS requests, don't send a body
        if method == "OPTIONS":
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=timeout
            )
        else:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                timeout=timeout
            )
        
        logger.debug(f"API Response Status: {response.status_code}")
        logger.debug(f"API Response Headers: {dict(response.headers)}")
        
        # Log detailed information for 4xx and 5xx responses
        if 400 <= response.status_code < 600:
            logger.warning(f"API request failed with status {response.status_code}")
            logger.warning(f"Request URL: {url}")
            logger.warning(f"Request Method: {method}")
            logger.warning(f"Request Headers: {headers}")
            if json:
                logger.warning(f"Request Body: {json}")
            logger.warning(f"Response Headers: {dict(response.headers)}")
            try:
                response_body = response.json()
                logger.warning(f"Response Body: {response_body}")
            except:
                logger.warning(f"Response Text: {response.text}")
        
        # Try to parse the response as JSON
        try:
            data = response.json()
            logger.debug(f"API Response Body: {data}")
            return data, response.status_code
        except ValueError:
            logger.error(f"Invalid JSON response: {response.text}")
            return {"success": False, "message": "Invalid JSON response from API"}, 500
            
    except requests.exceptions.Timeout:
        logger.warning(f"API request timed out: {path}")
        
        # Special handling for discovery operation timeout
        if path == "/api/discover" and json and "target" in json:
            target = json.get("target", "")
            # Return a fallback response for discovery
            return {
                "success": True,
                "message": f"Discovery in progress for {target}. Results will be available soon.",
                "data": [{
                    "ip": target.split("/")[0].strip(),  # Extract the base IP from CIDR notation
                    "status": "pending",
                    "method": "fallback",
                    "timestamp": datetime.datetime.now().isoformat()
                }]
            }, 200
        
        # Special handling for health check timeout
        if path == "/api/health":
            return {
                "success": True,
                "message": "API server is busy but responding",
                "data": {
                    "status": "busy",
                    "active_operations": True
                }
            }, 200
            
        return {"success": False, "message": f"Request timed out. The API server might be busy or not running."}, 504
        
    except requests.exceptions.ConnectionError:
        logger.warning(f"API connection error: {path}")
        return {"success": False, "message": "Could not connect to API server. Please check if it's running."}, 503
        
    except Exception as e:
        logger.error(f"API request error: {str(e)}", exc_info=True)
        return {"success": False, "message": f"Error: {str(e)}"}, 500

@app.route('/api/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
def api_proxy(path):
    """API proxy endpoint with detailed request and response logging."""
    logger.debug(f"API proxy request for path: /api/{path}")
    logger.debug(f"API proxy request method: {request.method}")
    logger.debug(f"API proxy request headers: {dict(request.headers)}")
    
    if request.method == 'OPTIONS':
        logger.debug("Handling OPTIONS request in api_proxy")
        response = make_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'
        response.headers['Access-Control-Allow-Headers'] = '*'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        logger.debug(f"OPTIONS response headers: {dict(response.headers)}")
        return response
    
    # Log request body for non-GET requests
    request_body = None
    if request.method != 'GET' and request.is_json:
        request_body = request.get_json(silent=True)
        logger.debug(f"API proxy request body: {request_body}")
        
    # Forward the request to the API server
    data, status_code = proxy_request(
        method=request.method,
        path=f"/api/{path}",
        json=request_body
    )
    
    logger.debug(f"API proxy response status: {status_code}")
    logger.debug(f"API proxy response data: {data}")
    
    response = jsonify(data)
    response.status_code = status_code
    
    # Add CORS headers explicitly to this response
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    logger.debug(f"Final API proxy response headers: {dict(response.headers)}")
    
    # Log detailed information for 4xx and 5xx responses
    if 400 <= status_code < 600:
        logger.warning(f"API proxy response failed with status {status_code}")
        logger.warning(f"Failed request URL: {request.url}")
        logger.warning(f"Failed request method: {request.method}")
        logger.warning(f"Failed request headers: {dict(request.headers)}")
        if request_body:
            logger.warning(f"Failed request body: {request_body}")
        logger.warning(f"Failed response data: {data}")
    
    return response

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/discover')
def discover_page():
    """Render the device discovery page."""
    return render_template('discover.html')

@app.route('/services')
def services_page():
    """Render the port scanning page."""
    return render_template('services.html')

@app.route('/fingerprint')
def fingerprint_page():
    """Render the fingerprinting page."""
    return render_template('fingerprint.html')

@app.route('/nmap')
def nmap_page():
    """Render the Nmap scanning page."""
    return render_template('nmap.html')

@app.route('/results')
def results_page():
    """Render the results page."""
    return render_template('results.html')

@app.route('/favicon.ico')
def favicon():
    return "", 204

@app.route('/robots.txt')
def robots():
    return "", 200, {'Content-Type': 'text/plain'}

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
    
    # Ensure no caching for API responses
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
    
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

# Handle OPTIONS requests
@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    """Handle OPTIONS requests with proper CORS headers and detailed logging."""
    logger.debug(f"Handling OPTIONS request for path: /api/{path}")
    logger.debug(f"OPTIONS Request Headers: {dict(request.headers)}")
    logger.debug(f"OPTIONS Request Origin: {request.headers.get('Origin', 'No Origin')}")
    logger.debug(f"OPTIONS Request Access-Control-Request-Method: {request.headers.get('Access-Control-Request-Method', 'None')}")
    logger.debug(f"OPTIONS Request Access-Control-Request-Headers: {request.headers.get('Access-Control-Request-Headers', 'None')}")
    
    response = make_response()
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    logger.debug(f"OPTIONS Response Headers: {dict(response.headers)}")
    return response

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint that checks the API server status with detailed logging."""
    logger.debug("Health check request received")
    logger.debug(f"Health check request headers: {dict(request.headers)}")
    
    try:
        logger.debug("Forwarding health check request to API server")
        data, status_code = proxy_request("GET", "/api/health")
        logger.debug(f"Health check response status: {status_code}")
        logger.debug(f"Health check response data: {data}")
        
        # If we got a response but it indicates a warning
        if status_code == 200 and data.get("success") and data.get("data", {}).get("status") == "warning":
            logger.warning("API health check returned a warning")
            response = jsonify(data)
            response.headers['Access-Control-Allow-Origin'] = '*'
            logger.debug(f"Health check warning response headers: {dict(response.headers)}")
            return response, 200
            
        # If we got a successful response
        if status_code == 200 and data.get("success"):
            logger.debug("API health check successful")
            response = jsonify(data)
            response.headers['Access-Control-Allow-Origin'] = '*'
            logger.debug(f"Health check success response headers: {dict(response.headers)}")
            return response, 200
            
        # If we got an error response
        logger.warning(f"API health check failed with status {status_code}")
        response = jsonify({
            "success": True,
            "message": "API server is responding but reported an error",
            "data": {
                "status": "warning",
                "warning": "API server returned an error response. Some features may not work correctly."
            }
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        logger.debug(f"Health check error response headers: {dict(response.headers)}")
        return response, 200
        
    except Exception as e:
        logger.warning(f"API health check error: {str(e)}")
        logger.exception("Health check exception details:")
        response = jsonify({
            "success": True,
            "message": "Could not connect to API server",
            "data": {
                "status": "warning",
                "warning": "Could not connect to API server. Please check if it's running."
            }
        })
        response.headers['Access-Control-Allow-Origin'] = '*'
        logger.debug(f"Health check exception response headers: {dict(response.headers)}")
        return response, 200

# Add an error handler for all exceptions
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

# Add a specific handler for 403 errors
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

def main():
    """Run the Flask application."""
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5002))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main() 