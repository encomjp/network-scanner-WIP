#!/usr/bin/env python3
"""
Network Scanner Launcher

This script launches the Network Scanner application with both the API backend
and the web frontend.
"""

import os
import sys
import time
import signal
import subprocess
import threading
import logging
import argparse
import webbrowser
import platform
import socket
import importlib
import traceback
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("launcher")

# Global variables
processes = []
stop_event = threading.Event()

def check_dependencies():
    """Check if all required dependencies are installed."""
    required_packages = [
        "fastapi", "uvicorn", "flask", "pydantic", "starlette"
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

def is_port_in_use(port, host='127.0.0.1'):
    """Check if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

def find_available_port(start_port, host='127.0.0.1'):
    """Find an available port starting from start_port."""
    port = start_port
    while is_port_in_use(port, host):
        port += 1
        if port > start_port + 100:  # Limit search to 100 ports
            raise RuntimeError(f"Could not find an available port in range {start_port}-{start_port+100}")
    return port

def check_api_health(host, port, max_retries=30, retry_interval=1):
    """Check if the API server is healthy."""
    url = f"http://{host}:{port}/api/health"
    
    logger.info(f"Checking API health at {url}...")
    
    for i in range(max_retries):
        try:
            import requests
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    status = data.get("data", {}).get("status")
                    initialized = data.get("data", {}).get("initialized", False)
                    if status == "ok" and initialized:
                        logger.info("API server is fully initialized and healthy")
                        return True
                    elif status == "initializing":
                        logger.info(f"API server is still initializing... (attempt {i+1}/{max_retries})")
                    else:
                        logger.info(f"API server status: {status} (attempt {i+1}/{max_retries})")
                else:
                    logger.warning(f"API health check returned unsuccessful response: {data.get('error', 'Unknown error')}")
            else:
                logger.warning(f"API health check failed with status code: {response.status_code} (attempt {i+1}/{max_retries})")
        except requests.RequestException as e:
            if i == 0:
                logger.debug(f"API health check failed (attempt {i+1}/{max_retries}): {str(e)}")
            elif i % 5 == 0:  # Log less frequently after the first attempt
                logger.debug(f"API health check failed (attempt {i+1}/{max_retries}): {str(e)}")
        except ImportError:
            logger.warning("Requests library not available, skipping health check")
            return True  # Assume it's healthy if we can't check
        except Exception as e:
            logger.warning(f"Unexpected error during API health check: {str(e)}")
            
        # Only sleep if we're not on the last attempt
        if i < max_retries - 1:
            time.sleep(retry_interval)
    
    logger.warning("API server health check timed out after maximum retries")
    return False

def start_backend(host, port, debug=False):
    """Start the backend API server."""
    logger.info(f"Starting backend API server on {host}:{port}")
    
    # Check if port is available
    if is_port_in_use(port, host):
        logger.warning(f"Port {port} is already in use. Finding an available port...")
        port = find_available_port(port + 1, host)
        logger.info(f"Using port {port} for backend API server")
    
    # Set environment variables
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["API_HOST"] = host
    env["API_PORT"] = str(port)
    env["API_DEBUG"] = "true" if debug else "false"
    
    # Start the backend process
    cmd = [
        sys.executable, "-m", "network_scanner.backend.api.main",
        "--host", host,
        "--port", str(port),
        "--debug" if debug else ""
    ]
    
    # Filter out empty arguments
    cmd = [arg for arg in cmd if arg]
    
    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        processes.append(process)
        
        # Start threads to monitor output
        threading.Thread(target=monitor_output, args=(process, "backend", "stdout"), daemon=True).start()
        threading.Thread(target=monitor_output, args=(process, "backend", "stderr"), daemon=True).start()
        
        # Wait for backend to start
        for _ in range(30):  # Wait up to 30 seconds
            if stop_event.is_set():
                return None
            
            if is_port_in_use(port, host):
                logger.info(f"Backend API server started successfully on {host}:{port}")
                return port
            
            time.sleep(1)
        
        logger.error("Backend API server failed to start within the timeout period")
        return None
    except Exception as e:
        logger.error(f"Error starting backend: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def start_frontend(host, port, api_port, debug=False):
    """Start the frontend web server."""
    logger.info(f"Starting frontend web server on {host}:{port}")
    
    # Check if port is available
    if is_port_in_use(port, host):
        logger.warning(f"Port {port} is already in use. Finding an available port...")
        port = find_available_port(port + 1, host)
        logger.info(f"Using port {port} for frontend web server")
    
    # Set environment variables
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    env["FLASK_HOST"] = host
    env["FLASK_PORT"] = str(port)
    env["FLASK_DEBUG"] = "true" if debug else "false"
    env["API_HOST"] = host
    env["API_PORT"] = str(api_port)
    
    # Start the frontend process
    cmd = [
        sys.executable, "-m", "network_scanner.frontend.web.app",
        "--host", host,
        "--port", str(port),
        "--debug" if debug else ""
    ]
    
    # Filter out empty arguments
    cmd = [arg for arg in cmd if arg]
    
    try:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        processes.append(process)
        
        # Start threads to monitor output
        threading.Thread(target=monitor_output, args=(process, "frontend", "stdout"), daemon=True).start()
        threading.Thread(target=monitor_output, args=(process, "frontend", "stderr"), daemon=True).start()
        
        # Wait for frontend to start
        for _ in range(30):  # Wait up to 30 seconds
            if stop_event.is_set():
                return None
            
            if is_port_in_use(port, host):
                logger.info(f"Frontend web server started successfully on {host}:{port}")
                return port
            
            time.sleep(1)
        
        logger.error("Frontend web server failed to start within the timeout period")
        return None
    except Exception as e:
        logger.error(f"Error starting frontend: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def monitor_output(process, name, stream_name):
    """Monitor process output and log it."""
    stream = process.stdout if stream_name == "stdout" else process.stderr
    prefix = f"[{name}]"
    
    while not stop_event.is_set():
        try:
            line = stream.readline()
            if not line:
                break
            
            line = line.strip()
            if line:
                if stream_name == "stderr":
                    logger.error(f"{prefix} {line}")
                else:
                    logger.info(f"{prefix} {line}")
        except Exception as e:
            logger.error(f"Error monitoring {name} {stream_name}: {str(e)}")
            break

def cleanup():
    """Clean up processes on exit."""
    logger.info("Shutting down Network Scanner...")
    
    stop_event.set()
    
    for process in processes:
        try:
            if platform.system() == "Windows":
                # On Windows, we need to use taskkill to kill the process tree
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # On Unix-like systems, we can use process groups
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except (AttributeError, ProcessLookupError):
                    pass
                process.terminate()
            
            # Wait for process to terminate
            process.wait(timeout=5)
            
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError) as e:
            logger.warning(f"Error terminating process: {e}")
            try:
                process.kill()
            except:
                pass
    
    logger.info("Network Scanner shutdown complete")

def open_browser(url):
    """Open the web browser after a short delay."""
    def _open_browser():
        time.sleep(2)  # Wait for servers to fully initialize
        logger.info(f"Opening browser at {url}")
        webbrowser.open(url)
    
    threading.Thread(target=_open_browser, daemon=True).start()

def main():
    """Main entry point for the launcher."""
    parser = argparse.ArgumentParser(description="Network Scanner Launcher")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind servers to")
    parser.add_argument("--api-port", type=int, default=8000, help="Port for the API server")
    parser.add_argument("--web-port", type=int, default=5002, help="Port for the web server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    parser.add_argument("--wait-for-api", action="store_true", help="Wait for API to fully initialize before opening browser")
    parser.add_argument("--api-timeout", type=int, default=60, help="Maximum time to wait for API initialization in seconds")
    
    args = parser.parse_args()
    
    logger.info("Starting Network Scanner...")
    logger.info(f"Debug mode: {'enabled' if args.debug else 'disabled'}")
    
    # Check dependencies
    if not check_dependencies():
        logger.error("Missing required dependencies. Please install them before running the launcher.")
        return 1
    
    try:
        # Start backend
        logger.info(f"Starting backend API server on {args.host}:{args.api_port}...")
        api_port = start_backend(args.host, args.api_port, args.debug)
        
        if not api_port:
            logger.error("Backend API server failed to start. Exiting.")
            cleanup()
            return 1
        
        logger.info(f"Backend API server started on {args.host}:{api_port}")
        
        # Start frontend
        logger.info(f"Starting frontend web server on {args.host}:{args.web_port}...")
        frontend_port = start_frontend(args.host, args.web_port, api_port, args.debug)
        
        if not frontend_port:
            logger.error("Frontend web server failed to start. Exiting.")
            cleanup()
            return 1
        
        logger.info(f"Frontend web server started on {args.host}:{frontend_port}")
        
        # Wait for API to fully initialize if requested
        if args.wait_for_api:
            logger.info(f"Waiting for API server to fully initialize (timeout: {args.api_timeout}s)...")
            api_ready = check_api_health(args.host, api_port, max_retries=args.api_timeout, retry_interval=1)
            
            if api_ready:
                logger.info("API server is fully initialized and ready")
            else:
                logger.warning("API server initialization timed out, but continuing anyway")
                logger.warning("Some features may not work until the API is fully initialized")
        
        # Open browser if requested
        if not args.no_browser:
            url = f"http://{args.host}:{frontend_port}"
            logger.info(f"Opening browser at {url}")
            open_browser(url)
        
        logger.info(f"Network Scanner is running!")
        logger.info(f"API server: http://{args.host}:{api_port}")
        logger.info(f"Web interface: http://{args.host}:{frontend_port}")
        logger.info("Press Ctrl+C to exit")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
            # Check if processes are still running
            for process in processes[:]:
                if process.poll() is not None:
                    logger.error(f"Process exited with code {process.returncode}")
                    processes.remove(process)
            
            if not processes:
                logger.error("All processes have exited. Shutting down.")
                break
            
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        cleanup()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 