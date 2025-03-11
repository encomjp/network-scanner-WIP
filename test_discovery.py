#!/usr/bin/env python3
import sys
import time
import logging
from network_scanner.discovery.ping_scanner import PingScanner
from network_scanner.backend.services.scanner_service import ScannerService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger("test_discovery")

def test_ping_scanner_directly():
    """Test the ping scanner directly."""
    logger.info("Testing ping scanner directly")
    target = "192.168.31.0/24"
    timeout = 15  # Longer timeout
    
    ping_scanner = PingScanner()
    ping_scanner.initialize({
        "target": target,
        "timeout": timeout,
        "stealth_mode": False,
        "concurrent_pings": 20,
    })
    
    logger.info(f"Starting ping scan of {target}")
    start_time = time.time()
    results = ping_scanner.scan()
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Scan completed in {duration:.2f} seconds")
    
    if results:
        logger.info(f"Found {len(results)} devices:")
        for device in results:
            logger.info(f"  - {device['ip']} ({device.get('status', 'unknown')})")
    else:
        logger.warning("No devices found")
    
    return results

def test_scanner_service():
    """Test the scanner service."""
    logger.info("Testing scanner service")
    target = "192.168.31.0/24"
    timeout = 15  # Longer timeout
    
    scanner = ScannerService()
    
    logger.info(f"Starting discovery on target: {target}")
    start_time = time.time()
    results = scanner.discover_devices(target, timeout, False)
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Discovery completed in {duration:.2f} seconds")
    
    if results:
        logger.info(f"Found {len(results)} devices:")
        for device in results:
            logger.info(f"  - {device['ip']} ({device.get('status', 'unknown')})")
    else:
        logger.warning("No devices found")
    
    return results

if __name__ == "__main__":
    logger.info("=== Testing PingScanner directly ===")
    ping_results = test_ping_scanner_directly()
    
    logger.info("\n=== Testing ScannerService ===")
    service_results = test_scanner_service()
    
    logger.info("\n=== Summary ===")
    logger.info(f"PingScanner found {len(ping_results) if ping_results else 0} devices")
    logger.info(f"ScannerService found {len(service_results) if service_results else 0} devices") 