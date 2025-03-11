#!/usr/bin/env python3
"""
Backend Tester - A CLI tool to directly test the network scanner backend.

This tool bypasses the web interface and directly calls the backend services
to help diagnose issues with network scanning.
"""

import argparse
import sys
import logging
import json
import time
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger("backend_tester")

def test_discovery(target: str, timeout: float = 1.0, stealth: bool = False, verbose: bool = False) -> None:
    """Test device discovery functionality."""
    from network_scanner.backend.services.scanner_service import ScannerService
    
    logger.info(f"Initializing scanner service for discovery test")
    scanner = ScannerService()
    scanner.initialize()
    
    logger.info(f"Starting discovery on target: {target}")
    logger.info(f"Parameters: timeout={timeout}, stealth={stealth}")
    
    start_time = time.time()
    results = scanner.discover_devices(target, timeout, stealth)
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Discovery completed in {duration:.2f} seconds")
    
    if results:
        logger.info(f"Found {len(results)} devices:")
        for device in results:
            logger.info(f"  - {device['ip']} ({device['status']}, method: {device['method']})")
            if verbose:
                # Print all device details
                for key, value in device.items():
                    if key not in ['ip', 'status', 'method']:
                        logger.info(f"    {key}: {value}")
    else:
        logger.warning("No devices found")
    
    # Test the underlying ping scanner directly
    logger.info("\nTesting ping scanner directly:")
    from network_scanner.discovery.ping_scanner import PingScanner
    
    ping_scanner = PingScanner()
    ping_scanner.initialize({
        "timeout": timeout,
        "stealth_mode": stealth,
        "concurrent_pings": 20,
    })
    
    logger.info("Testing if target is a local network")
    is_local = ping_scanner._is_local_network(target)
    logger.info(f"Is local network: {is_local}")
    
    if is_local:
        logger.info("Testing ARP scan")
        start_time = time.time()
        arp_results = ping_scanner._perform_arp_scan(target)
        end_time = time.time()
        
        logger.info(f"ARP scan completed in {end_time - start_time:.2f} seconds")
        if arp_results:
            logger.info(f"ARP scan found {len(arp_results)} devices:")
            for device in arp_results:
                logger.info(f"  - {device['ip']} (method: {device['method']})")
                if 'mac' in device:
                    logger.info(f"    MAC: {device['mac']}")
                if 'hostname' in device:
                    logger.info(f"    Hostname: {device['hostname']}")
        else:
            logger.warning("ARP scan found no devices")
    
    # Test gateway detection
    logger.info("\nTesting gateway detection:")
    gateway = scanner._get_default_gateway()
    if gateway:
        logger.info(f"Detected gateway: {gateway}")
    else:
        logger.warning("Could not detect gateway")
    
    # Try to ping common gateway addresses
    logger.info("\nTesting common gateway addresses:")
    common_gateways = []
    
    # Extract network prefix from target
    if '/' in target:
        network_prefix = target.split('/')[0]
    else:
        network_prefix = target
    
    if '.' in network_prefix:
        parts = network_prefix.split('.')
        if len(parts) == 4:
            # Test common gateway patterns
            common_gateways = [
                f"{parts[0]}.{parts[1]}.{parts[2]}.1",
                f"{parts[0]}.{parts[1]}.{parts[2]}.254",
                f"{parts[0]}.{parts[1]}.{parts[2]}.100"
            ]
    
    if not common_gateways:
        common_gateways = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
    
    for gw in common_gateways:
        logger.info(f"Testing {gw}...")
        is_alive = ping_scanner._is_ip_alive(gw)
        logger.info(f"  {gw} is {'alive' if is_alive else 'not responding'}")

def test_port_scan(target: str, ports: str = "22,80,443", timeout: float = 1.0, verbose: bool = False) -> None:
    """Test port scanning functionality."""
    from network_scanner.backend.services.scanner_service import ScannerService
    
    logger.info(f"Initializing scanner service for port scan test")
    scanner = ScannerService()
    scanner.initialize()
    
    logger.info(f"Starting port scan on target: {target}")
    logger.info(f"Ports: {ports}, timeout: {timeout}")
    
    start_time = time.time()
    results = scanner.scan_ports(target, ports, timeout)
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Port scan completed in {duration:.2f} seconds")
    
    if results:
        logger.info(f"Found {len(results)} open ports:")
        for service in results:
            logger.info(f"  - {service['ip']}:{service['port']} ({service['protocol']}, {service['state']})")
            if service.get('service'):
                logger.info(f"    Service: {service['service']}")
            if verbose and service.get('banner'):
                logger.info(f"    Banner: {service['banner']}")
    else:
        logger.warning("No open ports found")

def test_nmap_scan(target: str, ports: str = "22,80,443", vuln: bool = False, verbose: bool = False) -> None:
    """Test Nmap scanning functionality."""
    from network_scanner.backend.services.scanner_service import ScannerService
    
    logger.info(f"Initializing scanner service for Nmap scan test")
    scanner = ScannerService()
    scanner.initialize()
    
    logger.info(f"Starting Nmap scan on target: {target}")
    logger.info(f"Ports: {ports}, vulnerability scan: {vuln}")
    
    start_time = time.time()
    results = scanner.nmap_scan(target, ports, vuln)
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Nmap scan completed in {duration:.2f} seconds")
    
    if results:
        logger.info(f"Found {len(results)} services:")
        for service in results:
            logger.info(f"  - {service['ip']}:{service['port']} ({service['protocol']}, {service['state']})")
            if service.get('service'):
                logger.info(f"    Service: {service['service']}")
            if verbose:
                if service.get('version'):
                    logger.info(f"    Version: {service['version']}")
                if service.get('product'):
                    logger.info(f"    Product: {service['product']}")
                if service.get('vulnerabilities'):
                    logger.info(f"    Vulnerabilities: {len(service['vulnerabilities'])}")
                    for vuln in service['vulnerabilities']:
                        logger.info(f"      - {vuln['id']}: {vuln['description']}")
    else:
        logger.warning("No services found")

def test_fingerprint(target: str, confidence: float = 0.7, verbose: bool = False) -> None:
    """Test OS fingerprinting functionality."""
    from network_scanner.backend.services.scanner_service import ScannerService
    
    logger.info(f"Initializing scanner service for fingerprinting test")
    scanner = ScannerService()
    scanner.initialize()
    
    logger.info(f"Starting OS fingerprinting on target: {target}")
    logger.info(f"Confidence threshold: {confidence}")
    
    start_time = time.time()
    result = scanner.fingerprint_os(target, confidence)
    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Fingerprinting completed in {duration:.2f} seconds")
    
    if result:
        logger.info(f"Fingerprinting result for {result.get('ip', target)}:")
        if result.get('os'):
            logger.info(f"  OS: {result['os']}")
        if result.get('confidence'):
            logger.info(f"  Confidence: {result['confidence']}")
        if result.get('ttl'):
            logger.info(f"  TTL: {result['ttl']}")
        if verbose and result.get('details'):
            logger.info(f"  Details: {result['details']}")
    else:
        logger.warning("No fingerprinting results")

def main():
    """Main entry point for the backend tester."""
    parser = argparse.ArgumentParser(description="Network Scanner Backend Tester")
    
    # Common arguments
    parser.add_argument("--target", "-t", required=True, help="Target to scan (IP, range, or CIDR notation)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Discovery command
    discover_parser = subparsers.add_parser("discover", help="Test device discovery")
    discover_parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds")
    discover_parser.add_argument("--stealth", action="store_true", help="Use stealth mode")
    
    # Port scan command
    portscan_parser = subparsers.add_parser("portscan", help="Test port scanning")
    portscan_parser.add_argument("--ports", "-p", default="22,80,443", help="Ports to scan (comma-separated or range)")
    portscan_parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds")
    
    # Nmap scan command
    nmap_parser = subparsers.add_parser("nmap", help="Test Nmap scanning")
    nmap_parser.add_argument("--ports", "-p", default="22,80,443", help="Ports to scan (comma-separated or range)")
    nmap_parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning")
    
    # Fingerprint command
    fingerprint_parser = subparsers.add_parser("fingerprint", help="Test OS fingerprinting")
    fingerprint_parser.add_argument("--confidence", type=float, default=0.7, help="Confidence threshold (0.0-1.0)")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == "discover":
            test_discovery(args.target, args.timeout, args.stealth, args.verbose)
        elif args.command == "portscan":
            test_port_scan(args.target, args.ports, args.timeout, args.verbose)
        elif args.command == "nmap":
            test_nmap_scan(args.target, args.ports, args.vuln, args.verbose)
        elif args.command == "fingerprint":
            test_fingerprint(args.target, args.confidence, args.verbose)
    except Exception as e:
        logger.error(f"Error during test: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main() 