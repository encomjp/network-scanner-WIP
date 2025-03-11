"""
Scanner service implementation.

This module provides services for scanning operations.
"""

from typing import Dict, List, Optional, Any, Union
import logging
import datetime
import sys
import threading
import ipaddress
import queue

from network_scanner.core.logging_setup import get_logger
from network_scanner.discovery.ping_scanner import PingScanner
from network_scanner.service_detection.port_scanner import PortScanner
from network_scanner.service_detection.nmap_scanner import NmapScanner
from network_scanner.fingerprinting.ttl_analyzer import TTLAnalyzer

logger = get_logger(__name__)


class ScannerService:
    """Service for scanning operations."""

    def __init__(self):
        """Initialize the scanner service."""
        self.ping_scanner = PingScanner()
        self.port_scanner = PortScanner()
        self.nmap_scanner = NmapScanner()
        self.ttl_analyzer = TTLAnalyzer()
        self._active_scans = 0
        self._lock = threading.Lock()

    def initialize(self) -> bool:
        """Initialize all scanners."""
        try:
            self.ping_scanner.initialize({})
            self.port_scanner.initialize({})
            self.nmap_scanner.initialize({})
            self.ttl_analyzer.initialize({})
            return True
        except Exception as e:
            logger.error(f"Error initializing scanners: {str(e)}")
            return False

    def _increment_active_scans(self):
        """Increment the active scans counter."""
        with self._lock:
            self._active_scans += 1
            logger.debug(f"Active scans: {self._active_scans}")
            
    def _decrement_active_scans(self):
        """Decrement the active scans counter."""
        with self._lock:
            if self._active_scans > 0:
                self._active_scans -= 1
            logger.debug(f"Active scans: {self._active_scans}")

    def discover_devices(self, target: str, timeout: float = 1.0, stealth: bool = False) -> List[Dict[str, Any]]:
        """Discover devices on the network using ping scan."""
        try:
            self._increment_active_scans()
            
            # Check if we're on a different network than the default
            gateway = self._get_default_gateway()
            if gateway and target.startswith('192.168.1.') and not gateway.startswith('192.168.1.'):
                gateway_parts = gateway.split('.')
                if len(gateway_parts) == 4:
                    if gateway_parts[0] == '192' and gateway_parts[1] == '168' and gateway_parts[2] != '1':
                        suggested_network = f"192.168.{gateway_parts[2]}.0/24"
                        logger.info(f"Gateway detected on {gateway}, suggesting network {suggested_network} instead of {target}")
                    
            # Start the discovery process
            logger.info(f"Starting discovery on target: {target}")
            
            # Configure the scanner with the correct target
            self.ping_scanner.initialize({
                "target": target,  # Explicitly set the target
                "timeout": timeout, 
                "stealth_mode": stealth
            })
            
            # Start a thread for scanning to avoid blocking
            import threading
            import time
            import ipaddress
            import queue
            
            # Use a thread-safe queue to store results
            result_queue = queue.Queue()
            scan_complete = threading.Event()
            
            # Determine if this is a CIDR range and calculate the number of hosts
            try:
                network = ipaddress.ip_network(target, strict=False)
                num_hosts = network.num_addresses
                logger.info(f"Target {target} has {num_hosts} potential hosts")
                
                # Adjust timeout multiplier based on network size and specific networks
                if target.startswith('192.168.22.'):
                    # Special case for 192.168.22.0/24 network which needs more time
                    timeout_multiplier = 6.0
                elif num_hosts > 256:  # Larger than a /24 network
                    timeout_multiplier = 5.0
                elif num_hosts > 16:  # Larger than a /28 network
                    timeout_multiplier = 3.0
                else:
                    timeout_multiplier = 2.0
            except ValueError:
                # Not a valid CIDR, assume it's a single host
                num_hosts = 1
                timeout_multiplier = 1.5
                
            logger.info(f"Using timeout multiplier of {timeout_multiplier} for {target}")
            
            # Create a list to store partial results that can be accessed from the main thread
            partial_results = []
            partial_results_lock = threading.Lock()
            
            def scan_thread():
                try:
                    # Perform the scan
                    scan_results = self.ping_scanner.scan(target)
                    
                    # Process the results
                    for device in scan_results:
                        # Convert to dict if it's not already
                        if not isinstance(device, dict):
                            device = device.__dict__
                        
                        # Add timestamp if not present
                        if "timestamp" not in device:
                            device["timestamp"] = datetime.datetime.now().isoformat()
                            
                        # Add to result queue
                        result_queue.put(device)
                        
                        # Also add to partial results list for timeout access
                        with partial_results_lock:
                            partial_results.append(device)
                        
                    logger.info(f"Found {len(scan_results)} devices on {target}")
                except Exception as e:
                    logger.error(f"Error during discovery: {str(e)}")
                finally:
                    scan_complete.set()
                    self._decrement_active_scans()
            
            # Start the scan thread
            thread = threading.Thread(target=scan_thread)
            thread.daemon = True
            thread.start()
            
            # Wait for the scan to complete or timeout
            if not scan_complete.wait(timeout=timeout * timeout_multiplier):
                # Get any results that might be in the queue
                results = []
                try:
                    while True:
                        results.append(result_queue.get_nowait())
                except queue.Empty:
                    pass
                
                # If queue is empty, check partial_results
                if not results:
                    with partial_results_lock:
                        results = partial_results.copy()
                
                logger.warning(f"Scan timeout for {target}, returning any partial results ({len(results)} devices found so far)")
                # Don't decrement active scans here, let the thread do it when it completes
                return results
            
            # Scan completed, get all results from the queue
            results = []
            try:
                while True:
                    results.append(result_queue.get_nowait())
            except queue.Empty:
                pass
                
            return results
            
        except Exception as e:
            logger.error(f"Error during discovery: {str(e)}")
            self._decrement_active_scans()  # Ensure we decrement on error
            return []

    def _get_default_gateway(self) -> Optional[str]:
        """Try to determine the default gateway IP address."""
        try:
            # Try different methods to get the gateway
            
            # Method 1: Using netifaces (if available)
            try:
                import netifaces
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    return gateways['default'][netifaces.AF_INET][0]
            except ImportError:
                pass
            
            # Method 2: Using socket and struct (works on Linux/macOS)
            try:
                import socket
                import struct
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines():
                        fields = line.strip().split()
                        if fields[1] == '00000000':  # Destination is 0.0.0.0
                            gateway = struct.pack('<L', int(fields[2], 16))
                            return socket.inet_ntoa(gateway)
            except:
                pass
            
            # Method 3: Using route command (macOS/Linux)
            try:
                import subprocess
                if sys.platform.startswith('darwin'):  # macOS
                    output = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8')
                    for line in output.split('\n'):
                        if 'gateway:' in line:
                            return line.split('gateway:')[1].strip()
                else:  # Linux
                    output = subprocess.check_output(['ip', 'route', 'show', 'default']).decode('utf-8')
                    return output.split('via')[1].split()[0]
            except:
                pass
            
            # Method 4: Parse ifconfig/ipconfig output
            try:
                import subprocess
                if sys.platform.startswith('win'):  # Windows
                    output = subprocess.check_output(['ipconfig']).decode('utf-8')
                    for line in output.split('\n'):
                        if 'Default Gateway' in line:
                            return line.split(':')[1].strip()
                else:  # Unix-like
                    output = subprocess.check_output(['ifconfig']).decode('utf-8')
                    # This is a simplistic approach and might not work in all cases
                    for line in output.split('\n'):
                        if 'inet ' in line and 'netmask' in line and not '127.0.0.1' in line:
                            ip = line.split('inet ')[1].split()[0]
                            # Assume gateway is first IP in subnet
                            parts = ip.split('.')
                            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            except:
                pass
            
            return None
        except Exception as e:
            logger.error(f"Error determining default gateway: {str(e)}")
            return None

    def scan_ports(
        self, 
        target: str, 
        ports: Optional[Union[List[int], str]] = None,
        timeout: float = 1.0,
        stealth: bool = False,
        randomize: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan ports on the specified target."""
        self._increment_active_scans()
        try:
            logger.info(f"Starting port scan on target: {target}")
            
            # Configure the scanner
            self.port_scanner.initialize({
                "timeout": timeout,
                "stealth_mode": stealth,
                "randomize_ports": randomize
            })
            
            # Perform the scan
            results = self.port_scanner.scan(target, ports)
            
            return results
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            return []
        finally:
            self._decrement_active_scans()

    def nmap_scan(
        self, 
        target: str, 
        ports: Optional[Union[List[int], str]] = None,
        vuln: bool = False
    ) -> List[Dict[str, Any]]:
        """Perform an Nmap scan on the specified target."""
        self._increment_active_scans()
        try:
            if vuln:
                return self.nmap_scanner.scan_vulnerabilities(target, ports)
            else:
                return self.nmap_scanner.scan(target, ports)
        except Exception as e:
            logger.error(f"Error during Nmap scan: {str(e)}")
            return []
        finally:
            self._decrement_active_scans()

    def fingerprint_os(self, target: str, confidence: float = 0.7) -> Dict[str, Any]:
        """Perform OS fingerprinting on the specified target."""
        self._increment_active_scans()
        try:
            return self.ttl_analyzer.fingerprint(target)
        except Exception as e:
            logger.error(f"Error during OS fingerprinting: {str(e)}")
            return {
                "ip": target,
                "os": "Unknown",
                "confidence": 0.0,
                "ttl": None,
                "timestamp": datetime.datetime.now().isoformat()
            }
        finally:
            self._decrement_active_scans() 