"""
Port Scanner - TCP port scanning for service detection.

This module scans network hosts for open TCP ports to detect running services.
"""

import logging
import random
import socket
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from network_scanner.core.scheduler import scheduler
from network_scanner.service_detection.base import ServiceDetectionModule

logger = logging.getLogger(__name__)

# Common service port mappings
COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5900: "vnc",
    8080: "http-proxy"
}

class PortScanner(ServiceDetectionModule):
    """Scan for open TCP ports to detect services."""
    
    def __init__(self):
        """Initialize the port scanner."""
        super().__init__()
        self.target = None
        self.ports = None
        self.timeout = 1.0
        self.interval = 3600  # 1 hour between scans
        self.task_id = None
        self.concurrent_scans = 50
        self.stealth_mode = False
        self.stealth_delay = 0.2
        self.randomize_ports = False
        logger.debug("PortScanner initialized")
        
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the port scanner with configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.target = config.get('target')
            self.ports = self.parse_port_specification(config.get('ports'))
            self.timeout = config.get('timeout', 1.0)
            self.interval = config.get('interval', 3600)
            self.concurrent_scans = config.get('concurrent_scans', 50)
            self.stealth_mode = config.get('stealth_mode', False)
            self.stealth_delay = config.get('stealth_delay', 0.2)
            self.randomize_ports = config.get('randomize_ports', False)
            
            if self.target:
                logger.info(f"PortScanner initialized with target: {self.target}")
            else:
                logger.info("PortScanner initialized without target")
                
            return True
            
        except Exception as e:
            logger.error(f"Error initializing PortScanner: {e}")
            return False
            
    def start(self) -> bool:
        """
        Start periodic scanning if a target is configured.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("PortScanner already running")
            return False
            
        if not self.target:
            logger.warning("Cannot start PortScanner without a target")
            return False
            
        try:
            # Schedule periodic scanning
            self.task_id = scheduler.schedule(
                func=self.scan,
                interval=self.interval,
                args=[self.target],
                name="PortScanner"
            )
            
            self.running = True
            logger.info(f"PortScanner started with interval {self.interval}s")
            
            # Execute first scan immediately
            threading.Thread(target=self.scan, args=[self.target]).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting PortScanner: {e}")
            return False
            
    def stop(self) -> bool:
        """
        Stop periodic scanning.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("PortScanner not running")
            return False
            
        try:
            if self.task_id is not None:
                scheduler.remove_task(self.task_id)
                self.task_id = None
                
            self.running = False
            logger.info("PortScanner stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping PortScanner: {e}")
            return False
            
    def _check_port(self, ip: str, port: int) -> Tuple[bool, Optional[str]]:
        """
        Check if a TCP port is open.
        
        Args:
            ip: IP address to check
            port: Port number to check
            
        Returns:
            Tuple of (is_open, service_banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((ip, port))
            is_open = (result == 0)
            
            banner = None
            
            if is_open:
                try:
                    # Try to get a banner
                    sock.settimeout(0.5)
                    # Send a simple HTTP request for port 80 and 443
                    if port in (80, 443, 8080):
                        sock.send(b"GET / HTTP/1.0\r\n\r\n")
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except (socket.timeout, ConnectionRefusedError):
                    pass
                
            sock.close()
            return (is_open, banner)
            
        except Exception as e:
            logger.debug(f"Error checking port {port} on {ip}: {e}")
            return (False, None)
            
    def scan(self, target: str, ports: Optional[Union[List[int], str]] = None) -> List[Dict[str, Any]]:
        """
        Scan the target for open ports and services.
        
        Args:
            target: Target to scan (IP or hostname)
            ports: Optional ports to scan (list of ints or comma-separated string)
            
        Returns:
            List of discovered services
        """
        logger.info(f"Starting port scan of {target}")
        self.last_scan_time = datetime.now()
        
        try:
            # Resolve hostname to IP if needed
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return []
                
            # Parse ports if provided, otherwise use configured ports
            if ports is not None:
                port_set = self.parse_port_specification(ports)
            else:
                port_set = self.ports if self.ports else self.parse_port_specification(None)
                
            # Convert to list and potentially randomize
            port_list = list(port_set)
            if self.randomize_ports:
                random.shuffle(port_list)
                
            results = []
            
            if self.stealth_mode:
                # Sequential scanning with delays
                for port in port_list:
                    is_open, banner = self._check_port(ip, port)
                    if is_open:
                        service_name = COMMON_SERVICES.get(port, f"unknown-{port}")
                        results.append({
                            "ip": ip,
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": service_name,
                            "banner": banner,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                    time.sleep(self.stealth_delay)
            else:
                # Concurrent scanning with thread pool
                from concurrent.futures import ThreadPoolExecutor
                
                with ThreadPoolExecutor(max_workers=self.concurrent_scans) as executor:
                    # Submit all tasks
                    future_to_port = {executor.submit(self._check_port, ip, port): port for port in port_list}
                    
                    # Process results as they complete
                    for future in future_to_port:
                        port = future_to_port[future]
                        try:
                            is_open, banner = future.result()
                            if is_open:
                                service_name = COMMON_SERVICES.get(port, f"unknown-{port}")
                                results.append({
                                    "ip": ip,
                                    "port": port,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": service_name,
                                    "banner": banner,
                                    "timestamp": datetime.utcnow().isoformat()
                                })
                        except Exception as e:
                            logger.error(f"Error scanning port {port} on {ip}: {e}")
            
            logger.info(f"Port scan completed. Found {len(results)} open ports on {ip}")
            self.last_scan_results = results
            
            # Publish the results
            self.publish_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during port scan: {e}")
            return []
            
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this service detection module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        try:
            # Check if it's a valid hostname or IP
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False 