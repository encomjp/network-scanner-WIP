"""
Ping Scanner - ICMP-based network discovery.

This module discovers network devices using ICMP echo requests (ping).
"""

import ipaddress
import logging
import subprocess
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from network_scanner.core.scheduler import scheduler
from network_scanner.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)

class PingScanner(DiscoveryModule):
    """Discover network devices using ICMP ping."""
    
    def __init__(self):
        """Initialize the ping scanner."""
        super().__init__()
        self.target = None
        self.timeout = 1
        self.count = 1
        self.interval = 300  # 5 minutes between scans
        self.task_id = None
        self.concurrent_pings = 10
        self.stealth_mode = False
        self.stealth_delay = 0.5
        logger.debug("PingScanner initialized")
        
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the ping scanner with configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.target = config.get('target', '192.168.1.0/24')
            self.timeout = config.get('timeout', 1)
            self.count = config.get('count', 1)
            self.interval = config.get('interval', 300)
            self.concurrent_pings = config.get('concurrent_pings', 10)
            self.stealth_mode = config.get('stealth_mode', False)
            self.stealth_delay = config.get('stealth_delay', 0.5)
            
            logger.info(f"PingScanner initialized with target: {self.target}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing PingScanner: {e}")
            return False
            
    def start(self) -> bool:
        """
        Start periodic scanning.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("PingScanner already running")
            return False
            
        try:
            # Schedule periodic scanning
            self.task_id = scheduler.schedule(
                func=self.scan,
                interval=self.interval,
                args=[self.target],
                name="PingScanner"
            )
            
            self.running = True
            logger.info(f"PingScanner started with interval {self.interval}s")
            
            # Execute first scan immediately
            threading.Thread(target=self.scan, args=[self.target]).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting PingScanner: {e}")
            return False
            
    def stop(self) -> bool:
        """
        Stop periodic scanning.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("PingScanner not running")
            return False
            
        try:
            if self.task_id is not None:
                scheduler.remove_task(self.task_id)
                self.task_id = None
                
            self.running = False
            logger.info("PingScanner stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping PingScanner: {e}")
            return False
            
    def _is_ip_alive(self, ip: str) -> bool:
        """
        Check if an IP address responds to ping.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if the IP responds to ping, False otherwise
        """
        try:
            # Use different ping command based on platform
            import platform
            
            if platform.system().lower() == "windows":
                command = ["ping", "-n", str(self.count), "-w", str(self.timeout * 1000), ip]
            else:  # Linux, Darwin (macOS), etc.
                command = ["ping", "-c", str(self.count), "-W", str(self.timeout), ip]
                
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout + 1
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.debug(f"Error pinging {ip}: {e}")
            return False
            
    def scan(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan the network for devices using ICMP ping.
        
        Args:
            target: Target to scan (IP, range, or CIDR notation)
            
        Returns:
            List of discovered devices
        """
        if target is None:
            target = self.target
            
        logger.info(f"Starting ping scan of {target}")
        self.last_scan_time = datetime.now()
        
        try:
            # Parse the target
            if '/' in target:  # CIDR notation
                network = ipaddress.ip_network(target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            elif '-' in target:  # Range notation (e.g., 192.168.1.1-192.168.1.10)
                start_ip, end_ip = target.split('-')
                start_parts = [int(p) for p in start_ip.split('.')]
                end_parts = [int(p) for p in end_ip.split('.')]
                
                # Simple case: only last octet differs
                if start_parts[:3] == end_parts[:3]:
                    ip_prefix = '.'.join(str(p) for p in start_parts[:3]) + '.'
                    ip_list = [ip_prefix + str(i) for i in range(start_parts[3], end_parts[3] + 1)]
                else:
                    raise ValueError(f"Complex IP ranges not supported: {target}")
            else:  # Single IP
                ip_list = [target]
                
            # Scan the IPs
            results = []
            
            if self.stealth_mode:
                # Sequential scanning with delays
                for ip in ip_list:
                    if self._is_ip_alive(ip):
                        results.append({
                            "ip": ip,
                            "timestamp": datetime.utcnow().isoformat(),
                            "method": "ping",
                            "status": "up"
                        })
                    time.sleep(self.stealth_delay)
            else:
                # Concurrent scanning with thread pool
                from concurrent.futures import ThreadPoolExecutor
                
                with ThreadPoolExecutor(max_workers=self.concurrent_pings) as executor:
                    # Submit all tasks
                    future_to_ip = {executor.submit(self._is_ip_alive, ip): ip for ip in ip_list}
                    
                    # Process results as they complete
                    for future in future_to_ip:
                        ip = future_to_ip[future]
                        try:
                            is_alive = future.result()
                            if is_alive:
                                results.append({
                                    "ip": ip,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "method": "ping",
                                    "status": "up"
                                })
                        except Exception as e:
                            logger.error(f"Error scanning {ip}: {e}")
            
            logger.info(f"Ping scan completed. Found {len(results)} active devices")
            self.last_scan_results = results
            
            # Publish the results
            self.publish_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during ping scan: {e}")
            return []
            
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this discovery module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        try:
            # Check if it's a valid IP address
            if '/' in target:  # CIDR notation
                ipaddress.ip_network(target, strict=False)
            elif '-' in target:  # Range notation
                start_ip, end_ip = target.split('-')
                ipaddress.ip_address(start_ip)
                ipaddress.ip_address(end_ip)
            else:  # Single IP
                ipaddress.ip_address(target)
                
            return True
            
        except ValueError:
            return False 