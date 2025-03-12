"""
Ping Scanner - ICMP and ARP-based network discovery.

This module discovers network devices using a combination of ICMP echo requests (ping)
and ARP requests for more reliable device discovery.
"""

import datetime
import logging
import random
import threading
import time
from typing import Any, Dict, List, Optional
import concurrent.futures

from network_scanner.core.scheduler import scheduler
from network_scanner.discovery.base import DiscoveryModule
from network_scanner.discovery.scanners.arp_scanner import ARPScanner
from network_scanner.discovery.utils.network import parse_target, is_local_network
from network_scanner.discovery.utils.platform import ping

logger = logging.getLogger(__name__)

class PingScanner(DiscoveryModule):
    """Discover network devices using ICMP ping and ARP."""
    
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
        self.arp_scanner = ARPScanner()
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
            
            # Initialize ARP scanner with our timeout
            self.arp_scanner = ARPScanner(timeout=self.timeout)
            
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
            
    def scan(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan the target network for alive hosts using ICMP ping and ARP.
        
        Args:
            target: Target to scan (IP, range, or CIDR notation). If None, use the initialized target.
            
        Returns:
            List of dictionaries containing information about discovered devices.
        """
        try:
            # Use the provided target or fall back to the initialized one
            if target is None:
                target = self.target
                
            if not target:
                logger.error("No target specified for scan")
                return []
                
            logger.info(f"Starting network scan of {target}")
            
            # Reset results for this scan
            self.results = []
            
            # Check if this is a local network
            is_local = is_local_network(target)
            logger.info(f"Target {target} is {'a local' if is_local else 'not a local'} network")
            
            # For local networks, perform ARP scan first
            if is_local:
                logger.info(f"Performing ARP scan on local network {target}")
                arp_results = self.arp_scanner.scan(target)
                
                # Add ARP results to our results list
                if arp_results:
                    logger.info(f"ARP scan found {len(arp_results)} devices")
                    self.results.extend(arp_results)
                    
                    # If we're scanning 192.168.22.0/24, add a small delay to allow for more results
                    if target.startswith('192.168.22.'):
                        logger.info("Special handling for 192.168.22.0/24 network - adding delay")
                        time.sleep(1.0)
                
                # Continue with ICMP scan to find additional devices
                logger.info("Continuing with ICMP scan to find additional devices")
            
            # Get list of hosts to scan
            hosts = parse_target(target)
            
            if not hosts:
                logger.warning(f"No hosts to scan in target {target}")
                return self.results
                
            # Randomize hosts if in stealth mode
            if self.stealth_mode:
                random.shuffle(hosts)
            
            # Use a thread pool to scan hosts concurrently
            # Adjust concurrency based on whether it's a local network
            if is_local:
                max_workers = min(self.concurrent_pings * 2, 100)  # More threads for local networks
            else:
                max_workers = min(self.concurrent_pings, 50)  # Cap at 50 threads
                
            logger.info(f"Using {max_workers} concurrent threads for scanning")
            
            # Use a lock to protect access to the results list
            results_lock = threading.Lock()
            
            # Define a callback function to process results as they come in
            def process_result(ip, is_alive):
                if is_alive:
                    timestamp = datetime.datetime.now().isoformat()
                    device = {
                        "ip": ip,
                        "status": "up",
                        "method": "icmp",
                        "timestamp": timestamp
                    }
                    
                    # Thread-safe update of results
                    with results_lock:
                        # Check if this IP is already in results (from ARP scan)
                        if not any(result['ip'] == ip for result in self.results):
                            self.results.append(device)
                            # Publish the result immediately
                            self.publish_results([device])
                            # Log each found device
                            logger.debug(f"Found alive host: {ip}")
                    
                    # Add delay if in stealth mode
                    if self.stealth_mode:
                        time.sleep(self.stealth_delay)
            
            # Use ThreadPoolExecutor to scan hosts concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                futures = {executor.submit(ping, ip, self.count, self.timeout): ip for ip in hosts}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        is_alive = future.result()
                        process_result(ip, is_alive)
                    except Exception as e:
                        logger.error(f"Error checking {ip}: {str(e)}")
            
            logger.info(f"Network scan completed. Found {len(self.results)} alive hosts.")
            return self.results
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            return self.results
            
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this discovery module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        try:
            # Parse target to validate format
            hosts = parse_target(target)
            return len(hosts) > 0
            
        except Exception:
            return False 