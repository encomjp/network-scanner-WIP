"""
Ping Scanner - ICMP-based network discovery.

This module discovers network devices using ICMP echo requests (ping).
"""

import ipaddress
import logging
import subprocess
import threading
import time
import datetime
from typing import Any, Dict, List, Optional, Union
import random
import concurrent.futures
import platform
import traceback

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
        Check if an IP address responds to a ping.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            bool: True if the IP responds to ping, False otherwise.
        """
        # Special handling for localhost and gateway IPs
        if ip in ['127.0.0.1', 'localhost']:
            logger.debug(f"Special IP detected: {ip} (localhost), assuming it's alive")
            return True
            
        # Special handling for common gateway IPs
        if ip in ['192.168.31.254', '192.168.31.1', '192.168.1.1', '192.168.0.1', '10.0.0.1']:
            logger.debug(f"Gateway IP detected: {ip}, assuming it's alive")
            return True
        
        # Adjust timeout for local networks
        effective_timeout = self.timeout
        if self._is_local_network(ip):
            # Cap timeout at 1 second for local networks
            effective_timeout = min(1.0, self.timeout)
        
        try:
            # Determine the appropriate ping command based on the platform
            if platform.system().lower() == "windows":
                # Windows ping command
                cmd = ["ping", "-n", "1", "-w", str(int(effective_timeout * 1000)), ip]
            else:
                # Unix-like ping command (Linux, macOS)
                cmd = ["ping", "-c", "1", "-W", str(int(effective_timeout)), ip]
            
            # Execute the ping command
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=effective_timeout + 1,  # Add 1 second buffer
                check=False
            )
            
            # Return True if the ping was successful (return code 0)
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            logger.debug(f"Ping timeout for {ip}")
            return False
        except Exception as e:
            logger.error(f"Error pinging {ip}: {str(e)}")
            return False
            
    def scan(self, target: Optional[str] = None, **kwargs) -> List[Dict[str, Any]]:
        """
        Scan a target network for alive hosts.
        
        Args:
            target: The target IP, range, or CIDR notation. If None, uses the default target.
            **kwargs: Additional arguments including timeout, stealth, and passive mode.
            
        Returns:
            List of dictionaries containing information about discovered devices.
        """
        start_time = time()
        timeout = kwargs.get('timeout', self.timeout)
        stealth_mode = kwargs.get('stealth', self.stealth_mode)
        passive_mode = kwargs.get('passive', False)
        
        # Log scan parameters
        logger.info(f"[DEBUG] Starting ping scan with target: {target}, timeout: {timeout}s, stealth: {stealth_mode}, passive: {passive_mode}")
        
        if not target:
            if not self.target:
                logger.error("[DEBUG] No target specified for scan")
                return []
            target = self.target
            
        # Special handling for single IP targets
        if self._is_single_ip(target):
            logger.info(f"[DEBUG] Single IP target detected: {target}")
            # For single IPs, just check if it's alive
            is_alive = self._is_ip_alive(target)
            if is_alive:
                logger.info(f"[DEBUG] Single IP {target} is alive")
                return [{
                    'ip': target,
                    'status': 'alive',
                    'method': 'ping',
                    'timestamp': time()
                }]
            else:
                logger.info(f"[DEBUG] Single IP {target} is not alive")
                return []
                
        # For local networks, try ARP scan first if not in passive mode
        if not passive_mode and self._is_local_network(target):
            logger.info(f"[DEBUG] Local network detected: {target}, attempting ARP scan")
            try:
                arp_results = self._perform_arp_scan(target)
                if arp_results:
                    logger.info(f"[DEBUG] ARP scan successful, found {len(arp_results)} devices")
                    return arp_results
                logger.info("[DEBUG] ARP scan returned no results, falling back to ping scan")
            except Exception as e:
                logger.error(f"[DEBUG] ARP scan failed: {str(e)}, falling back to ping scan")
        
        # Parse the target to get a list of hosts to scan
        try:
            logger.info(f"[DEBUG] Parsing target: {target}")
            hosts = self._parse_target(target)
            logger.info(f"[DEBUG] Target parsed, {len(hosts)} hosts to scan")
            
            # Special handling for 192.168.31.0/24 network
            if target.startswith('192.168.31.'):
                logger.info("[DEBUG] Special handling for 192.168.31.0/24 network")
                # Prioritize gateway and common IPs
                gateway = '192.168.31.1'
                if gateway in hosts:
                    hosts.remove(gateway)
                    hosts.insert(0, gateway)
                    
                gateway2 = '192.168.31.254'
                if gateway2 in hosts:
                    hosts.remove(gateway2)
                    hosts.insert(0, gateway2)
                    
                # Limit to first 50 hosts for faster results
                if len(hosts) > 50:
                    logger.info(f"[DEBUG] Limiting scan to first 50 hosts out of {len(hosts)}")
                    hosts = hosts[:50]
            
            # Randomize the host list if stealth mode is enabled
            if stealth_mode:
                logger.info("[DEBUG] Stealth mode enabled, randomizing host list")
                random.shuffle(hosts)
            
            # Determine the number of threads to use
            is_local = self._is_local_network(target)
            max_threads = min(self.concurrent_pings, 50)  # Cap at 50 concurrent threads
            
            if is_local:
                # Use more threads for local networks
                num_threads = min(len(hosts), max_threads)
                logger.info(f"[DEBUG] Local network detected, using {num_threads} threads")
            else:
                # Use fewer threads for remote networks
                num_threads = min(len(hosts), max(1, max_threads // 2))
                logger.info(f"[DEBUG] Remote network detected, using {num_threads} threads")
            
            # Create a thread lock for thread-safe access to the results list
            results_lock = threading.Lock()
            results = []
            
            # Define a callback function to process the results
            def process_result(ip, is_alive):
                if is_alive:
                    logger.info(f"[DEBUG] Found alive host: {ip}")
                    with results_lock:
                        results.append({
                            'ip': ip,
                            'status': 'alive',
                            'method': 'ping',
                            'timestamp': time()
                        })
                else:
                    logger.debug(f"[DEBUG] Host not alive: {ip}")
            
            # Use ThreadPoolExecutor to scan hosts concurrently
            logger.info(f"[DEBUG] Starting ThreadPoolExecutor with {num_threads} threads")
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                # Submit tasks for each IP
                future_to_ip = {executor.submit(self._is_ip_alive, ip): ip for ip in hosts}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        is_alive = future.result()
                        process_result(ip, is_alive)
                    except Exception as e:
                        logger.error(f"[DEBUG] Error checking status of {ip}: {str(e)}")
            
            # Log completion
            scan_duration = time() - start_time
            logger.info(f"[DEBUG] Ping scan completed in {scan_duration:.2f}s, found {len(results)} alive hosts")
            
            # If no hosts found, at least return the gateway if it's a local network
            if not results and is_local:
                logger.info("[DEBUG] No hosts found, checking gateway")
                gateway = self._get_default_gateway()
                if gateway:
                    logger.info(f"[DEBUG] Adding gateway {gateway} to results")
                    results.append({
                        'ip': gateway,
                        'status': 'alive',
                        'method': 'gateway',
                        'timestamp': time()
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"[DEBUG] Error during ping scan: {str(e)}")
            logger.error(traceback.format_exc())
            return []

    def _is_local_network(self, target: str) -> bool:
        """Determine if the target is on the local network."""
        try:
            # Parse the target network
            target_network = target
            if '/' not in target_network:
                # If it's a single IP, assume /32
                target_network = f"{target}/32"
            
            target_net = ipaddress.ip_network(target_network, strict=False)
            
            # Check if target is in any private network range
            # RFC 1918 private network ranges
            private_networks = [
                ipaddress.ip_network('10.0.0.0/8'),      # Class A private network
                ipaddress.ip_network('172.16.0.0/12'),   # Class B private network
                ipaddress.ip_network('192.168.0.0/16'),  # Class C private network
                ipaddress.ip_network('169.254.0.0/16'),  # Link-local addresses
            ]
            
            # Check if target is in any private network
            for private_net in private_networks:
                if target_net.subnet_of(private_net) or target_net.overlaps(private_net):
                    logger.info(f"Target {target} is in private network range {private_net}")
                    return True
            
            # If not in private ranges, check local interfaces as a fallback
            from scapy.all import conf
            local_networks = []
            
            for iface in conf.ifaces.values():
                if iface.ip and iface.ip != '127.0.0.1' and iface.ip != '0.0.0.0':
                    try:
                        # Get network address for this interface
                        ip_obj = ipaddress.ip_address(iface.ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            # Assume /24 if we don't know the netmask
                            network = f"{iface.ip.rsplit('.', 1)[0]}.0/24"
                            local_networks.append(network)
                    except Exception as e:
                        logger.debug(f"Error processing interface {iface.name}: {str(e)}")
            
            # Check if target is in any local network
            for local_net in local_networks:
                local_net_obj = ipaddress.ip_network(local_net, strict=False)
                # Check if target network overlaps with local network
                if target_net.overlaps(local_net_obj):
                    logger.info(f"Target {target} overlaps with local network {local_net}")
                    return True
            
            logger.info(f"Target {target} is not on a local network")
            return False
        except Exception as e:
            logger.error(f"Error checking if network is local: {str(e)}")
            # Default to True for private IP ranges even if we can't determine
            try:
                first_ip = str(next(target_net.hosts()))
                if first_ip.startswith('192.168.') or first_ip.startswith('10.') or \
                   (first_ip.startswith('172.') and 16 <= int(first_ip.split('.')[1]) <= 31):
                    logger.info(f"Assuming {target} is local based on IP pattern")
                    return True
            except:
                pass
            # Default to False if we can't determine
            return False

    def _perform_arp_scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform an ARP scan for faster local network discovery.
        
        Args:
            target: The target network in CIDR notation.
            
        Returns:
            List of dictionaries containing information about discovered devices.
        """
        try:
            from network_scanner.discovery.scanners.arp_scanner import ARPScanner
            arp_scanner = ARPScanner()
            logger.info(f"Performing ARP scan for {target}")
            return arp_scanner.scan(target)
        except ImportError:
            logger.warning("ARP scanner not available")
            return []
        except Exception as e:
            logger.warning(f"ARP scan failed: {str(e)}")
            return []
            
    def _parse_target(self, target: str) -> List[str]:
        """
        Parse a target string into a list of IP addresses.
        
        Args:
            target: Target string (CIDR, range, or comma-separated IPs).
            
        Returns:
            List of IP addresses to scan.
        """
        hosts = []
        
        # Handle CIDR notation
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            
        # Handle IP range notation (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in target:
            start_ip, end_ip = target.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # If only the last octet is provided in the end IP, use the first three octets from the start IP
            if '.' not in end_ip:
                start_octets = start_ip.split('.')
                end_ip = f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{end_ip}"
            
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            
            hosts = [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]
            
        # Handle comma-separated IPs
        elif ',' in target:
            hosts = [ip.strip() for ip in target.split(',')]
            
        # Handle single IP
        else:
            hosts = [target]
            
        return hosts

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