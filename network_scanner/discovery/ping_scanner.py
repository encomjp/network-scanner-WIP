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
        Scan the target network for alive hosts.
        
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
                
            logger.info(f"Starting ping scan of {target}")
            
            # Reset results for this scan
            self.results = []
            
            # Check if this is a local network
            is_local_network = self._is_local_network(target)
            logger.info(f"Target {target} is {'a local' if is_local_network else 'not a local'} network")
            
            # For local networks, perform ARP scan first
            if is_local_network:
                logger.info(f"Performing ARP scan on local network {target}")
                arp_results = self._perform_arp_scan(target)
                
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
            
            # Perform ICMP ping scan
            logger.info(f"Performing ICMP ping scan on {target}")
            
            # Parse the target to get a list of hosts to scan
            hosts = []
            try:
                # Check if it's a CIDR notation
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    hosts = [str(ip) for ip in network.hosts()]
                    
                    # For 192.168.22.0/24, prioritize certain IPs
                    if target.startswith('192.168.22.'):
                        logger.info("Prioritizing gateway and common IPs for 192.168.22.0/24")
                        priority_ips = [
                            f"192.168.22.{i}" for i in [1, 254, 100, 200, 150, 50]
                        ]
                        # Move priority IPs to the front
                        for ip in reversed(priority_ips):
                            if ip in hosts:
                                hosts.remove(ip)
                                hosts.insert(0, ip)
                # Check if it's a range (e.g., 192.168.1.1-10)
                elif '-' in target:
                    parts = target.split('-')
                    if len(parts) == 2:
                        base_ip = parts[0].rsplit('.', 1)[0]
                        start = int(parts[0].rsplit('.', 1)[1])
                        end = int(parts[1])
                        hosts = [f"{base_ip}.{i}" for i in range(start, end + 1)]
                # Single IP
                else:
                    hosts = [target]
                    logger.info(f"Single IP {target} to scan")
            except Exception as e:
                logger.error(f"Error parsing target {target}: {str(e)}")
                return self.results
            
            if not hosts:
                logger.warning(f"No hosts to scan in target {target}")
                return self.results
                
            # Randomize hosts if in stealth mode
            if self.stealth_mode:
                random.shuffle(hosts)
            
            # Use a thread pool to scan hosts concurrently
            # Adjust concurrency based on whether it's a local network
            if is_local_network:
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
                futures = {executor.submit(self._is_ip_alive, ip): ip for ip in hosts}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        is_alive = future.result()
                        process_result(ip, is_alive)
                    except Exception as e:
                        logger.error(f"Error checking {ip}: {str(e)}")
            
            logger.info(f"Ping scan completed. Found {len(self.results)} alive hosts.")
            return self.results
            
        except Exception as e:
            logger.error(f"Error during ping scan: {str(e)}")
            return self.results

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
        """Perform an ARP scan on the local network."""
        try:
            from scapy.all import ARP, Ether, srp
            import socket
            
            results = []
            
            # Parse the target network
            if '/' not in target:
                # If it's a single IP, use /24 network
                network_parts = target.split('.')
                network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
                logger.info(f"Converting single IP {target} to network {network} for ARP scan")
            else:
                network = target
            
            # For larger networks, break into smaller subnets
            try:
                target_net = ipaddress.ip_network(network, strict=False)
                if target_net.prefixlen < 24 and target_net.num_addresses > 256:
                    logger.info(f"Large network detected ({target_net.num_addresses} addresses). Breaking into /24 subnets.")
                    subnets = list(target_net.subnets(new_prefix=24))
                    logger.info(f"Will scan {len(subnets)} subnets: {[str(s) for s in subnets]}")
                else:
                    subnets = [target_net]
            except Exception as e:
                logger.error(f"Error parsing network {network}: {str(e)}")
                subnets = [network]  # Fall back to original network string
            
            # Scan each subnet
            for subnet in subnets:
                subnet_str = str(subnet)
                logger.info(f"Sending ARP broadcast to {subnet_str}")
                
                # Create ARP request packet
                arp = ARP(pdst=subnet_str)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
                packet = ether/arp
                
                # Send packet and capture responses
                # Try multiple times for reliability
                timeout = self.timeout
                max_attempts = 2
                
                for attempt in range(max_attempts):
                    logger.debug(f"ARP scan attempt {attempt+1}/{max_attempts} for {subnet_str}")
                    responses, _ = srp(packet, timeout=timeout, verbose=0)
                    
                    if responses:
                        logger.info(f"Got {len(responses)} ARP responses from {subnet_str}")
                        break
                    else:
                        logger.debug(f"No ARP responses from {subnet_str} on attempt {attempt+1}")
                        # Increase timeout for next attempt
                        timeout *= 1.5
                
                # Process responses
                for sent, received in responses:
                    timestamp = datetime.datetime.now().isoformat()
                    
                    # Try to get hostname
                    hostname = None
                    try:
                        hostname = socket.gethostbyaddr(received.psrc)[0]
                    except:
                        pass
                    
                    device = {
                        "ip": received.psrc,
                        "status": "up",
                        "method": "arp",
                        "timestamp": timestamp
                    }
                    
                    if hostname:
                        device["hostname"] = hostname
                        
                    if received.hwsrc:
                        device["mac"] = received.hwsrc
                        
                    # Check if this device is already in results
                    if not any(r.get('ip') == device['ip'] for r in results):
                        results.append(device)
                        
                        # Publish the result
                        self.publish_results([device])
                        
                        logger.debug(f"Found device via ARP: {device['ip']} (MAC: {device.get('mac', 'unknown')})")
            
            logger.info(f"ARP scan completed. Found {len(results)} devices.")
            return results
        except Exception as e:
            logger.error(f"Error during ARP scan: {str(e)}")
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