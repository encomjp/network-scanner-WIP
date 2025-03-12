"""
ARP Scanner - ARP-based network discovery.

This module discovers network devices using ARP requests.
"""

import datetime
import logging
import socket
from typing import Dict, List, Any, Optional

from scapy.all import ARP, Ether, srp
from network_scanner.discovery.utils.network import split_network

logger = logging.getLogger(__name__)

class ARPScanner:
    """Discover network devices using ARP requests."""
    
    def __init__(self, timeout: float = 1.0):
        """
        Initialize the ARP scanner.
        
        Args:
            timeout: Timeout in seconds for ARP requests
        """
        self.timeout = timeout
        
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform an ARP scan on the target network.
        
        Args:
            target: Target network in CIDR notation or single IP
            
        Returns:
            List of dictionaries containing information about discovered devices
        """
        try:
            results = []
            
            # Split network into manageable subnets
            subnets = split_network(target)
            
            # Scan each subnet
            for subnet in subnets:
                logger.info(f"Sending ARP broadcast to {subnet}")
                
                # Create ARP request packet
                arp = ARP(pdst=subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
                packet = ether/arp
                
                # Send packet and capture responses
                # Try multiple times for reliability
                timeout = self.timeout
                max_attempts = 2
                
                for attempt in range(max_attempts):
                    logger.debug(f"ARP scan attempt {attempt+1}/{max_attempts} for {subnet}")
                    responses, _ = srp(packet, timeout=timeout, verbose=0)
                    
                    if responses:
                        logger.info(f"Got {len(responses)} ARP responses from {subnet}")
                        break
                    else:
                        logger.debug(f"No ARP responses from {subnet} on attempt {attempt+1}")
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
                        logger.debug(f"Found device via ARP: {device['ip']} (MAC: {device.get('mac', 'unknown')})")
            
            logger.info(f"ARP scan completed. Found {len(results)} devices.")
            return results
            
        except Exception as e:
            logger.error(f"Error during ARP scan: {str(e)}")
            return [] 