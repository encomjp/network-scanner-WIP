"""
Network utility functions for discovery modules.
"""

import ipaddress
import logging
from typing import List, Tuple
from scapy.all import conf

logger = logging.getLogger(__name__)

def parse_target(target: str) -> List[str]:
    """
    Parse a target string into a list of IP addresses.
    
    Args:
        target: Target string (CIDR, range, or single IP)
        
    Returns:
        List of IP addresses to scan
    """
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
        
    return hosts

def is_local_network(target: str) -> bool:
    """
    Determine if the target is on the local network.
    
    Args:
        target: Target network in CIDR notation or single IP
        
    Returns:
        True if target is on local network, False otherwise
    """
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

def split_network(network: str, max_size: int = 256) -> List[str]:
    """
    Split a network into smaller subnets if it's too large.
    
    Args:
        network: Network in CIDR notation
        max_size: Maximum number of addresses per subnet
        
    Returns:
        List of subnet strings
    """
    try:
        if '/' not in network:
            # If it's a single IP, use /24 network
            network_parts = network.split('.')
            network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
            
        target_net = ipaddress.ip_network(network, strict=False)
        if target_net.prefixlen < 24 and target_net.num_addresses > max_size:
            logger.info(f"Large network detected ({target_net.num_addresses} addresses). Breaking into /24 subnets.")
            subnets = list(target_net.subnets(new_prefix=24))
            logger.info(f"Will scan {len(subnets)} subnets: {[str(s) for s in subnets]}")
            return [str(subnet) for subnet in subnets]
        else:
            return [str(target_net)]
            
    except Exception as e:
        logger.error(f"Error splitting network {network}: {str(e)}")
        return [network]  # Fall back to original network string 