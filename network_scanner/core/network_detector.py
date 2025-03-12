import socket
import subprocess
import platform
import logging
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
import time
import re

logger = logging.getLogger(__name__)

class NetworkDetector:
    """
    A utility class for quick network detection operations.
    This class provides methods for detecting local network devices
    without requiring the full scan infrastructure.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect_local_network(self) -> List[Dict[str, Any]]:
        """
        Quickly detect devices on the local network using a combination of
        methods including checking localhost, gateway, and common IPs.
        
        Returns:
            List[Dict[str, Any]]: List of detected devices with their information
        """
        results = []
        
        # Always add localhost
        localhost_info = self._get_localhost_info()
        if localhost_info:
            results.append(localhost_info)
        
        # Check gateway
        gateway_info = self._get_gateway_info()
        if gateway_info:
            results.append(gateway_info)
            
        # Check common IPs in local network
        common_ips = self._get_common_local_ips()
        for ip_info in common_ips:
            if ip_info and ip_info.get('ip') not in [r.get('ip') for r in results]:
                results.append(ip_info)
                
        return results
    
    def _get_localhost_info(self) -> Dict[str, Any]:
        """Get information about localhost"""
        try:
            hostname = socket.gethostname()
            ip = "127.0.0.1"
            return {
                "ip": ip,
                "hostname": hostname,
                "status": "alive",
                "method": "direct",
                "timestamp": time.time(),
                "is_gateway": False,
                "mac_address": "00:00:00:00:00:00",  # Placeholder for localhost
                "vendor": "Local"
            }
        except Exception as e:
            self.logger.error(f"Error getting localhost info: {e}")
            return {
                "ip": "127.0.0.1",
                "hostname": "localhost",
                "status": "alive",
                "method": "direct",
                "timestamp": time.time(),
                "is_gateway": False,
                "mac_address": "00:00:00:00:00:00",
                "vendor": "Local"
            }
    
    def _get_gateway_info(self) -> Optional[Dict[str, Any]]:
        """Attempt to detect and get information about the gateway"""
        try:
            gateway_ip = self._detect_gateway()
            if not gateway_ip:
                # Try common gateway IPs if detection fails
                for ip in ["192.168.31.1", "192.168.31.254", "192.168.1.1", "10.0.0.1"]:
                    if self._is_ip_alive(ip):
                        gateway_ip = ip
                        break
            
            if gateway_ip:
                return {
                    "ip": gateway_ip,
                    "hostname": "gateway",
                    "status": "alive",
                    "method": "ping",
                    "timestamp": time.time(),
                    "is_gateway": True,
                    "mac_address": self._get_mac_address(gateway_ip),
                    "vendor": "Gateway"
                }
            return None
        except Exception as e:
            self.logger.error(f"Error getting gateway info: {e}")
            # Fallback to common gateway
            return {
                "ip": "192.168.31.1",
                "hostname": "gateway",
                "status": "unknown",
                "method": "fallback",
                "timestamp": time.time(),
                "is_gateway": True,
                "mac_address": "00:00:00:00:00:00",
                "vendor": "Gateway"
            }
    
    def _get_common_local_ips(self) -> List[Dict[str, Any]]:
        """Check common IPs in local networks"""
        results = []
        # Try to determine local network
        local_network = self._detect_local_network_cidr()
        
        # Common last octets to check
        common_hosts = [1, 2, 100, 101, 254]
        
        if local_network:
            try:
                network = ipaddress.IPv4Network(local_network, strict=False)
                base_ip = str(network.network_address).split('.')
                
                for host in common_hosts:
                    ip = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{host}"
                    if self._is_ip_alive(ip):
                        mac = self._get_mac_address(ip)
                        results.append({
                            "ip": ip,
                            "hostname": f"host-{ip}",
                            "status": "alive",
                            "method": "ping",
                            "timestamp": time.time(),
                            "is_gateway": False,
                            "mac_address": mac,
                            "vendor": "Unknown"
                        })
            except Exception as e:
                self.logger.error(f"Error checking common IPs: {e}")
        
        return results
    
    def _detect_gateway(self) -> Optional[str]:
        """Attempt to detect the gateway IP address"""
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", universal_newlines=True)
                for line in output.split('\n'):
                    if "Default Gateway" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            return match.group(1)
            else:  # Unix-like systems
                # Try to get default route
                try:
                    output = subprocess.check_output("netstat -rn | grep default", shell=True, universal_newlines=True)
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', output)
                    if match:
                        return match.group(1)
                except:
                    # Try alternative method
                    try:
                        output = subprocess.check_output("ip route | grep default", shell=True, universal_newlines=True)
                        match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
                        if match:
                            return match.group(1)
                    except:
                        pass
            return None
        except Exception as e:
            self.logger.error(f"Error detecting gateway: {e}")
            return None
    
    def _detect_local_network_cidr(self) -> Optional[str]:
        """Attempt to detect the local network CIDR"""
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", universal_newlines=True)
                ip_address = None
                subnet_mask = None
                
                for line in output.split('\n'):
                    if "IPv4 Address" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip_address = match.group(1)
                    if "Subnet Mask" in line:
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            subnet_mask = match.group(1)
                    
                    if ip_address and subnet_mask:
                        # Convert subnet mask to CIDR notation
                        cidr = sum([bin(int(x)).count('1') for x in subnet_mask.split('.')])
                        return f"{ip_address}/{cidr}"
            else:  # Unix-like systems
                try:
                    # Try to get IP and CIDR
                    output = subprocess.check_output("ifconfig | grep 'inet ' | grep -v 127.0.0.1", shell=True, universal_newlines=True)
                    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+).*netmask\s+0x([0-9a-f]+)', output)
                    if match:
                        ip_address = match.group(1)
                        netmask_hex = match.group(2)
                        # Convert hex netmask to CIDR
                        netmask_bin = bin(int(netmask_hex, 16))[2:].zfill(32)
                        cidr = netmask_bin.count('1')
                        return f"{ip_address}/{cidr}"
                except:
                    # Try alternative method
                    try:
                        output = subprocess.check_output("ip addr | grep 'inet ' | grep -v 127.0.0.1", shell=True, universal_newlines=True)
                        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', output)
                        if match:
                            return f"{match.group(1)}/{match.group(2)}"
                    except:
                        pass
            
            # Fallback to common networks
            return "192.168.31.0/24"
        except Exception as e:
            self.logger.error(f"Error detecting local network: {e}")
            return "192.168.31.0/24"  # Fallback
    
    def _is_ip_alive(self, ip: str) -> bool:
        """Check if an IP address responds to ping"""
        try:
            # Special case for localhost
            if ip == "127.0.0.1" or ip == "localhost":
                return True
                
            # Construct ping command based on platform
            if platform.system() == "Windows":
                command = ["ping", "-n", "1", "-w", "500", ip]
            else:  # Unix-like systems (Linux, macOS)
                command = ["ping", "-c", "1", "-W", "1", ip]
            
            # Execute ping command with a short timeout
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            self.logger.error(f"Error pinging {ip}: {e}")
            return False
    
    def _get_mac_address(self, ip: str) -> str:
        """Attempt to get MAC address for an IP"""
        try:
            if ip == "127.0.0.1" or ip == "localhost":
                return "00:00:00:00:00:00"
                
            if platform.system() == "Windows":
                # Use ARP on Windows
                output = subprocess.check_output(f"arp -a {ip}", shell=True, universal_newlines=True)
                match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', output)
                if match:
                    return match.group(1)
            else:
                # Use ARP on Unix-like systems
                try:
                    output = subprocess.check_output(f"arp -n {ip}", shell=True, universal_newlines=True)
                    match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', output)
                    if match:
                        return match.group(1)
                except:
                    pass
            
            return "00:00:00:00:00:00"  # Default if not found
        except Exception as e:
            self.logger.error(f"Error getting MAC address for {ip}: {e}")
            return "00:00:00:00:00:00" 