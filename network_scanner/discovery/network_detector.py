"""
Advanced network detection module that uses multiple methods to discover the network.
"""

import subprocess
import logging
import re
import platform
import json
from typing import Dict, List, Optional, Tuple
import ipaddress
import socket
logger = logging.getLogger(__name__)

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    logger.warning("netifaces package not installed. Some network detection features will be limited.")
    HAS_NETIFACES = False

class NetworkDetector:
    """Advanced network detection using multiple methods."""
    
    def __init__(self):
        self.system = platform.system().lower()
        self._setup_commands()
        
    def initialize(self, config=None):
        """Initialize the network detector with optional configuration."""
        logger.debug("Initializing NetworkDetector")
        return True
        
    def _setup_commands(self):
        """Set up system-specific commands."""
        if self.system == "darwin":  # macOS
            self.ip_cmd = "ifconfig"
            self.route_cmd = "netstat -nr"
            self.ss_cmd = "netstat -nr" 
        elif self.system == "linux":
            self.ip_cmd = "ip addr"
            self.route_cmd = "ip route"
            self.ss_cmd = "ss -nr"
        else:  # Windows
            self.ip_cmd = "ipconfig"
            self.route_cmd = "route print"
            self.ss_cmd = "netstat -nr"
            
    def get_network_info(self) -> Dict:
        """Get comprehensive network information using multiple methods."""
        try:
            interfaces = self._get_interface_info()
            default_gateway = self._get_default_gateway()
            
            # Limit the number of recommended targets to avoid overwhelming the response
            recommended_targets = self._get_recommended_targets()
            if isinstance(recommended_targets, list) and len(recommended_targets) > 10:
                # Filter to only include IPv4 networks that are likely to be local networks
                filtered_targets = [
                    target for target in recommended_targets 
                    if isinstance(target, str) and 
                    any(target.startswith(prefix) for prefix in ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'])
                ]
                
                # If we still have too many, take the first 5
                if len(filtered_targets) > 5:
                    recommended_targets = filtered_targets[:5]
                else:
                    recommended_targets = filtered_targets
            
            # Build a more concise response
            info = {
                "interfaces": interfaces,
                "default_gateway": default_gateway,
                "recommended_targets": recommended_targets
            }
            
            # Log the network information for debugging (but limit the size)
            logger.debug(f"Network info: interfaces={len(interfaces)}, gateway={default_gateway}")
                
            return info
            
        except Exception as e:
            logger.error(f"Error getting network info: {str(e)}")
            return {
                "interfaces": [],
                "default_gateway": None,
                "error": str(e)
            }

    def _get_interface_info(self) -> List[Dict]:
        """Get information about network interfaces."""
        interfaces = []
        
        try:
            # Use netifaces for cross-platform interface detection if available
            if HAS_NETIFACES:
                try:
                    for iface in netifaces.interfaces():
                        try:
                            addrs = netifaces.ifaddresses(iface)
                            
                            # Skip loopback and interfaces without IPv4
                            if netifaces.AF_INET not in addrs:
                                continue
                                
                            for addr in addrs[netifaces.AF_INET]:
                                ip = addr.get('addr')
                                if not ip or ip.startswith('127.'):
                                    continue
                                    
                                netmask = addr.get('netmask', '')
                                broadcast = addr.get('broadcast', '')
                                
                                # Calculate network address and CIDR
                                try:
                                    if netmask:
                                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                        cidr = str(network)
                                    else:
                                        cidr = f"{ip}/24"  # Assume /24 if no netmask
                                except Exception:
                                    cidr = f"{ip}/24"
                                    
                                interface_info = {
                                    "name": iface,
                                    "ip": ip,
                                    "netmask": netmask,
                                    "broadcast": broadcast,
                                    "network": cidr
                                }
                                
                                # Get MAC address if available
                                if netifaces.AF_LINK in addrs:
                                    mac = addrs[netifaces.AF_LINK][0].get('addr')
                                    if mac:
                                        interface_info["mac"] = mac
                                        
                                interfaces.append(interface_info)
                        except Exception as e:
                            logger.debug(f"Error processing interface {iface}: {str(e)}")
                            continue
                except Exception as e:
                    logger.error(f"Error enumerating interfaces: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error getting interface info: {str(e)}")
            
        # Fallback to command line tools if netifaces didn't work
        if not interfaces:
            try:
                if self.system in ["linux", "darwin"]:
                    output = subprocess.check_output(self.ip_cmd.split(), text=True)
                    interfaces = self._parse_unix_interfaces(output)
                else:  # Windows
                    output = subprocess.check_output(self.ip_cmd, text=True)
                    interfaces = self._parse_windows_interfaces(output)
            except Exception as e:
                logger.error(f"Error getting interface info from command line: {str(e)}")
                
        return interfaces
        
    def _get_default_gateway(self) -> Optional[Dict]:
        """Get information about the default gateway."""
        try:
            # Try netifaces first if available
            if HAS_NETIFACES:
                try:
                    gws = netifaces.gateways()
                    default = gws.get('default', {}).get(netifaces.AF_INET)
                    if default:
                        gw_ip, interface = default[0], default[1]
                        return {
                            "ip": gw_ip,
                            "interface": interface
                        }
                except Exception as e:
                    logger.debug(f"Error getting gateway from netifaces: {e}")
                
            # Fallback to command line
            if self.system in ["linux", "darwin"]:
                output = subprocess.check_output(self.route_cmd.split(), text=True)
                # Look for default route
                for line in output.splitlines():
                    if "default" in line or "0.0.0.0" in line:
                        parts = line.split()
                        for part in parts:
                            try:
                                ip = ipaddress.ip_address(part)
                                if not ip.is_loopback and not ip.is_unspecified:
                                    return {"ip": str(ip)}
                            except ValueError:
                                continue
            else:  # Windows
                output = subprocess.check_output(self.route_cmd, text=True)
                for line in output.splitlines():
                    if "0.0.0.0" in line:
                        parts = line.split()
                        for part in parts:
                            try:
                                ip = ipaddress.ip_address(part)
                                if not ip.is_loopback and not ip.is_unspecified:
                                    return {"ip": str(ip)}
                            except ValueError:
                                continue
                                
        except Exception as e:
            logger.error(f"Error getting default gateway: {str(e)}")
            
        return None
        
    def _get_routing_info(self) -> List[Dict]:
        """Get routing table information."""
        routes = []
        
        try:
            if self.system in ["linux", "darwin"]:
                output = subprocess.check_output(self.route_cmd.split(), text=True)
                for line in output.splitlines():
                    if "default" not in line and "Destination" not in line:
                        parts = line.split()
                        for part in parts:
                            try:
                                # Check if it's a CIDR notation or convert it
                                if "/" in part:
                                    network = ipaddress.ip_network(part, strict=False)
                                else:
                                    # Try to parse as IP
                                    ip = ipaddress.ip_address(part)
                                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                                    
                                if not network.is_loopback:
                                    routes.append({
                                        "network": str(network)
                                    })
                                break
                            except ValueError:
                                continue
            else:  # Windows
                output = subprocess.check_output(self.route_cmd, text=True)
                for line in output.splitlines():
                    if "0.0.0.0" not in line and "Network Destination" not in line:
                        parts = line.split()
                        for part in parts:
                            try:
                                network = ipaddress.ip_network(f"{part}/24", strict=False)
                                if not network.is_loopback:
                                    routes.append({
                                        "network": str(network)
                                    })
                                break
                            except ValueError:
                                continue
                                
        except Exception as e:
            logger.error(f"Error getting routing info: {str(e)}")
            
        return routes
        
    def _get_connected_networks(self) -> List[str]:
        """Get list of directly connected networks."""
        networks = set()
        
        # Add networks from interfaces
        for iface in self._get_interface_info():
            if "network" in iface:
                networks.add(iface["network"])
                
        # Add networks from routing table
        for route in self._get_routing_info():
            if "network" in route:
                networks.add(route["network"])
                
        return list(networks)
        
    def _get_recommended_targets(self) -> List[str]:
        """Generate recommended targets for scanning."""
        targets = set()
        
        # Add connected networks
        networks = self._get_connected_networks()
        targets.update(networks)
        
        # Add specific networks based on interface IPs
        for iface in self._get_interface_info():
            if "ip" in iface:
                ip = iface["ip"]
                if not ip.startswith("127."):  # Skip loopback
                    # Add /24 network for this interface
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                        targets.add(network)
                        
        # Add gateway network if available
        gateway = self._get_default_gateway()
        if gateway and "ip" in gateway:
            gw_ip = gateway["ip"]
            gw_parts = gw_ip.split('.')
            if len(gw_parts) == 4:
                network = f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.0/24"
                targets.add(network)
                
        return list(targets)
        
    def _get_nmap_info(self) -> Optional[Dict]:
        """Get additional network information using nmap if available."""
        try:
            # Check if nmap is installed
            subprocess.run(["nmap", "--version"], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
        except Exception:
            logger.debug("nmap not available")
            return None
            
        try:
            # Get default gateway
            gateway = self._get_default_gateway()
            if not gateway or "ip" not in gateway:
                return None
                
            gw_ip = gateway["ip"]
            gw_parts = gw_ip.split('.')
            if len(gw_parts) != 4:
                return None
                
            # Scan gateway and common IPs
            targets = [
                gw_ip,  # Gateway
                f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.1",  # Common router IP
                f"{gw_parts[0]}.{gw_parts[1]}.{gw_parts[2]}.254"  # Another common router IP
            ]
            
            results = {}
            for target in targets:
                # Quick OS detection scan
                cmd = ["nmap", "-O", "-T4", "--max-os-tries", "1", target]
                try:
                    output = subprocess.check_output(cmd, 
                                                  stderr=subprocess.PIPE,
                                                  text=True,
                                                  timeout=10)
                    
                    results[target] = {
                        "os_info": self._parse_nmap_os(output),
                        "raw_output": output
                    }
                except Exception as e:
                    logger.debug(f"Error scanning {target} with nmap: {str(e)}")
                    
            return results if results else None
            
        except Exception as e:
            logger.error(f"Error getting nmap info: {str(e)}")
            return None
            
    def _parse_nmap_os(self, output: str) -> Dict:
        """Parse OS information from nmap output."""
        os_info = {
            "name": None,
            "accuracy": None,
            "type": None
        }
        
        try:
            for line in output.splitlines():
                if "OS details:" in line:
                    os_info["name"] = line.split("OS details:")[1].strip()
                elif "Aggressive OS guesses:" in line:
                    os_info["name"] = line.split("Aggressive OS guesses:")[1].split("(")[0].strip()
                elif "OS CPE:" in line:
                    os_info["type"] = line.split("OS CPE:")[1].strip()
                elif "OS guess accuracy:" in line:
                    try:
                        os_info["accuracy"] = int(re.findall(r'\d+', line)[0])
                    except (IndexError, ValueError):
                        pass
                        
        except Exception as e:
            logger.debug(f"Error parsing nmap OS info: {str(e)}")
            
        return os_info
        
    def _parse_unix_interfaces(self, output: str) -> List[Dict]:
        """Parse interface information from Unix-like systems."""
        interfaces = []
        current_iface = None
        
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Check for new interface (starts with name and no leading whitespace)
            if not line.startswith(' ') and not line.startswith('\t'):
                # Save previous interface if exists
                if current_iface and current_iface.get('ip'):
                    interfaces.append(current_iface)
                
                # Extract interface name (handle both formats: "en0:" and "en0: flags=...")
                iface_name = line.split(':')[0].strip()
                current_iface = {"name": iface_name}
            
            # Handle macOS/BSD style
            elif current_iface and "inet " in line:
                parts = line.strip().split()
                try:
                    # Format: inet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255
                    ip_index = parts.index("inet") + 1
                    if ip_index < len(parts):
                        ip = parts[ip_index]
                        if not ip.startswith('127.'):
                            current_iface["ip"] = ip
                            
                            # Get netmask
                            if "netmask" in parts:
                                netmask_index = parts.index("netmask") + 1
                                if netmask_index < len(parts):
                                    netmask_hex = parts[netmask_index]
                                    # Convert hex netmask to dotted decimal if needed
                                    if netmask_hex.startswith("0x"):
                                        try:
                                            netmask_int = int(netmask_hex, 16)
                                            netmask = ".".join([str((netmask_int >> i) & 0xFF) for i in [24, 16, 8, 0]])
                                            current_iface["netmask"] = netmask
                                            
                                            # Calculate network CIDR
                                            try:
                                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                                current_iface["network"] = str(network)
                                            except Exception as e:
                                                logger.debug(f"Error calculating network CIDR: {str(e)}")
                                                current_iface["network"] = f"{ip}/24"  # Fallback
                                        except Exception as e:
                                            logger.debug(f"Error converting netmask: {str(e)}")
                                    else:
                                        current_iface["netmask"] = netmask_hex
                            
                            # Get broadcast
                            if "broadcast" in parts:
                                broadcast_index = parts.index("broadcast") + 1
                                if broadcast_index < len(parts):
                                    current_iface["broadcast"] = parts[broadcast_index]
                except Exception as e:
                    logger.debug(f"Error parsing inet line: {str(e)}")
            
            # Handle Linux style
            elif current_iface and "inet addr:" in line:
                try:
                    # Format: inet addr:192.168.1.1 Bcast:192.168.1.255 Mask:255.255.255.0
                    addr_part = line.split("inet addr:")[1].strip()
                    ip = addr_part.split()[0]
                    if not ip.startswith('127.'):
                        current_iface["ip"] = ip
                        
                        # Get broadcast and netmask
                        if "Bcast:" in line:
                            bcast = line.split("Bcast:")[1].split()[0]
                            current_iface["broadcast"] = bcast
                        
                        if "Mask:" in line:
                            mask = line.split("Mask:")[1].split()[0]
                            current_iface["netmask"] = mask
                            
                            # Calculate network CIDR
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                                current_iface["network"] = str(network)
                            except Exception as e:
                                logger.debug(f"Error calculating network CIDR: {str(e)}")
                                current_iface["network"] = f"{ip}/24"  # Fallback
                except Exception as e:
                    logger.debug(f"Error parsing inet addr line: {str(e)}")
        
        # Add the last interface if it exists and has an IP
        if current_iface and current_iface.get('ip'):
            interfaces.append(current_iface)
            
        return interfaces
        
    def _parse_windows_interfaces(self, output: str) -> List[Dict]:
        """Parse interface information from Windows systems."""
        interfaces = []
        current_iface = None
        
        for line in output.splitlines():
            if "adapter" in line.lower():
                if current_iface:
                    interfaces.append(current_iface)
                current_iface = {"name": line.split(':')[0]}
            elif current_iface:
                if "IPv4 Address" in line:
                    ip = line.split(':')[1].strip()
                    if not ip.startswith('127.'):
                        current_iface["ip"] = ip
                elif "Subnet Mask" in line:
                    current_iface["netmask"] = line.split(':')[1].strip()
                    
        if current_iface:
            interfaces.append(current_iface)
            
        return interfaces

    def get_local_network_info(self) -> Dict:
        """Get network information for local connections using the full detection method."""
        try:
            # Use the full network detection method first
            network_info = self.get_network_info()
            
            # Check if we got valid network information
            if network_info and "interfaces" in network_info and network_info["interfaces"]:
                # Filter out loopback interfaces if we have other interfaces
                non_loopback_interfaces = [
                    iface for iface in network_info["interfaces"] 
                    if "ip" in iface and not iface["ip"].startswith("127.")
                ]
                
                if non_loopback_interfaces:
                    # We have valid non-loopback interfaces, use them
                    return {
                        "interfaces": network_info["interfaces"],
                        "default_gateway": network_info["default_gateway"]
                    }
            
            # Fallback to simplified approach if full detection didn't work
            interfaces = []
            default_gateway = None
            
            # Get the hostname and try to get its IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            if local_ip and not local_ip.startswith('127.'):
                # Create a basic interface entry
                interface_info = {
                    "name": "local",
                    "ip": local_ip,
                    "network": f"{local_ip.rsplit('.', 1)[0]}.0/24"  # Assume /24
                }
                interfaces.append(interface_info)
                
                # Create a basic gateway entry (assume gateway is .1 or .254 in the same subnet)
                ip_parts = local_ip.split('.')
                if len(ip_parts) == 4:
                    # Try common gateway addresses
                    gateway_candidates = [
                        f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1",
                        f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.254"
                    ]
                    default_gateway = {"ip": gateway_candidates[0]}
            
            # Add localhost for testing
            interfaces.append({
                "name": "localhost",
                "ip": "127.0.0.1",
                "network": "127.0.0.0/8"
            })
            
            return {
                "interfaces": interfaces,
                "default_gateway": default_gateway
            }
            
        except Exception as e:
            logger.error(f"Error getting local network info: {str(e)}")
            return {
                "interfaces": [{"name": "localhost", "ip": "127.0.0.1", "network": "127.0.0.0/8"}],
                "default_gateway": None
            }
