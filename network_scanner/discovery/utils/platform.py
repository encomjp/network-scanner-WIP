"""
Platform-specific utility functions for discovery modules.
"""

import platform
import subprocess
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

def get_ping_command(count: int, timeout: float, target: str) -> List[str]:
    """
    Get the appropriate ping command for the current platform.
    
    Args:
        count: Number of ping attempts
        timeout: Timeout in seconds
        target: Target IP address
        
    Returns:
        List of command arguments
    """
    system = platform.system().lower()
    
    if system == "windows":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), target]
    else:  # Linux, Darwin (macOS), etc.
        return ["ping", "-c", str(count), "-W", str(timeout), target]

def ping(target: str, count: int = 1, timeout: float = 1.0) -> bool:
    """
    Ping a target IP address.
    
    Args:
        target: Target IP address
        count: Number of ping attempts
        timeout: Timeout in seconds
        
    Returns:
        True if target responds to ping, False otherwise
    """
    try:
        command = get_ping_command(count, timeout, target)
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 1
        )
        
        return result.returncode == 0
        
    except Exception as e:
        logger.debug(f"Error pinging {target}: {e}")
        return False

def get_interface_info() -> List[dict]:
    """
    Get information about network interfaces.
    
    Returns:
        List of dictionaries containing interface information
    """
    from scapy.all import conf
    interfaces = []
    
    for iface in conf.ifaces.values():
        if iface.ip and iface.ip != '127.0.0.1' and iface.ip != '0.0.0.0':
            try:
                interfaces.append({
                    'name': iface.name,
                    'ip': iface.ip,
                    'mac': iface.mac,
                    'network': f"{iface.ip.rsplit('.', 1)[0]}.0/24"  # Assume /24
                })
            except Exception as e:
                logger.debug(f"Error processing interface {iface.name}: {str(e)}")
                
    return interfaces 