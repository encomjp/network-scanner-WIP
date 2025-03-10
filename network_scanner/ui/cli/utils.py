"""
CLI Utilities - Helper functions for the CLI interface.

This module provides utility functions for the CLI interface.
"""

import datetime
import time
from typing import Optional


def format_timestamp(timestamp: str) -> str:
    """
    Format an ISO timestamp into a human-readable string.
    
    Args:
        timestamp: ISO format timestamp string
        
    Returns:
        Human-readable timestamp
    """
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return timestamp
        
def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human-readable duration
    """
    if seconds < 60:
        return f"{seconds:.2f} sec"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} min"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hrs"
        
def get_ip_range_description(target: str) -> str:
    """
    Get a human-readable description of an IP range.
    
    Args:
        target: IP range in CIDR or range notation
        
    Returns:
        Human-readable description
    """
    if '/' in target:  # CIDR notation
        import ipaddress
        try:
            network = ipaddress.ip_network(target, strict=False)
            return f"{target} ({network.num_addresses} hosts)"
        except ValueError:
            return target
    elif '-' in target:  # Range notation
        parts = target.split('-')
        if len(parts) == 2:
            return f"{parts[0]} to {parts[1]}"
    
    return target
    
def format_bytes(num_bytes: int) -> str:
    """
    Format bytes to a human-readable string.
    
    Args:
        num_bytes: Number of bytes
        
    Returns:
        Human-readable size
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB" 