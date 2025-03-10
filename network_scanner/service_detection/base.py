"""
Base Service Detection Module - Abstract base class for service detection modules.

This module defines the interface that all service detection modules must implement.
"""

import abc
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union

from network_scanner.core.event_bus import event_bus

logger = logging.getLogger(__name__)

class ServiceDetectionModule(abc.ABC):
    """Abstract base class for all service detection modules."""
    
    def __init__(self):
        """Initialize the service detection module."""
        self.name = self.__class__.__name__
        self.running = False
        self.last_scan_time = None
        self.last_scan_results = []
        logger.debug(f"Initialized service detection module: {self.name}")
        
    @abc.abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the module with the provided configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def start(self) -> bool:
        """
        Start the service detection process.
        
        Returns:
            True if started successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def stop(self) -> bool:
        """
        Stop the service detection process.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def scan(self, target: str, ports: Optional[Union[List[int], str]] = None) -> List[Dict[str, Any]]:
        """
        Perform a service scan on the specified target.
        
        Args:
            target: Target to scan (IP or hostname)
            ports: Optional ports to scan (list of ints or comma-separated string)
            
        Returns:
            List of discovered services as dictionaries
        """
        pass
        
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the results of the last scan.
        
        Returns:
            List of discovered services as dictionaries
        """
        return self.last_scan_results
        
    def is_running(self) -> bool:
        """
        Check if the service detection module is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running
        
    def status(self) -> Dict[str, Any]:
        """
        Get the status of the service detection module.
        
        Returns:
            Dictionary with status information
        """
        return {
            "name": self.name,
            "running": self.running,
            "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "services_found": len(self.last_scan_results)
        }
        
    def publish_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Publish scan results to the event bus.
        
        Args:
            results: List of discovered services as dictionaries
        """
        event_data = {
            "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "results": results
        }
        
        event_bus.publish("service_detection.results", event_data)
        logger.debug(f"Published {len(results)} service detection results from {self.name}")
        
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this service detection module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        # Default implementation, should be overridden by subclasses
        return True
        
    def parse_port_specification(self, ports: Optional[Union[List[int], str]] = None) -> Set[int]:
        """
        Parse a port specification into a set of port numbers.
        
        Args:
            ports: Port specification (list of ints, comma-separated string, or range string)
            
        Returns:
            Set of port numbers
        """
        if ports is None:
            # Default to common ports
            return {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
            
        if isinstance(ports, list):
            return set(ports)
            
        if isinstance(ports, str):
            port_set = set()
            
            for part in ports.split(','):
                part = part.strip()
                
                if '-' in part:
                    # Range of ports (e.g., "80-100")
                    start, end = part.split('-')
                    port_set.update(range(int(start), int(end) + 1))
                else:
                    # Single port
                    port_set.add(int(part))
                    
            return port_set
            
        raise ValueError(f"Invalid port specification: {ports}") 