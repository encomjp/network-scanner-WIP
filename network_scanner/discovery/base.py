"""
Base Discovery Module - Abstract base class for discovery modules.

This module defines the interface that all discovery modules must implement.
"""

import abc
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from network_scanner.core.event_bus import event_bus

logger = logging.getLogger(__name__)

class DiscoveryModule(abc.ABC):
    """Abstract base class for all discovery modules."""
    
    def __init__(self):
        """Initialize the discovery module."""
        self.name = self.__class__.__name__
        self.running = False
        self.last_scan_time = None
        self.last_scan_results = []
        logger.debug(f"Initialized discovery module: {self.name}")
        
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
        Start the discovery process.
        
        Returns:
            True if started successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def stop(self) -> bool:
        """
        Stop the discovery process.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform a scan on the specified target.
        
        Args:
            target: Target to scan (IP, range, or hostname)
            
        Returns:
            List of discovered devices as dictionaries
        """
        pass
        
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the results of the last scan.
        
        Returns:
            List of discovered devices as dictionaries
        """
        return self.last_scan_results
        
    def is_running(self) -> bool:
        """
        Check if the discovery module is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running
        
    def status(self) -> Dict[str, Any]:
        """
        Get the status of the discovery module.
        
        Returns:
            Dictionary with status information
        """
        return {
            "name": self.name,
            "running": self.running,
            "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "devices_found": len(self.last_scan_results)
        }
        
    def publish_results(self, results: List[Dict[str, Any]]) -> None:
        """
        Publish scan results to the event bus.
        
        Args:
            results: List of discovered devices as dictionaries
        """
        event_data = {
            "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "results": results
        }
        
        event_bus.publish("discovery.results", event_data)
        logger.debug(f"Published {len(results)} discovery results from {self.name}")
        
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this discovery module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        # Default implementation, should be overridden by subclasses
        return True 