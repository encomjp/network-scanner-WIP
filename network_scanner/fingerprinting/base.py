"""
Base Fingerprinting Module - Abstract base class for fingerprinting modules.

This module defines the interface that all fingerprinting modules must implement.
"""

import abc
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from network_scanner.core.event_bus import event_bus

logger = logging.getLogger(__name__)

class FingerprintingModule(abc.ABC):
    """Abstract base class for all fingerprinting modules."""
    
    def __init__(self):
        """Initialize the fingerprinting module."""
        self.name = self.__class__.__name__
        self.running = False
        self.last_scan_time = None
        self.last_scan_results = []
        logger.debug(f"Initialized fingerprinting module: {self.name}")
        
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
        Start the fingerprinting process.
        
        Returns:
            True if started successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def stop(self) -> bool:
        """
        Stop the fingerprinting process.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Perform fingerprinting on the specified target.
        
        Args:
            target: Target to fingerprint (IP or hostname)
            
        Returns:
            Fingerprinting results as a dictionary
        """
        pass
        
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the results of the last fingerprinting operation.
        
        Returns:
            List of fingerprinting results as dictionaries
        """
        return self.last_scan_results
        
    def is_running(self) -> bool:
        """
        Check if the fingerprinting module is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running
        
    def status(self) -> Dict[str, Any]:
        """
        Get the status of the fingerprinting module.
        
        Returns:
            Dictionary with status information
        """
        return {
            "name": self.name,
            "running": self.running,
            "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "fingerprints_found": len(self.last_scan_results)
        }
        
    def publish_results(self, results: Dict[str, Any]) -> None:
        """
        Publish fingerprinting results to the event bus.
        
        Args:
            results: Fingerprinting results as a dictionary
        """
        event_data = {
            "module": self.name,
            "timestamp": datetime.utcnow().isoformat(),
            "results": results
        }
        
        event_bus.publish("fingerprinting.results", event_data)
        logger.debug(f"Published fingerprinting results from {self.name}")
        
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this fingerprinting module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        # Default implementation, should be overridden by subclasses
        return True 