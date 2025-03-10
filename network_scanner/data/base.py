"""
Base Data Module - Abstract base class for data management modules.

This module defines the interface that all data management modules must implement.
"""

import abc
import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

class DataModule(abc.ABC):
    """Abstract base class for all data management modules."""
    
    def __init__(self):
        """Initialize the data module."""
        self.name = self.__class__.__name__
        logger.debug(f"Initialized data module: {self.name}")
        
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
    def store(self, data_type: str, data: Any) -> bool:
        """
        Store data in the data module.
        
        Args:
            data_type: Type of data being stored
            data: Data to store
            
        Returns:
            True if data was stored successfully, False otherwise
        """
        pass
        
    @abc.abstractmethod
    def retrieve(self, data_type: str, query: Optional[Dict[str, Any]] = None) -> List[Any]:
        """
        Retrieve data from the data module.
        
        Args:
            data_type: Type of data to retrieve
            query: Optional query to filter the data
            
        Returns:
            List of matching data items
        """
        pass
        
    @abc.abstractmethod
    def delete(self, data_type: str, query: Dict[str, Any]) -> int:
        """
        Delete data from the data module.
        
        Args:
            data_type: Type of data to delete
            query: Query to identify data to delete
            
        Returns:
            Number of items deleted
        """
        pass
        
    @abc.abstractmethod
    def update(self, data_type: str, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        """
        Update data in the data module.
        
        Args:
            data_type: Type of data to update
            query: Query to identify data to update
            update_data: Data to update
            
        Returns:
            Number of items updated
        """
        pass
        
    @abc.abstractmethod
    def count(self, data_type: str, query: Optional[Dict[str, Any]] = None) -> int:
        """
        Count data items in the data module.
        
        Args:
            data_type: Type of data to count
            query: Optional query to filter the data
            
        Returns:
            Number of matching items
        """
        pass 