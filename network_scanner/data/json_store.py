"""
JSON Store - JSON file-based data storage.

This module provides a simple JSON file-based data storage implementation.
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import threading

from network_scanner.data.base import DataModule

logger = logging.getLogger(__name__)

class JSONStore(DataModule):
    """Simple JSON file-based data storage."""
    
    def __init__(self):
        """Initialize the JSON store."""
        super().__init__()
        self.data_dir = None
        self.data = {}
        self.auto_save = True
        self.save_interval = 60  # seconds
        self.last_save_time = {}
        self.locks = {}
        logger.debug("JSONStore initialized")
        
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the JSON store with configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.data_dir = Path(config.get('data_dir', 'data'))
            self.auto_save = config.get('auto_save', True)
            self.save_interval = config.get('save_interval', 60)
            
            # Create data directory if it doesn't exist
            os.makedirs(self.data_dir, exist_ok=True)
            
            logger.info(f"JSONStore initialized with data directory: {self.data_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing JSONStore: {e}")
            return False
            
    def _get_data_file(self, data_type: str) -> Path:
        """
        Get the file path for a given data type.
        
        Args:
            data_type: Type of data
            
        Returns:
            Path to the data file
        """
        return self.data_dir / f"{data_type}.json"
        
    def _load_data(self, data_type: str) -> None:
        """
        Load data from disk for a given data type.
        
        Args:
            data_type: Type of data to load
        """
        # Initialize lock for this data type if needed
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            data_file = self._get_data_file(data_type)
            
            if data_file.exists():
                try:
                    with open(data_file, 'r') as f:
                        self.data[data_type] = json.load(f)
                    logger.debug(f"Loaded {len(self.data[data_type])} items from {data_file}")
                except Exception as e:
                    logger.error(f"Error loading data from {data_file}: {e}")
                    self.data[data_type] = []
            else:
                self.data[data_type] = []
                
    def _save_data(self, data_type: str) -> bool:
        """
        Save data to disk for a given data type.
        
        Args:
            data_type: Type of data to save
            
        Returns:
            True if save was successful, False otherwise
        """
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            data_file = self._get_data_file(data_type)
            
            try:
                with open(data_file, 'w') as f:
                    json.dump(self.data[data_type], f, indent=2)
                    
                self.last_save_time[data_type] = time.time()
                logger.debug(f"Saved {len(self.data[data_type])} items to {data_file}")
                return True
                
            except Exception as e:
                logger.error(f"Error saving data to {data_file}: {e}")
                return False
                
    def _needs_save(self, data_type: str) -> bool:
        """
        Check if data needs to be saved based on save interval.
        
        Args:
            data_type: Type of data to check
            
        Returns:
            True if data should be saved, False otherwise
        """
        if not self.auto_save:
            return False
            
        last_save = self.last_save_time.get(data_type, 0)
        return (time.time() - last_save) >= self.save_interval
        
    def _matches_query(self, item: Dict[str, Any], query: Dict[str, Any]) -> bool:
        """
        Check if an item matches a query.
        
        Args:
            item: Item to check
            query: Query to match against
            
        Returns:
            True if item matches query, False otherwise
        """
        for key, value in query.items():
            if key not in item:
                return False
                
            if isinstance(value, dict) and isinstance(item[key], dict):
                # Recursive check for nested dictionaries
                if not self._matches_query(item[key], value):
                    return False
            elif item[key] != value:
                return False
                
        return True
        
    def store(self, data_type: str, data: Any) -> bool:
        """
        Store data in the JSON store.
        
        Args:
            data_type: Type of data being stored
            data: Data to store
            
        Returns:
            True if data was stored successfully, False otherwise
        """
        # Make sure the data type is loaded
        if data_type not in self.data:
            self._load_data(data_type)
            
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            try:
                # Add timestamp if not already present
                if isinstance(data, dict) and "timestamp" not in data:
                    data["timestamp"] = datetime.utcnow().isoformat()
                    
                # Add to in-memory data
                self.data[data_type].append(data)
                
                # Save if needed
                if self._needs_save(data_type):
                    self._save_data(data_type)
                    
                return True
                
            except Exception as e:
                logger.error(f"Error storing data in JSONStore: {e}")
                return False
                
    def retrieve(self, data_type: str, query: Optional[Dict[str, Any]] = None) -> List[Any]:
        """
        Retrieve data from the JSON store.
        
        Args:
            data_type: Type of data to retrieve
            query: Optional query to filter the data
            
        Returns:
            List of matching data items
        """
        # Make sure the data type is loaded
        if data_type not in self.data:
            self._load_data(data_type)
            
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            if query is None:
                # Return all data
                return self.data[data_type].copy()
                
            # Filter data based on query
            return [item for item in self.data[data_type] if self._matches_query(item, query)]
            
    def delete(self, data_type: str, query: Dict[str, Any]) -> int:
        """
        Delete data from the JSON store.
        
        Args:
            data_type: Type of data to delete
            query: Query to identify data to delete
            
        Returns:
            Number of items deleted
        """
        # Make sure the data type is loaded
        if data_type not in self.data:
            self._load_data(data_type)
            
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            original_length = len(self.data[data_type])
            
            # Filter out matching items
            self.data[data_type] = [item for item in self.data[data_type] if not self._matches_query(item, query)]
            
            deleted_count = original_length - len(self.data[data_type])
            
            # Save if items were deleted
            if deleted_count > 0 and self._needs_save(data_type):
                self._save_data(data_type)
                
            return deleted_count
            
    def update(self, data_type: str, query: Dict[str, Any], update_data: Dict[str, Any]) -> int:
        """
        Update data in the JSON store.
        
        Args:
            data_type: Type of data to update
            query: Query to identify data to update
            update_data: Data to update
            
        Returns:
            Number of items updated
        """
        # Make sure the data type is loaded
        if data_type not in self.data:
            self._load_data(data_type)
            
        if data_type not in self.locks:
            self.locks[data_type] = threading.RLock()
            
        with self.locks[data_type]:
            updated_count = 0
            
            for item in self.data[data_type]:
                if self._matches_query(item, query):
                    # Update item with new data
                    item.update(update_data)
                    updated_count += 1
                    
            # Save if items were updated
            if updated_count > 0 and self._needs_save(data_type):
                self._save_data(data_type)
                
            return updated_count
            
    def count(self, data_type: str, query: Optional[Dict[str, Any]] = None) -> int:
        """
        Count data items in the JSON store.
        
        Args:
            data_type: Type of data to count
            query: Optional query to filter the data
            
        Returns:
            Number of matching items
        """
        # Use retrieve to get matching items, then count them
        return len(self.retrieve(data_type, query))
        
    def save_all(self) -> bool:
        """
        Save all data to disk.
        
        Returns:
            True if all saves were successful, False otherwise
        """
        success = True
        
        for data_type in self.data:
            if not self._save_data(data_type):
                success = False
                
        return success
        
    def load_all(self) -> None:
        """
        Load all data from disk.
        """
        # Find all JSON files in the data directory
        if not self.data_dir.exists():
            return
            
        for file_path in self.data_dir.glob("*.json"):
            data_type = file_path.stem
            self._load_data(data_type) 