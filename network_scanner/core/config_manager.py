"""
Configuration Manager - Handles loading and accessing configuration.

This module provides a central place to load, store, and access configuration
from various sources including YAML files, environment variables, and CLI args.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages application configuration from various sources."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one config manager exists."""
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the config manager if not already initialized."""
        if self._initialized:
            return
            
        self._config = {}
        self._config_files = []
        self._initialized = True
        load_dotenv()  # Load .env file if exists
        logger.debug("ConfigManager initialized")
    
    def load_config_file(self, config_file: Union[str, Path]) -> bool:
        """
        Load configuration from a YAML file.
        
        Args:
            config_file: Path to the configuration file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        config_path = Path(config_file)
        
        if not config_path.exists():
            logger.error(f"Config file not found: {config_path}")
            return False
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            if not isinstance(config, dict):
                logger.error(f"Invalid config format in {config_path}")
                return False
                
            # Merge with existing config
            self._merge_config(config)
            self._config_files.append(str(config_path))
            
            logger.info(f"Loaded config from {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            return False
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """
        Recursively merge new config into existing config.
        
        Args:
            new_config: New configuration to merge
        """
        for key, value in new_config.items():
            if (key in self._config and 
                isinstance(self._config[key], dict) and 
                isinstance(value, dict)):
                # Recursively merge dictionaries
                self._merge_dicts(self._config[key], value)
            else:
                # Replace or add value
                self._config[key] = value
    
    def _merge_dicts(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Recursively merge source dict into target dict.
        
        Args:
            target: Dict to merge into
            source: Dict to merge from
        """
        for key, value in source.items():
            if (key in target and 
                isinstance(target[key], dict) and 
                isinstance(value, dict)):
                self._merge_dicts(target[key], value)
            else:
                target[key] = value
    
    def set_config_value(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value using dot notation key path.
        
        Args:
            key_path: Dot notation path (e.g., 'scanner.timeout')
            value: Value to set
        """
        parts = key_path.split('.')
        config = self._config
        
        # Navigate to the nested dict
        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            elif not isinstance(config[part], dict):
                config[part] = {}
            config = config[part]
            
        # Set the value
        config[parts[-1]] = value
        logger.debug(f"Set config value: {key_path} = {value}")
    
    def get_config_value(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation key path.
        
        Args:
            key_path: Dot notation path (e.g., 'scanner.timeout')
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        parts = key_path.split('.')
        config = self._config
        
        # Navigate to the nested value
        for part in parts:
            if not isinstance(config, dict) or part not in config:
                return default
            config = config[part]
            
        return config
    
    def load_from_env(self, prefix: str = 'NETSCANNER_') -> None:
        """
        Load configuration from environment variables.
        
        Environment variables with the specified prefix are loaded into 
        configuration. The variable name after the prefix is converted to 
        lowercase and underscores are replaced with dots for nesting.
        
        Args:
            prefix: Prefix for environment variables to load
        """
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
                
            # Remove prefix and convert to lowercase
            config_key = key[len(prefix):].lower()
            
            # Convert underscores to dots for nesting
            config_key = config_key.replace('_', '.')
            
            # Try to convert value to appropriate type
            if value.lower() in ('true', 'yes', 'on', '1'):
                value = True
            elif value.lower() in ('false', 'no', 'off', '0'):
                value = False
            else:
                try:
                    # Try converting to int or float
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    # Keep as string
                    pass
                    
            self.set_config_value(config_key, value)
            logger.debug(f"Loaded config from env: {config_key} = {value}")
    
    def load_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """
        Load configuration from a dictionary.
        
        Args:
            config_dict: Dictionary to load
        """
        self._merge_config(config_dict)
        logger.debug(f"Loaded config from dict with {len(config_dict)} keys")
    
    def get_full_config(self) -> Dict[str, Any]:
        """
        Get the complete configuration.
        
        Returns:
            Complete configuration dictionary
        """
        return self._config.copy()
    
    def get_config_files(self) -> List[str]:
        """
        Get list of loaded configuration files.
        
        Returns:
            List of loaded configuration file paths
        """
        return self._config_files.copy()


# Create the singleton instance
config_manager = ConfigManager() 