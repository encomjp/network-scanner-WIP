"""
Plugin Manager - Dynamic module loading and management.

This module handles the discovery, loading, and lifecycle management of plugins.
"""

import importlib
import inspect
import logging
import os
import pkgutil
import sys
from typing import Any, Dict, List, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')

class PluginManager:
    """Manages the discovery, loading and lifecycle of plugins."""
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one plugin manager exists."""
        if cls._instance is None:
            cls._instance = super(PluginManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize the plugin manager if not already initialized."""
        if self._initialized:
            return
            
        self._plugins = {}
        self._plugin_instances = {}
        self._initialized = True
        logger.debug("PluginManager initialized")
    
    def discover_plugins(self, base_package: str, base_class: Type[T]) -> List[Type[T]]:
        """
        Discover all plugins derived from base_class in the base_package.
        
        Args:
            base_package: The package to search for plugins
            base_class: The base class that plugins must inherit from
            
        Returns:
            List of discovered plugin classes
        """
        logger.debug(f"Discovering plugins in {base_package} based on {base_class.__name__}")
        
        discovered_plugins = []
        
        try:
            package = importlib.import_module(base_package)
            package_dir = os.path.dirname(package.__file__)
            
            # Walk through all modules in the package
            for _, name, is_pkg in pkgutil.iter_modules([package_dir]):
                try:
                    module_name = f"{base_package}.{name}"
                    module = importlib.import_module(module_name)
                    
                    # Find all classes in the module that inherit from base_class
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        
                        if (inspect.isclass(attr) and 
                            issubclass(attr, base_class) and 
                            attr != base_class):
                            
                            logger.debug(f"Discovered plugin: {attr.__name__}")
                            discovered_plugins.append(attr)
                            self._plugins[attr.__name__] = attr
                            
                except Exception as e:
                    logger.error(f"Error loading module {name}: {e}")
                    
            logger.info(f"Discovered {len(discovered_plugins)} plugins for {base_class.__name__}")
            
        except Exception as e:
            logger.error(f"Error discovering plugins: {e}")
            
        return discovered_plugins
    
    def load_plugin(self, plugin_class: Type[T], config: Optional[Dict[str, Any]] = None) -> Optional[T]:
        """
        Load a plugin by its class and initialize it with config.
        
        Args:
            plugin_class: The class of the plugin to load
            config: Optional configuration dict to pass to the plugin
            
        Returns:
            Initialized plugin instance or None if loading failed
        """
        logger.debug(f"Loading plugin: {plugin_class.__name__}")
        
        if plugin_class.__name__ in self._plugin_instances:
            logger.debug(f"Plugin {plugin_class.__name__} already loaded")
            return self._plugin_instances[plugin_class.__name__]
        
        try:
            instance = plugin_class()
            
            # Initialize if the plugin has an initialize method and config provided
            if hasattr(instance, 'initialize') and config is not None:
                instance.initialize(config)
                
            self._plugin_instances[plugin_class.__name__] = instance
            logger.info(f"Successfully loaded plugin: {plugin_class.__name__}")
            return instance
            
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_class.__name__}: {e}")
            return None
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin by name.
        
        Args:
            plugin_name: Name of the plugin to unload
            
        Returns:
            True if successfully unloaded, False otherwise
        """
        if plugin_name not in self._plugin_instances:
            logger.warning(f"Plugin {plugin_name} not loaded")
            return False
        
        try:
            instance = self._plugin_instances[plugin_name]
            
            # Call stop method if it exists
            if hasattr(instance, 'stop'):
                instance.stop()
                
            del self._plugin_instances[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Get a loaded plugin instance by name.
        
        Args:
            plugin_name: Name of the plugin to get
            
        Returns:
            Plugin instance or None if not found
        """
        return self._plugin_instances.get(plugin_name)
    
    def get_all_plugins(self) -> Dict[str, Any]:
        """
        Get all loaded plugin instances.
        
        Returns:
            Dictionary of plugin name to instance
        """
        return self._plugin_instances.copy()
    
    def get_available_plugins(self) -> Dict[str, Type]:
        """
        Get all available plugin classes.
        
        Returns:
            Dictionary of plugin name to class
        """
        return self._plugins.copy()


# Create the singleton instance
plugin_manager = PluginManager() 