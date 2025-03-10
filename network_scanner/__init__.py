"""
Network Scanner - A modular, stealthy network scanner.
"""

__version__ = "0.1.0"

# Import core modules for easier access
from network_scanner.core.event_bus import event_bus
from network_scanner.core.plugin_manager import plugin_manager
from network_scanner.core.config_manager import config_manager
from network_scanner.core.scheduler import scheduler, async_scheduler
from network_scanner.core.logging_setup import setup_logging, get_logger

# Import modules to ensure they're available for plugin discovery
import network_scanner.discovery
import network_scanner.service_detection
import network_scanner.fingerprinting
import network_scanner.data 