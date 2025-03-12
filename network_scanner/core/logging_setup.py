"""
Logging Setup - Centralized logging configuration.

This module configures logging for the application with different levels,
formatters, and handlers.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional, Union

# ANSI color codes for terminal output
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
BLUE = "\033[34m"

# Define log format constants
DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DEBUG_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s"

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to log levels"""
    
    def __init__(self, fmt=None, datefmt=None, style='%', debug_mode=False):
        super().__init__(fmt, datefmt, style)
        self.debug_mode = debug_mode
        
    def format(self, record):
        # Choose format based on debug mode
        base_format = DEBUG_LOG_FORMAT if self.debug_mode else DEFAULT_LOG_FORMAT
        
        # Apply colors based on log level
        if record.levelno >= logging.CRITICAL:
            colored_format = f"{RED}{base_format}{RESET}"
        elif record.levelno >= logging.ERROR:
            colored_format = f"{RED}{base_format}{RESET}"
        elif record.levelno >= logging.WARNING:
            colored_format = f"{YELLOW}{base_format}{RESET}"
        elif record.levelno >= logging.INFO:
            colored_format = base_format  # No color for INFO
        else:  # DEBUG and below
            colored_format = f"{BLUE}{base_format}{RESET}"
            
        formatter = logging.Formatter(colored_format)
        return formatter.format(record)

def setup_logging(
    log_level: Union[int, str] = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    debug_mode: bool = False,
    log_to_console: bool = True,
    log_to_file: bool = False,
    max_file_size: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5
) -> None:
    """
    Set up application logging with the specified configuration.
    
    Args:
        log_level: Logging level (default: INFO)
        log_file: Path to log file, if log_to_file is True
        debug_mode: Whether to enable debug mode with more verbose output
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        max_file_size: Maximum log file size before rotation
        backup_count: Number of backup log files to keep
    """
    # Convert string log level to numeric if needed
    if isinstance(log_level, str):
        log_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Select log format based on debug mode
    log_format = DEBUG_LOG_FORMAT if debug_mode else DEFAULT_LOG_FORMAT
    plain_formatter = logging.Formatter(log_format)
    colored_formatter = ColoredFormatter(debug_mode=debug_mode)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(colored_formatter)
        console_handler.setLevel(log_level)
        root_logger.addHandler(console_handler)
    
    # Add file handler if requested and log file provided
    if log_to_file and log_file:
        # Ensure directory exists
        log_path = Path(log_file)
        os.makedirs(log_path.parent, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setFormatter(plain_formatter)  # No colors in log file
        file_handler.setLevel(log_level)
        root_logger.addHandler(file_handler)
    
    # Set some libraries to a higher log level to reduce noise
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("scapy").setLevel(logging.WARNING)
    
    # Log the setup
    logging.info(f"Logging initialized with level {logging.getLevelName(log_level)}")
    if debug_mode:
        logging.debug("Debug mode enabled with verbose logging")
    if log_to_file and log_file:
        logging.info(f"Logging to file: {log_file}")
        
def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name, typically __name__ of the calling module
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name) 