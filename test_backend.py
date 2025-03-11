#!/usr/bin/env python3
"""
Wrapper script to run the network scanner backend tester.
"""

import sys
import os
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("test_backend")

# Check for root/sudo privileges
def check_privileges():
    """Check if the script is running with root/sudo privileges."""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix/Linux/MacOS
        return os.geteuid() == 0

# Warn if not running with sufficient privileges
if not check_privileges():
    logger.warning("⚠️  Running without root/sudo privileges!")
    logger.warning("Some scanning features (ARP scanning, ICMP ping) may not work correctly.")
    logger.warning("Consider restarting with 'sudo python test_backend.py ...'")
    # Give the user a moment to read the warning
    time.sleep(2)

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the backend tester
from network_scanner.tools.backend_tester import main

if __name__ == "__main__":
    main() 