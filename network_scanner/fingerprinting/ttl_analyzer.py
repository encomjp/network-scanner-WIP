"""
TTL Analyzer - OS fingerprinting based on TTL values.

This module uses the Time-To-Live (TTL) values in ping responses to
estimate the operating system of remote devices.
"""

import logging
import socket
import subprocess
import threading
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from network_scanner.core.scheduler import scheduler
from network_scanner.fingerprinting.base import FingerprintingModule

logger = logging.getLogger(__name__)

# TTL ranges for different OS families
# These are approximate and may vary between OS versions and configurations
TTL_SIGNATURES = {
    "windows": {"min": 64, "max": 128, "default": 128},   # Windows typically uses 128
    "unix": {"min": 48, "max": 64, "default": 64},        # Unix/Linux/macOS typically uses 64
    "solaris": {"min": 200, "max": 255, "default": 255},  # Solaris/AIX typically uses 255
    "network_device": {"min": 224, "max": 255, "default": 255}  # Routers/switches typically use 255
}

class TTLAnalyzer(FingerprintingModule):
    """OS fingerprinting using TTL values from ping responses."""
    
    def __init__(self):
        """Initialize the TTL analyzer."""
        super().__init__()
        self.target = None
        self.interval = 3600  # 1 hour between scans
        self.task_id = None
        self.confidence_threshold = 0.7
        self.ping_count = 4
        logger.debug("TTLAnalyzer initialized")
        
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the TTL analyzer with configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.target = config.get('target')
            self.interval = config.get('interval', 3600)
            self.confidence_threshold = config.get('confidence_threshold', 0.7)
            self.ping_count = config.get('ping_count', 4)
            
            if self.target:
                logger.info(f"TTLAnalyzer initialized with target: {self.target}")
            else:
                logger.info("TTLAnalyzer initialized without target")
                
            return True
            
        except Exception as e:
            logger.error(f"Error initializing TTLAnalyzer: {e}")
            return False
            
    def start(self) -> bool:
        """
        Start periodic fingerprinting if a target is configured.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("TTLAnalyzer already running")
            return False
            
        if not self.target:
            logger.warning("Cannot start TTLAnalyzer without a target")
            return False
            
        try:
            # Schedule periodic fingerprinting
            self.task_id = scheduler.schedule(
                func=self.fingerprint,
                interval=self.interval,
                args=[self.target],
                name="TTLAnalyzer"
            )
            
            self.running = True
            logger.info(f"TTLAnalyzer started with interval {self.interval}s")
            
            # Execute first fingerprinting immediately
            threading.Thread(target=self.fingerprint, args=[self.target]).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting TTLAnalyzer: {e}")
            return False
            
    def stop(self) -> bool:
        """
        Stop periodic fingerprinting.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("TTLAnalyzer not running")
            return False
            
        try:
            if self.task_id is not None:
                scheduler.remove_task(self.task_id)
                self.task_id = None
                
            self.running = False
            logger.info("TTLAnalyzer stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping TTLAnalyzer: {e}")
            return False
            
    def _get_ttl_value(self, ip: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Get the TTL value from a ping response.
        
        Args:
            ip: IP address to ping
            
        Returns:
            Tuple of (TTL value, raw output) or (None, None) if failed
        """
        try:
            # Use different ping command based on platform
            import platform
            
            if platform.system().lower() == "windows":
                command = ["ping", "-n", str(self.ping_count), ip]
                ttl_pattern = r"TTL=(\d+)"
            else:  # Linux, Darwin (macOS), etc.
                command = ["ping", "-c", str(self.ping_count), ip]
                ttl_pattern = r"ttl=(\d+)"
                
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Ping failed for {ip}")
                return None, result.stdout
                
            # Extract TTL value using regex
            output = result.stdout
            match = re.search(ttl_pattern, output)
            
            if match:
                ttl = int(match.group(1))
                logger.debug(f"Found TTL value {ttl} for {ip}")
                return ttl, output
            else:
                logger.warning(f"Could not extract TTL value from ping output for {ip}")
                return None, output
                
        except Exception as e:
            logger.error(f"Error getting TTL value for {ip}: {e}")
            return None, None
            
    def _identify_os(self, ttl: int) -> Dict[str, Any]:
        """
        Identify the OS based on TTL value.
        
        Args:
            ttl: TTL value from ping
            
        Returns:
            Dictionary with OS identification and confidence
        """
        results = {}
        
        # Calculate confidence scores for each OS
        for os_name, ttl_range in TTL_SIGNATURES.items():
            if ttl == ttl_range["default"]:
                # Exact match with default TTL
                confidence = 0.9
            elif ttl_range["min"] <= ttl <= ttl_range["max"]:
                # Within the TTL range
                confidence = 0.7
            else:
                # Outside the TTL range
                confidence = 0.0
                
            if confidence > 0:
                results[os_name] = confidence
        
        # Find the OS with highest confidence
        if results:
            best_match = max(results.items(), key=lambda x: x[1])
            os_name, confidence = best_match
            
            return {
                "os": os_name,
                "confidence": confidence,
                "ttl": ttl,
                "matches": results
            }
        else:
            return {
                "os": "unknown",
                "confidence": 0.0,
                "ttl": ttl,
                "matches": {}
            }
            
    def fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Perform OS fingerprinting on the target using TTL analysis.
        
        Args:
            target: Target to fingerprint (IP or hostname)
            
        Returns:
            Fingerprinting results as a dictionary
        """
        logger.info(f"Starting TTL analysis for {target}")
        self.last_scan_time = datetime.now()
        
        try:
            # Resolve hostname to IP if needed
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                logger.error(f"Could not resolve hostname: {target}")
                return {"error": f"Could not resolve hostname: {target}"}
                
            # Get TTL value
            ttl, raw_output = self._get_ttl_value(ip)
            
            if ttl is None:
                result = {
                    "ip": ip,
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": "Could not determine TTL value",
                    "raw_output": raw_output
                }
            else:
                # Identify OS based on TTL
                os_info = self._identify_os(ttl)
                
                result = {
                    "ip": ip,
                    "timestamp": datetime.utcnow().isoformat(),
                    "ttl": ttl,
                    "os": os_info["os"],
                    "confidence": os_info["confidence"],
                    "all_matches": os_info["matches"]
                }
                
                # Only keep results above the confidence threshold
                if os_info["confidence"] < self.confidence_threshold:
                    result["os"] = "unknown"
                    result["notes"] = f"Best guess was {os_info['os']} with confidence {os_info['confidence']:.2f}, below threshold {self.confidence_threshold}"
            
            # Store and publish the result
            self.last_scan_results = [result]
            self.publish_results(result)
            
            logger.info(f"TTL analysis completed for {ip}. OS: {result.get('os', 'unknown')}")
            return result
            
        except Exception as e:
            logger.error(f"Error during TTL analysis: {e}")
            result = {
                "ip": target,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
            self.last_scan_results = [result]
            return result
            
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this fingerprinting module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        try:
            # Check if it's a valid hostname or IP
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False 