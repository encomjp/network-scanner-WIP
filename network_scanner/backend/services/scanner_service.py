"""
Scanner service implementation.

This module provides services for scanning operations.
"""

from typing import Dict, List, Optional, Any, Union
import logging
import datetime
import sys
import threading
import ipaddress
import queue
import asyncio
import traceback
from functools import partial
from collections import deque
from time import time
import uuid

from network_scanner.core.logging_setup import get_logger
from network_scanner.discovery.ping_scanner import PingScanner
from network_scanner.discovery.network_detector import NetworkDetector
from network_scanner.service_detection.port_scanner import PortScanner
from network_scanner.service_detection.nmap_scanner import NmapScanner
from network_scanner.fingerprinting.ttl_analyzer import TTLAnalyzer
from network_scanner.discovery.scanners.arp_scanner import ARPScanner
from network_scanner.discovery.utils.network import split_network

logger = get_logger(__name__)

class RateLimiter:
    """Rate limiter implementation using token bucket algorithm."""
    
    def __init__(self, rate: float, burst: int = 1):
        self.rate = rate  # tokens per second
        self.burst = burst  # maximum token bucket size
        self.tokens = burst  # current tokens
        self.last_update = time()
        self._lock = threading.Lock()
    
    def acquire(self) -> bool:
        """Try to acquire a token."""
        with self._lock:
            now = time()
            # Add new tokens based on time passed
            time_passed = now - self.last_update
            new_tokens = time_passed * self.rate
            self.tokens = min(self.burst, self.tokens + new_tokens)
            self.last_update = now
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

class ScannerService:
    """Service for managing network scanning operations."""

    def __init__(self):
        """Initialize the scanner service."""
        self._logger = logging.getLogger(__name__)
        self._logger.info("Initializing scanner service")
        
        # Initialize scanner instances
        self._ping_scanner = PingScanner()
        self._arp_scanner = ARPScanner()
        
        # Initialize scan cache
        self._scan_cache = {}
        self._scan_results = {}
        self._scan_status = {}
        
        # Initialize lock for thread safety
        self._lock = threading.RLock()
        
        # Track initialization status
        self._initialized = False
        
        # Start initialization in background
        threading.Thread(target=self._initialize_background, daemon=True).start()
        
        self._scanners = {}
        self._active_scans = 0
        self._scan_queue = asyncio.Queue()
        self._rate_limiters = {
            'network': RateLimiter(rate=0.2),  # 1 request per 5 seconds
            'ping': RateLimiter(rate=0.5),     # 1 request per 2 seconds
            'port': RateLimiter(rate=0.2),     # 1 request per 5 seconds
            'nmap': RateLimiter(rate=0.1),     # 1 request per 10 seconds
            'ttl': RateLimiter(rate=0.5)       # 1 request per 2 seconds
        }
        self._scan_tasks = set()
        self._scan_processor_task = None
        self._initialization_error = None

    def _initialize_background(self):
        """Initialize the service in the background."""
        try:
            # Perform any necessary initialization tasks
            # For example, loading device databases, warming up scanners, etc.
            
            # Pre-fetch network interfaces to speed up later requests
            network_detector = NetworkDetector()
            network_info = network_detector.get_network_info()
            interfaces = network_info.get('interfaces', [])
            self._logger.info(f"Detected {len(interfaces)} network interfaces")
            
            # Try to get default gateway
            try:
                gateway = network_info.get('default_gateway')
                if gateway:
                    self._logger.info(f"Detected default gateway: {gateway}")
                else:
                    self._logger.warning("No default gateway detected")
            except Exception as e:
                self._logger.warning(f"Failed to detect default gateway: {str(e)}")
            
            # Mark as initialized
            with self._lock:
                self._initialized = True
                self._logger.info("Scanner service initialization complete")
        except Exception as e:
            self._logger.error(f"Error during scanner service initialization: {str(e)}")
            self._logger.error(traceback.format_exc())

    def _get_scanner(self, scanner_type: str) -> Any:
        """Get or initialize a scanner by type."""
        if scanner_type not in self._scanners:
            scanner = None
            try:
                if scanner_type == 'ping':
                    scanner = PingScanner()
                elif scanner_type == 'port':
                    scanner = PortScanner()
                elif scanner_type == 'nmap':
                    scanner = NmapScanner()
                elif scanner_type == 'ttl':
                    scanner = TTLAnalyzer()
                elif scanner_type == 'network':
                    scanner = NetworkDetector()
                
                if scanner:
                    try:
                        logger.debug(f"Initializing {scanner_type} scanner")
                        scanner.initialize({})
                        self._scanners[scanner_type] = scanner
                        logger.debug(f"{scanner_type} scanner initialized successfully")
                    except Exception as e:
                        logger.error(f"Error initializing {scanner_type} scanner: {str(e)}")
                        logger.error(traceback.format_exc())
                        return None
            except ImportError as e:
                logger.error(f"Error importing {scanner_type} scanner: {str(e)}")
                logger.error(traceback.format_exc())
                return None
            except Exception as e:
                logger.error(f"Unexpected error initializing {scanner_type} scanner: {str(e)}")
                logger.error(traceback.format_exc())
                return None
        
        return self._scanners.get(scanner_type)

    async def initialize(self) -> bool:
        """Initialize core scanners asynchronously."""
        if self._initialized:
            return True

        try:
            logger.info("Initializing scanner service...")
            
            # Initialize network detector first as it's most commonly used
            network_scanner = self._get_scanner('network')
            if not network_scanner:
                self._initialization_error = "Failed to initialize network detector"
                logger.error(self._initialization_error)
                return False

            # Start the scan queue processor
            if not self._scan_processor_task or self._scan_processor_task.done():
                self._scan_processor_task = asyncio.create_task(self._process_scan_queue())
                logger.debug("Scan queue processor started")
            
            # Pre-initialize ping scanner
            ping_scanner = self._get_scanner('ping')
            if not ping_scanner:
                logger.warning("Failed to initialize ping scanner, will try again when needed")
            
            self._initialized = True
            logger.info("Scanner service core initialization completed")
            return True

        except Exception as e:
            self._initialization_error = f"Error initializing scanner service: {str(e)}"
            logger.error(self._initialization_error)
            logger.error(traceback.format_exc())
            return False

    async def _process_scan_queue(self):
        """Process queued scan requests."""
        logger.debug("Starting scan queue processor")
        while True:
            try:
                # Get the next scan request
                scan_type, func, args, kwargs, future = await self._scan_queue.get()
                
                # Check rate limit
                rate_limiter = self._rate_limiters.get(scan_type)
                if rate_limiter and not rate_limiter.acquire():
                    # If rate limited, requeue with delay
                    logger.debug(f"Rate limited {scan_type} scan, requeueing")
                    await asyncio.sleep(1)
                    await self._scan_queue.put((scan_type, func, args, kwargs, future))
                    continue
                
                try:
                    # Execute the scan
                    logger.debug(f"Executing {scan_type} scan")
                    result = await func(*args, **kwargs)
                    future.set_result(result)
                    logger.debug(f"{scan_type} scan completed successfully")
                except Exception as e:
                    logger.error(f"Error executing {scan_type} scan: {str(e)}")
                    logger.error(traceback.format_exc())
                    future.set_exception(e)
                finally:
                    self._scan_queue.task_done()
                    
            except asyncio.CancelledError:
                logger.info("Scan queue processor cancelled")
                break
            except Exception as e:
                logger.error(f"Error processing scan queue: {e}")
                logger.error(traceback.format_exc())
                await asyncio.sleep(1)  # Prevent tight loop on error

    async def _queue_scan(self, scan_type: str, func, *args, **kwargs) -> Any:
        """Queue a scan request."""
        if not self._initialized:
            logger.error(f"[DEBUG] Scanner service not initialized for {scan_type} scan")
            raise RuntimeError("Scanner service not initialized")
            
        queue_start_time = time()
        logger.info(f"[DEBUG] Queuing {scan_type} scan, current queue size: {self._scan_queue.qsize()}")
        
        future = asyncio.Future()
        await self._scan_queue.put((scan_type, func, args, kwargs, future))
        logger.debug(f"[DEBUG] Queued {scan_type} scan, new queue size: {self._scan_queue.qsize()}")
        
        # Wait for the scan to complete
        logger.info(f"[DEBUG] Waiting for {scan_type} scan to complete...")
        result = await future
        
        # Log completion
        queue_duration = round(time() - queue_start_time, 2)
        logger.info(f"[DEBUG] {scan_type} scan completed after {queue_duration}s in queue")
        
        return result

    async def get_network_info(self) -> Dict[str, Any]:
        """Get network information asynchronously."""
        # Check if we have cached network info that's less than 60 seconds old
        current_time = time()
        with self._lock:
            if hasattr(self, '_network_info_cache') and self._network_info_cache:
                cache_time, cached_info = self._network_info_cache
                # Use cached data if it's less than 60 seconds old
                if current_time - cache_time < 60:
                    logger.debug("Using cached network information")
                    return cached_info
        
        scanner = self._get_scanner('network')
        if not scanner:
            raise RuntimeError("Network detector not available")
        
        # Queue the network detection request
        logger.debug("Queuing network detection request")
        try:
            # Use the simplified local network detection method for faster results
            result = await self._run_in_executor(scanner.get_local_network_info)
            
            # Cache the result
            with self._lock:
                self._network_info_cache = (current_time, result)
                
            return result
        except Exception as e:
            logger.error(f"Error in get_network_info: {str(e)}")
            logger.error(traceback.format_exc())
            # Return a basic error response
            return {
                "interfaces": [{"name": "localhost", "ip": "127.0.0.1", "network": "127.0.0.0/8"}],
                "default_gateway": None,
                "recommended_targets": ["127.0.0.1/32", "192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
            }

    async def discover_devices(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Discover devices asynchronously."""
        scanner = self._get_scanner('ping')
        if not scanner:
            logger.error(f"[DEBUG] Ping scanner not available for target: {target}")
            raise RuntimeError("Ping scanner not available")
        
        logger.info(f"[DEBUG] Queuing device discovery for target: {target}, kwargs: {kwargs}")
        try:
            # Log the scan parameters
            timeout = kwargs.get('timeout', 1.0)
            stealth = kwargs.get('stealth', False)
            passive = kwargs.get('passive', False)
            logger.info(f"[DEBUG] Scan parameters: timeout={timeout}, stealth={stealth}, passive={passive}")
            
            # Queue the scan
            start_time = time()
            results = await self._queue_scan(
                'ping',
                self._run_in_executor,
                partial(scanner.scan, target, **kwargs)
            )
            end_time = time()
            
            # Log the results
            duration = round(end_time - start_time, 2)
            logger.info(f"[DEBUG] Device discovery completed for {target} in {duration}s, found {len(results)} devices")
            
            return results
        except Exception as e:
            logger.error(f"[DEBUG] Error in discover_devices for {target}: {str(e)}")
            logger.error(traceback.format_exc())
            return []

    async def _run_in_executor(self, func, *args, **kwargs):
        """Run a function in the thread pool."""
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, partial(func, *args, **kwargs))
        except Exception as e:
            logger.error(f"Error running in executor: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def scan_ports(
        self, 
        target: str, 
        ports: Optional[Union[List[int], str]] = None,
        timeout: float = 1.0,
        stealth: bool = False,
        randomize: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan ports on the specified target."""
        scanner = self._get_scanner('port')
        if not scanner:
            raise RuntimeError("Port scanner not available")
        
        logger.debug(f"Queuing port scan for target: {target}")
        try:
            return await self._queue_scan(
                'port',
                self._run_in_executor,
                partial(scanner.scan, target, ports, timeout=timeout, stealth=stealth, randomize=randomize)
            )
        except Exception as e:
            logger.error(f"Error in scan_ports: {str(e)}")
            logger.error(traceback.format_exc())
            return []

    async def nmap_scan(
        self, 
        target: str, 
        ports: Optional[Union[List[int], str]] = None,
        vuln: bool = False
    ) -> List[Dict[str, Any]]:
        """Perform an Nmap scan on the specified target."""
        scanner = self._get_scanner('nmap')
        if not scanner:
            raise RuntimeError("Nmap scanner not available")
        
        logger.debug(f"Queuing nmap scan for target: {target}")
        try:
            return await self._queue_scan(
                'nmap',
                self._run_in_executor,
                partial(scanner.scan_vulnerabilities if vuln else scanner.scan, target, ports)
            )
        except Exception as e:
            logger.error(f"Error in nmap_scan: {str(e)}")
            logger.error(traceback.format_exc())
            return []

    async def fingerprint_os(self, target: str, confidence: float = 0.7) -> Dict[str, Any]:
        """Perform OS fingerprinting on the specified target."""
        scanner = self._get_scanner('ttl')
        if not scanner:
            raise RuntimeError("TTL analyzer not available")
        
        logger.debug(f"Queuing OS fingerprinting for target: {target}")
        try:
            return await self._queue_scan(
                'ttl',
                self._run_in_executor,
                partial(scanner.fingerprint, target, confidence)
            )
        except Exception as e:
            logger.error(f"Error in fingerprint_os: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "ip": target,
                "os": "Unknown",
                "confidence": 0.0,
                "ttl": None,
                "timestamp": datetime.datetime.now().isoformat()
            }

    def _increment_active_scans(self):
        """Increment the active scans counter."""
        with self._lock:
            self._active_scans += 1
            logger.debug(f"Active scans: {self._active_scans}")
            
    def _decrement_active_scans(self):
        """Decrement the active scans counter."""
        with self._lock:
            if self._active_scans > 0:
                self._active_scans -= 1
            logger.debug(f"Active scans: {self._active_scans}")

    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the scanner service."""
        return {
            "initialized": self._initialized,
            "active_scans": self._active_scans,
            "queue_size": self._scan_queue.qsize() if hasattr(self, '_scan_queue') else 0,
            "error": self._initialization_error,
            "scanners": {
                scanner_type: scanner_type in self._scanners
                for scanner_type in ['network', 'ping', 'port', 'nmap', 'ttl']
            }
        }

    def is_initialized(self):
        """
        Check if the scanner service is fully initialized.
        
        Returns:
            bool: True if the service is initialized, False otherwise.
        """
        with self._lock:
            return self._initialized
