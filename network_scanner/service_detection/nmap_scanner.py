"""
Nmap Scanner - Integration with Nmap for comprehensive network scanning.

This module integrates with Nmap to provide more comprehensive service detection
and vulnerability scanning capabilities.
"""

import logging
import subprocess
import threading
import re
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import nmap

from network_scanner.core.scheduler import scheduler
from network_scanner.service_detection.base import ServiceDetectionModule

logger = logging.getLogger(__name__)

class NmapScanner(ServiceDetectionModule):
    """Comprehensive network scanner using Nmap."""
    
    def __init__(self):
        """Initialize the Nmap scanner."""
        super().__init__()
        self.target = None
        self.ports = None
        self.scan_arguments = "-sV"  # Version detection by default
        self.interval = 3600  # 1 hour between scans
        self.task_id = None
        self.scanner = nmap.PortScanner()
        self.scan_vulns = False
        logger.debug("NmapScanner initialized")
        
    def initialize(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the Nmap scanner with configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.target = config.get('target')
            self.ports = config.get('ports')
            
            # Handle scan arguments
            self.scan_arguments = config.get('scan_arguments', '-sV')
            
            # Ensure -sV is in scan arguments for version detection
            if "-sV" not in self.scan_arguments:
                self.scan_arguments += " -sV"
                
            # Handle vulnerability scanning
            self.scan_vulns = config.get('scan_vulns', False)
            if self.scan_vulns and "--script=vuln" not in self.scan_arguments:
                self.scan_arguments += " --script=vuln"
                
            self.interval = config.get('interval', 3600)
            
            if self.target:
                logger.info(f"NmapScanner initialized with target: {self.target}")
            else:
                logger.info("NmapScanner initialized without target")
                
            # Test if nmap is available
            try:
                version_output = subprocess.check_output(['nmap', '--version'], text=True)
                logger.info(f"Nmap detected: {version_output.splitlines()[0]}")
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.error(f"Failed to detect Nmap: {e}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error initializing NmapScanner: {e}")
            return False
            
    def start(self) -> bool:
        """
        Start periodic scanning if a target is configured.
        
        Returns:
            True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("NmapScanner already running")
            return False
            
        if not self.target:
            logger.warning("Cannot start NmapScanner without a target")
            return False
            
        try:
            # Schedule periodic scanning
            self.task_id = scheduler.schedule(
                func=self.scan,
                interval=self.interval,
                args=[self.target, self.ports],
                name="NmapScanner"
            )
            
            self.running = True
            logger.info(f"NmapScanner started with interval {self.interval}s")
            
            # Execute first scan immediately
            threading.Thread(target=self.scan, args=[self.target, self.ports]).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting NmapScanner: {e}")
            return False
            
    def stop(self) -> bool:
        """
        Stop periodic scanning.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        if not self.running:
            logger.warning("NmapScanner not running")
            return False
            
        try:
            if self.task_id is not None:
                scheduler.remove_task(self.task_id)
                self.task_id = None
                
            self.running = False
            logger.info("NmapScanner stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping NmapScanner: {e}")
            return False
            
    def scan(self, target: str, ports: Optional[Union[List[int], str]] = None) -> List[Dict[str, Any]]:
        """
        Scan the target using Nmap.
        
        Args:
            target: Target to scan (IP or hostname)
            ports: Optional ports to scan (list of ints or comma-separated string)
            
        Returns:
            List of discovered services
        """
        logger.info(f"Starting Nmap scan of {target}")
        self.last_scan_time = datetime.now()
        
        try:
            # Format ports if provided
            port_spec = None
            if ports:
                if isinstance(ports, list):
                    port_spec = ",".join(str(p) for p in ports)
                else:
                    port_spec = str(ports)
            
            # Run Nmap scan
            arguments = self.scan_arguments
            logger.debug(f"Running Nmap with arguments: {arguments}")
            
            self.scanner.scan(target, ports=port_spec, arguments=arguments)
            
            results = []
            
            # Process scan results
            if target in self.scanner.all_hosts():
                host_data = self.scanner[target]
                
                # Extract OS information if available
                os_info = None
                if 'osmatch' in host_data and host_data['osmatch']:
                    top_match = host_data['osmatch'][0]
                    os_info = {
                        'name': top_match['name'],
                        'accuracy': top_match['accuracy'],
                        'class': top_match.get('osclass', [{'type': 'unknown'}])[0]['type']
                    }
                
                # Extract port/service information
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        service_result = {
                            "ip": target,
                            "port": int(port),
                            "protocol": "tcp",
                            "state": port_data['state'],
                            "service": port_data['name'],
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', ''),
                            "extrainfo": port_data.get('extrainfo', ''),
                            "os_type": os_info['name'] if os_info else 'unknown',
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        # Add vulnerabilities if available
                        if 'script' in port_data:
                            vulns = {}
                            for script_name, output in port_data['script'].items():
                                if script_name.startswith('vuln-'):
                                    vulns[script_name] = output
                                    
                            if vulns:
                                service_result["vulnerabilities"] = vulns
                                
                        results.append(service_result)
                
                # Check UDP ports if scanned
                if 'udp' in host_data:
                    for port, port_data in host_data['udp'].items():
                        service_result = {
                            "ip": target,
                            "port": int(port),
                            "protocol": "udp",
                            "state": port_data['state'],
                            "service": port_data['name'],
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', ''),
                            "extrainfo": port_data.get('extrainfo', ''),
                            "os_type": os_info['name'] if os_info else 'unknown',
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        # Add vulnerabilities if available
                        if 'script' in port_data:
                            vulns = {}
                            for script_name, output in port_data['script'].items():
                                if script_name.startswith('vuln-'):
                                    vulns[script_name] = output
                                    
                            if vulns:
                                service_result["vulnerabilities"] = vulns
                                
                        results.append(service_result)
            
            logger.info(f"Nmap scan completed. Found {len(results)} services on {target}")
            self.last_scan_results = results
            
            # Publish the results
            self.publish_results(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Error during Nmap scan: {e}")
            return []
            
    def scan_vulnerabilities(self, target: str, ports: Optional[Union[List[int], str]] = None) -> List[Dict[str, Any]]:
        """
        Scan the target for vulnerabilities using Nmap.
        
        Args:
            target: Target to scan (IP or hostname)
            ports: Optional ports to scan (list of ints or comma-separated string)
            
        Returns:
            List of discovered vulnerabilities
        """
        # Set vulnerability scanning flag
        old_scan_vulns = self.scan_vulns
        old_args = self.scan_arguments
        
        self.scan_vulns = True
        if "--script=vuln" not in self.scan_arguments:
            self.scan_arguments += " --script=vuln"
            
        try:
            # Perform scan with vulnerability scripts
            results = self.scan(target, ports)
            return results
        finally:
            # Restore original settings
            self.scan_vulns = old_scan_vulns
            self.scan_arguments = old_args
            
    def is_supported(self, target: str) -> bool:
        """
        Check if the target is supported by this service detection module.
        
        Args:
            target: Target to check
            
        Returns:
            True if supported, False otherwise
        """
        # Nmap supports almost all targets
        return True 