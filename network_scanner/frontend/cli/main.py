"""
CLI Main - Command-line interface entry point.

This module provides the main command-line interface for the network scanner.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from network_scanner import __version__
from network_scanner.core.config_manager import config_manager
from network_scanner.core.event_bus import event_bus
from network_scanner.core.logging_setup import setup_logging
from network_scanner.core.plugin_manager import plugin_manager
from network_scanner.data.json_store import JSONStore
from network_scanner.discovery.base import DiscoveryModule
from network_scanner.discovery.ping_scanner import PingScanner
from network_scanner.fingerprinting.base import FingerprintingModule
from network_scanner.fingerprinting.ttl_analyzer import TTLAnalyzer
from network_scanner.service_detection.base import ServiceDetectionModule
from network_scanner.service_detection.port_scanner import PortScanner
from network_scanner.service_detection.nmap_scanner import NmapScanner
from network_scanner.frontend.cli.utils import format_duration, format_timestamp

# Initialize console for rich output
console = Console()

@click.group()
@click.version_option(__version__, prog_name="Network Scanner")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    help="Path to configuration file."
)
@click.option(
    "--debug/--no-debug",
    default=False,
    help="Enable debug output."
)
@click.option(
    "--log-file",
    type=click.Path(file_okay=True, dir_okay=False, writable=True),
    help="Path to log file."
)
@click.option(
    "--quiet/--no-quiet",
    default=False,
    help="Suppress output except for results and errors."
)
def cli(config: Optional[str], debug: bool, log_file: Optional[str], quiet: bool) -> None:
    """Network Scanner - A modular, stealthy network scanner."""
    # Setup logging
    log_level = logging.DEBUG if debug else logging.INFO
    setup_logging(
        log_level=log_level,
        log_file=log_file,
        debug_mode=debug,
        log_to_console=not quiet
    )
    
    # Get logger
    logger = logging.getLogger(__name__)
    
    # Load configuration
    if config:
        logger.info(f"Loading configuration from {config}")
        if not config_manager.load_config_file(config):
            logger.error(f"Failed to load configuration from {config}")
            sys.exit(1)
    
    # Load environment variables
    config_manager.load_from_env()
    
    # Initialize data store
    data_store = JSONStore()
    data_store.initialize({})
    
    # Subscribe to events
    def log_event(event):
        if debug:
            logger.debug(f"Event: {event['type']} - {event.get('data', '')}")
    
    event_bus.subscribe("*", log_event)
    
    def store_discovery_results(event):
        data = event.get("data", [])
        if isinstance(data, list):
            for device in data:
                data_store.store("devices", device)
    
    event_bus.subscribe("discovery.results", store_discovery_results)
    
    def store_service_results(event):
        data = event.get("data", [])
        if isinstance(data, list):
            for service in data:
                data_store.store("services", service)
    
    event_bus.subscribe("service.results", store_service_results)
    
    def store_fingerprint_results(event):
        data = event.get("data", {})
        if isinstance(data, dict) and "ip" in data:
            data_store.store("fingerprints", data)
    
    event_bus.subscribe("fingerprint.results", store_fingerprint_results)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP, range, or CIDR notation)."
)
@click.option(
    "--passive/--no-passive",
    default=False,
    help="Use only passive discovery methods."
)
@click.option(
    "--stealth/--no-stealth",
    default=False,
    help="Use stealth mode (slower but less detectable)."
)
@click.option(
    "--timeout",
    type=float,
    default=1.0,
    help="Timeout for network operations in seconds."
)
def discover(target: str, passive: bool, stealth: bool, timeout: float) -> None:
    """Discover devices on the network."""
    logger = logging.getLogger(__name__)
    logger.info(f"Starting discovery on {target}")
    
    # Initialize discovery module
    discovery = PingScanner()
    discovery.initialize({
        "timeout": timeout,
        "stealth_mode": stealth,
        "passive_only": passive
    })
    
    # Start discovery
    if not discovery.start():
        logger.error("Failed to start discovery")
        return
    
    # Perform scan
    with console.status(f"Scanning {target}...", spinner="dots"):
        start_time = time.time()
        results = discovery.scan(target)
        duration = time.time() - start_time
    
    # Stop discovery
    discovery.stop()
    
    # Display results
    if not results:
        console.print(f"No devices found on {target}", style="yellow")
        return
    
    console.print(f"Found {len(results)} devices on {target} in {format_duration(duration)}", style="green")
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP Address")
    table.add_column("Status")
    table.add_column("Method")
    table.add_column("Timestamp")
    
    for device in results:
        table.add_row(
            device["ip"],
            device["status"],
            device["method"],
            format_timestamp(device["timestamp"])
        )
    
    console.print(table)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP or hostname)."
)
@click.option(
    "--ports", "-p",
    help="Ports to scan (comma-separated or range, e.g., '80,443,8080-8090')."
)
@click.option(
    "--stealth/--no-stealth",
    default=False,
    help="Use stealth mode (slower but less detectable)."
)
@click.option(
    "--timeout",
    type=float,
    default=1.0,
    help="Timeout for network operations in seconds."
)
@click.option(
    "--randomize/--no-randomize",
    default=False,
    help="Randomize the order of ports scanned."
)
def services(target: str, ports: Optional[str], stealth: bool, timeout: float, randomize: bool) -> None:
    """Scan for services on a target."""
    logger = logging.getLogger(__name__)
    logger.info(f"Starting service scan on {target}")
    
    # Initialize service detection module
    service_detection = PortScanner()
    service_detection.initialize({
        "timeout": timeout,
        "stealth_mode": stealth,
        "randomize_ports": randomize
    })
    
    # Start service detection
    if not service_detection.start():
        logger.error("Failed to start service detection")
        return
    
    # Perform scan
    with console.status(f"Scanning {target}...", spinner="dots"):
        start_time = time.time()
        results = service_detection.scan(target, ports)
        duration = time.time() - start_time
    
    # Stop service detection
    service_detection.stop()
    
    # Display results
    if not results:
        console.print(f"No services found on {target}", style="yellow")
        return
    
    console.print(f"Found {len(results)} services on {target} in {format_duration(duration)}", style="green")
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP Address")
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("State")
    table.add_column("Banner")
    
    for service in results:
        table.add_row(
            service["ip"],
            str(service["port"]),
            service["protocol"],
            service.get("service", ""),
            service["state"],
            service.get("banner", "")
        )
    
    console.print(table)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to fingerprint (IP or hostname)."
)
@click.option(
    "--confidence",
    type=float,
    default=0.7,
    help="Confidence threshold (0.0-1.0) for fingerprinting results."
)
def fingerprint(target: str, confidence: float) -> None:
    """Fingerprint the operating system of a target."""
    logger = logging.getLogger(__name__)
    logger.info(f"Starting fingerprinting on {target}")
    
    # Initialize fingerprinting module
    fingerprinting = TTLAnalyzer()
    fingerprinting.initialize({
        "confidence_threshold": confidence
    })
    
    # Start fingerprinting
    if not fingerprinting.start():
        logger.error("Failed to start fingerprinting")
        return
    
    # Perform fingerprinting
    with console.status(f"Fingerprinting {target}...", spinner="dots"):
        start_time = time.time()
        result = fingerprinting.fingerprint(target)
        duration = time.time() - start_time
    
    # Stop fingerprinting
    fingerprinting.stop()
    
    # Display results
    if not result or not result.get("os"):
        console.print(f"Could not fingerprint {target}", style="yellow")
        return
    
    console.print(f"Fingerprinted {target} in {format_duration(duration)}", style="green")
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP Address")
    table.add_column("Operating System")
    table.add_column("Confidence")
    table.add_column("TTL")
    table.add_column("Timestamp")
    
    table.add_row(
        result["ip"],
        result["os"],
        f"{result.get('confidence', 0) * 100:.1f}%",
        str(result.get("ttl", "")),
        format_timestamp(result["timestamp"])
    )
    
    console.print(table)


@cli.command()
@click.option(
    "--target", "-t",
    required=True,
    help="Target to scan (IP, range, or CIDR notation)."
)
@click.option(
    "--ports", "-p",
    help="Ports to scan (comma-separated or range, e.g., '80,443,8080-8090')."
)
@click.option(
    "--stealth/--no-stealth",
    default=False,
    help="Use stealth mode (slower but less detectable)."
)
@click.option(
    "--timeout",
    type=float,
    default=1.0,
    help="Timeout for network operations in seconds."
)
@click.option(
    "--fingerprint/--no-fingerprint",
    default=True,
    help="Enable OS fingerprinting."
)
def scan(target: str, ports: Optional[str], stealth: bool, timeout: float, fingerprint: bool) -> None:
    """Perform a comprehensive scan of a target."""
    logger = logging.getLogger(__name__)
    logger.info(f"Starting comprehensive scan on {target}")
    
    # Initialize modules
    discovery = PingScanner()
    discovery.initialize({
        "timeout": timeout,
        "stealth_mode": stealth
    })
    
    service_detection = PortScanner()
    service_detection.initialize({
        "timeout": timeout,
        "stealth_mode": stealth
    })
    
    os_fingerprinting = None
    if fingerprint:
        os_fingerprinting = TTLAnalyzer()
        os_fingerprinting.initialize({})
    
    # Start modules
    if not discovery.start():
        logger.error("Failed to start discovery")
        return
    
    if not service_detection.start():
        logger.error("Failed to start service detection")
        discovery.stop()
        return
    
    if os_fingerprinting and not os_fingerprinting.start():
        logger.error("Failed to start OS fingerprinting")
        discovery.stop()
        service_detection.stop()
        return
    
    # Perform discovery
    with console.status(f"Discovering devices on {target}...", spinner="dots"):
        discovery_results = discovery.scan(target)
    
    if not discovery_results:
        console.print(f"No devices found on {target}", style="yellow")
        discovery.stop()
        service_detection.stop()
        if os_fingerprinting:
            os_fingerprinting.stop()
        return
    
    console.print(f"Found {len(discovery_results)} devices on {target}", style="green")
    
    # Perform service detection and fingerprinting
    all_services = []
    all_fingerprints = []
    
    for device in discovery_results:
        ip = device["ip"]
        
        with console.status(f"Scanning services on {ip}...", spinner="dots"):
            services = service_detection.scan(ip, ports)
            all_services.extend(services)
        
        if os_fingerprinting and device["status"] == "up":
            with console.status(f"Fingerprinting {ip}...", spinner="dots"):
                fingerprint_result = os_fingerprinting.fingerprint(ip)
                if fingerprint_result:
                    all_fingerprints.append(fingerprint_result)
    
    # Stop modules
    discovery.stop()
    service_detection.stop()
    if os_fingerprinting:
        os_fingerprinting.stop()
    
    # Display results
    console.print(f"Scan complete: {len(discovery_results)} devices, {len(all_services)} services, {len(all_fingerprints)} fingerprints", style="green")
    
    # Display devices
    console.print("\nDevices:", style="bold")
    device_table = Table(show_header=True, header_style="bold")
    device_table.add_column("IP Address")
    device_table.add_column("Status")
    device_table.add_column("Method")
    device_table.add_column("Timestamp")
    
    for device in discovery_results:
        device_table.add_row(
            device["ip"],
            device["status"],
            device["method"],
            format_timestamp(device["timestamp"])
        )
    
    console.print(device_table)
    
    # Display services
    if all_services:
        console.print("\nServices:", style="bold")
        service_table = Table(show_header=True, header_style="bold")
        service_table.add_column("IP Address")
        service_table.add_column("Port")
        service_table.add_column("Protocol")
        service_table.add_column("Service")
        service_table.add_column("State")
        service_table.add_column("Banner")
        
        for service in all_services:
            service_table.add_row(
                service["ip"],
                str(service["port"]),
                service["protocol"],
                service.get("service", ""),
                service["state"],
                service.get("banner", "")
            )
        
        console.print(service_table)
    
    # Display fingerprints
    if all_fingerprints:
        console.print("\nOS Fingerprints:", style="bold")
        fingerprint_table = Table(show_header=True, header_style="bold")
        fingerprint_table.add_column("IP Address")
        fingerprint_table.add_column("Operating System")
        fingerprint_table.add_column("Confidence")
        fingerprint_table.add_column("TTL")
        fingerprint_table.add_column("Timestamp")
        
        for fp in all_fingerprints:
            fingerprint_table.add_row(
                fp["ip"],
                fp.get("os", "Unknown"),
                f"{fp.get('confidence', 0) * 100:.1f}%",
                str(fp.get("ttl", "")),
                format_timestamp(fp["timestamp"])
            )
        
        console.print(fingerprint_table)


@cli.command()
def list_modules() -> None:
    """List available modules."""
    logger = logging.getLogger(__name__)
    logger.info("Listing available modules")
    
    # Get available modules
    discovery_modules = plugin_manager.discover_plugins("network_scanner.discovery", DiscoveryModule)
    service_modules = plugin_manager.discover_plugins("network_scanner.service_detection", ServiceDetectionModule)
    fingerprint_modules = plugin_manager.discover_plugins("network_scanner.fingerprinting", FingerprintingModule)
    
    # Display discovery modules
    console.print("\nDiscovery Modules:", style="bold")
    discovery_table = Table(show_header=True, header_style="bold")
    discovery_table.add_column("Name")
    discovery_table.add_column("Description")
    
    for module in discovery_modules:
        name = module.__name__
        doc = module.__doc__ or ""
        description = doc.strip().split("\n")[0] if doc else "No description"
        discovery_table.add_row(name, description)
    
    console.print(discovery_table)
    
    # Display service detection modules
    console.print("\nService Detection Modules:", style="bold")
    service_table = Table(show_header=True, header_style="bold")
    service_table.add_column("Name")
    service_table.add_column("Description")
    
    for module in service_modules:
        name = module.__name__
        doc = module.__doc__ or ""
        description = doc.strip().split("\n")[0] if doc else "No description"
        service_table.add_row(name, description)
    
    console.print(service_table)
    
    # Display fingerprinting modules
    console.print("\nFingerprinting Modules:", style="bold")
    fingerprint_table = Table(show_header=True, header_style="bold")
    fingerprint_table.add_column("Name")
    fingerprint_table.add_column("Description")
    
    for module in fingerprint_modules:
        name = module.__name__
        doc = module.__doc__ or ""
        description = doc.strip().split("\n")[0] if doc else "No description"
        fingerprint_table.add_row(name, description)
    
    console.print(fingerprint_table)


@cli.command()
@click.option(
    "--data-type",
    type=click.Choice(["devices", "services", "fingerprints"]),
    default="devices",
    help="Type of data to display."
)
@click.option(
    "--limit",
    type=int,
    default=50,
    help="Maximum number of records to display."
)
def results(data_type: str, limit: int) -> None:
    """Display stored scan results."""
    logger = logging.getLogger(__name__)
    logger.info(f"Displaying {data_type} results")
    
    # Initialize data store
    data_store = JSONStore()
    data_store.initialize({})
    
    # Get results
    data = data_store.retrieve(data_type)
    
    if not data:
        console.print(f"No {data_type} results found", style="yellow")
        return
    
    # Limit results
    if limit > 0:
        data = data[:limit]
    
    console.print(f"Found {len(data)} {data_type} results", style="green")
    
    # Display results based on data type
    if data_type == "devices":
        table = Table(show_header=True, header_style="bold")
        table.add_column("IP Address")
        table.add_column("Status")
        table.add_column("Method")
        table.add_column("Timestamp")
        
        for device in data:
            table.add_row(
                device["ip"],
                device.get("status", ""),
                device.get("method", ""),
                format_timestamp(device.get("timestamp", ""))
            )
        
        console.print(table)
    
    elif data_type == "services":
        table = Table(show_header=True, header_style="bold")
        table.add_column("IP Address")
        table.add_column("Port")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("State")
        table.add_column("Banner")
        table.add_column("Timestamp")
        
        for service in data:
            table.add_row(
                service["ip"],
                str(service.get("port", "")),
                service.get("protocol", ""),
                service.get("service", ""),
                service.get("state", ""),
                service.get("banner", ""),
                format_timestamp(service.get("timestamp", ""))
            )
        
        console.print(table)
    
    elif data_type == "fingerprints":
        table = Table(show_header=True, header_style="bold")
        table.add_column("IP Address")
        table.add_column("Operating System")
        table.add_column("Confidence")
        table.add_column("TTL")
        table.add_column("Timestamp")
        
        for fp in data:
            table.add_row(
                fp["ip"],
                fp.get("os", "Unknown"),
                f"{fp.get('confidence', 0) * 100:.1f}%",
                str(fp.get("ttl", "")),
                format_timestamp(fp.get("timestamp", ""))
            )
        
        console.print(table)


@cli.command()
def debug_info() -> None:
    """Display debug information."""
    logger = logging.getLogger(__name__)
    logger.info("Displaying debug information")
    
    # Display version information
    console.print("\nVersion Information:", style="bold")
    console.print(f"Network Scanner: {__version__}")
    console.print(f"Python: {sys.version}")
    console.print(f"Platform: {sys.platform}")
    
    # Display configuration
    console.print("\nConfiguration:", style="bold")
    config = config_manager.get_full_config()
    
    for section, values in config.items():
        console.print(f"\n[{section}]", style="blue")
        for key, value in values.items():
            if isinstance(value, dict):
                console.print(f"  {key}:", style="green")
                for subkey, subvalue in value.items():
                    console.print(f"    {subkey}: {subvalue}")
            else:
                console.print(f"  {key}: {value}")
    
    # Display loaded modules
    console.print("\nLoaded Modules:", style="bold")
    plugins = plugin_manager.get_all_plugins()
    
    if not plugins:
        console.print("No modules loaded")
    else:
        for name, plugin in plugins.items():
            console.print(f"{name}: {plugin.__class__.__name__}")
    
    # Display event history
    console.print("\nRecent Events:", style="bold")
    events = event_bus.get_event_history()
    
    if not events:
        console.print("No events recorded")
    else:
        events = events[-10:]  # Show last 10 events
        for event in events:
            console.print(f"{event['timestamp']} - {event['type']}")


@cli.command()
@click.option("--target", "-t", required=True, help="Target to scan using Nmap (IP or hostname).")
@click.option("--ports", "-p", help="Ports to scan (comma-separated or range, e.g., '80,443,8080-8090').")
@click.option("--vuln/--no-vuln", default=False, help="Enable vulnerability scanning using Nmap scripts.")
def nmap(target: str, ports: str, vuln: bool) -> None:
    """Perform an Nmap scan on a target."""
    import time
    logger = logging.getLogger(__name__)
    logger.info(f"Starting Nmap scan on {target}")
    
    # Initialize Nmap scanner
    scanner = NmapScanner()
    scanner.initialize({})
    
    # Perform scan
    with console.status(f"Scanning {target} with Nmap...", spinner="dots"):
        start_time = time.time()
        if vuln:
            results = scanner.scan_vulnerabilities(target, ports)
        else:
            results = scanner.scan(target, ports)
        duration = time.time() - start_time
    
    # Display results
    if not results:
        console.print(f"No services found on {target}", style="yellow")
        return
    
    console.print(f"Found {len(results)} services on {target} in {format_duration(duration)}", style="green")
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("IP Address")
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("State")
    table.add_column("Version")
    
    for service in results:
        table.add_row(
            service["ip"],
            str(service["port"]),
            service["protocol"],
            service.get("service", ""),
            service["state"],
            service.get("version", "")
        )
    
    console.print(table)


def main() -> None:
    """Entry point for the CLI."""
    cli() 