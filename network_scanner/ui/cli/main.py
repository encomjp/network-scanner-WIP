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
from network_scanner.ui.cli.utils import format_duration, format_timestamp

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
    """
    Network Scanner - A modular, stealthy network scanner.
    
    This tool helps discover devices on a network, identify their operating
    systems, detect running services, and scan for vulnerabilities.
    """
    # Setup logging
    log_level = "DEBUG" if debug else "INFO"
    setup_logging(
        log_level=log_level,
        log_file=log_file,
        debug_mode=debug,
        log_to_console=not quiet,
        log_to_file=bool(log_file)
    )
    
    logger = logging.getLogger(__name__)
    
    # Load configuration
    if config:
        if config_manager.load_config_file(config):
            logger.info(f"Loaded configuration from {config}")
        else:
            logger.error(f"Failed to load configuration from {config}")
            sys.exit(1)
            
    # Load environment variables
    config_manager.load_from_env()
    
    # Initialize data store
    data_store = JSONStore()
    data_store.initialize({'data_dir': 'data'})
    plugin_manager.load_plugin(JSONStore, {'data_dir': 'data'})
    
    # Register event listeners
    if debug:
        # In debug mode, log all events
        def log_event(event):
            logger.debug(f"Event: {event['type']} - {event.get('data', 'No data')}")
            
        event_bus.subscribe("*", log_event)
    
    # Register data storage event listeners
    def store_discovery_results(event):
        data = event.get('data', {})
        if data and 'results' in data:
            store = plugin_manager.get_plugin('JSONStore')
            if store:
                for result in data['results']:
                    store.store('devices', result)
                    
    def store_service_results(event):
        data = event.get('data', {})
        if data and 'results' in data:
            store = plugin_manager.get_plugin('JSONStore')
            if store:
                for result in data['results']:
                    store.store('services', result)
                    
    def store_fingerprint_results(event):
        data = event.get('data', {})
        if data and 'results' in data:
            store = plugin_manager.get_plugin('JSONStore')
            if store:
                store.store('fingerprints', data['results'])
    
    # Subscribe to events
    event_bus.subscribe("discovery.results", store_discovery_results)
    event_bus.subscribe("service_detection.results", store_service_results)
    event_bus.subscribe("fingerprinting.results", store_fingerprint_results)
    
    logger.debug("CLI initialized")
        
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
    """
    Discover devices on the network.
    
    This command scans the network to find active devices.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting discovery scan of {target}")
    
    # Configure the scanner
    scanner = PingScanner()
    
    config = {
        'target': target,
        'timeout': timeout,
        'stealth_mode': stealth,
        'stealth_delay': 0.5 if stealth else 0.0
    }
    
    if not scanner.initialize(config):
        logger.error("Failed to initialize discovery scanner")
        sys.exit(1)
        
    # Run the scan
    console.print(f"[bold blue]Scanning {target} for devices...[/bold blue]")
    results = scanner.scan(target)
    
    # Display the results
    if not results:
        console.print("[yellow]No devices found.[/yellow]")
        return
        
    # Create a table
    table = Table(title=f"Discovered Devices on {target}")
    table.add_column("IP Address", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Method", style="blue")
    table.add_column("Timestamp", style="yellow")
    
    for device in results:
        table.add_row(
            device["ip"],
            device["status"],
            device["method"],
            format_timestamp(device["timestamp"])
        )
        
    console.print(table)
    console.print(f"[bold green]Found {len(results)} active devices[/bold green]")
    
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
    """
    Detect services running on a target.
    
    This command scans for open ports and identifies services running on them.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting service scan of {target}")
    
    # Configure the scanner
    scanner = PortScanner()
    
    config = {
        'target': target,
        'ports': ports,
        'timeout': timeout,
        'stealth_mode': stealth,
        'stealth_delay': 0.2 if stealth else 0.0,
        'randomize_ports': randomize
    }
    
    if not scanner.initialize(config):
        logger.error("Failed to initialize service scanner")
        sys.exit(1)
        
    # Run the scan
    console.print(f"[bold blue]Scanning {target} for services...[/bold blue]")
    results = scanner.scan(target, ports)
    
    # Display the results
    if not results:
        console.print("[yellow]No open ports found.[/yellow]")
        return
        
    # Create a table
    table = Table(title=f"Detected Services on {target}")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="green")
    table.add_column("State", style="blue")
    table.add_column("Banner", style="yellow")
    
    for service in results:
        banner = service.get("banner", "")
        if banner and len(banner) > 50:
            banner = banner[:47] + "..."
            
        table.add_row(
            str(service["port"]),
            service["service"],
            service["state"],
            banner
        )
        
    console.print(table)
    console.print(f"[bold green]Found {len(results)} open ports[/bold green]")

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
    """
    Perform OS fingerprinting on a target.
    
    This command attempts to identify the operating system of the target.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting OS fingerprinting of {target}")
    
    # Configure the fingerprinter
    fingerprinter = TTLAnalyzer()
    
    config = {
        'target': target,
        'confidence_threshold': confidence,
        'ping_count': 4
    }
    
    if not fingerprinter.initialize(config):
        logger.error("Failed to initialize fingerprinting module")
        sys.exit(1)
        
    # Run the fingerprinting
    console.print(f"[bold blue]Fingerprinting {target}...[/bold blue]")
    result = fingerprinter.fingerprint(target)
    
    # Check for errors
    if "error" in result:
        console.print(f"[red]Error: {result['error']}[/red]")
        return
        
    # Display the results
    if result.get("os") == "unknown":
        console.print("[yellow]Could not determine OS with high confidence.[/yellow]")
        if "notes" in result:
            console.print(f"Note: {result['notes']}")
    else:
        confidence_pct = result.get("confidence", 0) * 100
        console.print(f"[bold green]Detected OS: {result['os']} (Confidence: {confidence_pct:.1f}%)[/bold green]")
        console.print(f"TTL value: {result.get('ttl', 'unknown')}")
        
        # Show all possible matches if in debug mode
        if "all_matches" in result and result["all_matches"]:
            console.print("\nAll potential matches:")
            matches_table = Table()
            matches_table.add_column("OS", style="cyan")
            matches_table.add_column("Confidence", style="green")
            
            for os_name, conf in result["all_matches"].items():
                matches_table.add_row(os_name, f"{conf * 100:.1f}%")
                
            console.print(matches_table)
    
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
    """
    Perform a complete network scan.
    
    This command runs discovery, service detection, and fingerprinting.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Starting complete scan of {target}")
    
    # First, discover devices
    console.print(f"[bold blue]Phase 1: Discovering devices on {target}...[/bold blue]")
    
    discovery_scanner = PingScanner()
    discovery_config = {
        'target': target,
        'timeout': timeout,
        'stealth_mode': stealth,
        'stealth_delay': 0.5 if stealth else 0.0
    }
    
    if not discovery_scanner.initialize(discovery_config):
        logger.error("Failed to initialize discovery scanner")
        sys.exit(1)
        
    discovery_results = discovery_scanner.scan(target)
    
    if not discovery_results:
        console.print("[yellow]No devices found. Scan complete.[/yellow]")
        return
        
    # Create a table for discovery results
    discovery_table = Table(title=f"Discovered Devices on {target}")
    discovery_table.add_column("IP Address", style="cyan")
    discovery_table.add_column("Status", style="green")
    
    for device in discovery_results:
        discovery_table.add_row(
            device["ip"],
            device["status"]
        )
        
    console.print(discovery_table)
    console.print(f"[bold green]Found {len(discovery_results)} active devices[/bold green]")
    
    # Then, scan each device for services
    console.print(f"[bold blue]\nPhase 2: Detecting services on discovered devices...[/bold blue]")
    
    service_scanner = PortScanner()
    service_config = {
        'timeout': timeout,
        'stealth_mode': stealth,
        'stealth_delay': 0.2 if stealth else 0.0
    }
    
    if not service_scanner.initialize(service_config):
        logger.error("Failed to initialize service scanner")
        sys.exit(1)
        
    all_services = []
    
    for device in discovery_results:
        ip = device["ip"]
        console.print(f"Scanning {ip} for services...")
        
        services = service_scanner.scan(ip, ports)
        all_services.extend(services)
        
        if services:
            # Create a table for service results
            service_table = Table(title=f"Services on {ip}")
            service_table.add_column("Port", style="cyan", justify="right")
            service_table.add_column("Service", style="green")
            service_table.add_column("State", style="blue")
            
            for service in services:
                service_table.add_row(
                    str(service["port"]),
                    service["service"],
                    service["state"]
                )
                
            console.print(service_table)
        else:
            console.print(f"No open ports found on {ip}")
    
    # If fingerprinting is enabled, identify OS
    if fingerprint:
        console.print(f"[bold blue]\nPhase 3: Fingerprinting operating systems...[/bold blue]")
        
        os_fingerprinter = TTLAnalyzer()
        os_config = {
            'confidence_threshold': 0.7,
            'ping_count': 4
        }
        
        if not os_fingerprinter.initialize(os_config):
            logger.error("Failed to initialize OS fingerprinting module")
            sys.exit(1)
            
        os_results = []
        
        # Create a table for OS results
        os_table = Table(title="Operating System Detection")
        os_table.add_column("IP Address", style="cyan")
        os_table.add_column("OS", style="green")
        os_table.add_column("Confidence", style="blue")
        os_table.add_column("TTL", style="yellow")
        
        for device in discovery_results:
            ip = device["ip"]
            console.print(f"Fingerprinting {ip}...")
            
            result = os_fingerprinter.fingerprint(ip)
            os_results.append(result)
            
            os_name = result.get("os", "unknown")
            confidence = result.get("confidence", 0)
            ttl = result.get("ttl", "unknown")
            
            os_table.add_row(
                ip,
                os_name,
                f"{confidence * 100:.1f}%" if isinstance(confidence, (int, float)) else "unknown",
                str(ttl)
            )
            
        console.print(os_table)
    
    console.print(f"[bold green]Scan complete. Found {len(all_services)} services across {len(discovery_results)} devices.[/bold green]")
    
@cli.command()
def list_modules() -> None:
    """
    List available scanner modules.
    
    This command lists all available discovery and service detection modules.
    """
    # Discover available modules
    discovery_modules = plugin_manager.discover_plugins("network_scanner.discovery", DiscoveryModule)
    service_modules = plugin_manager.discover_plugins("network_scanner.service_detection", ServiceDetectionModule)
    fingerprinting_modules = plugin_manager.discover_plugins("network_scanner.fingerprinting", FingerprintingModule)
    
    # Display discovery modules
    console.print("[bold blue]Available Discovery Modules:[/bold blue]")
    
    if discovery_modules:
        discovery_table = Table()
        discovery_table.add_column("Module", style="cyan")
        discovery_table.add_column("Description", style="green")
        
        for module_class in discovery_modules:
            name = module_class.__name__
            description = module_class.__doc__ or "No description"
            discovery_table.add_row(name, description.strip())
            
        console.print(discovery_table)
    else:
        console.print("[yellow]No discovery modules found.[/yellow]")
    
    # Display service detection modules
    console.print("\n[bold blue]Available Service Detection Modules:[/bold blue]")
    
    if service_modules:
        service_table = Table()
        service_table.add_column("Module", style="cyan")
        service_table.add_column("Description", style="green")
        
        for module_class in service_modules:
            name = module_class.__name__
            description = module_class.__doc__ or "No description"
            service_table.add_row(name, description.strip())
            
        console.print(service_table)
    else:
        console.print("[yellow]No service detection modules found.[/yellow]")
        
    # Display fingerprinting modules
    console.print("\n[bold blue]Available Fingerprinting Modules:[/bold blue]")
    
    if fingerprinting_modules:
        fingerprinting_table = Table()
        fingerprinting_table.add_column("Module", style="cyan")
        fingerprinting_table.add_column("Description", style="green")
        
        for module_class in fingerprinting_modules:
            name = module_class.__name__
            description = module_class.__doc__ or "No description"
            fingerprinting_table.add_row(name, description.strip())
            
        console.print(fingerprinting_table)
    else:
        console.print("[yellow]No fingerprinting modules found.[/yellow]")

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
    """
    Display stored scan results.
    
    This command displays previously saved scan results.
    """
    data_store = plugin_manager.get_plugin('JSONStore')
    
    if not data_store:
        console.print("[yellow]Data store not initialized. No results available.[/yellow]")
        return
        
    results = data_store.retrieve(data_type)
    
    if not results:
        console.print(f"[yellow]No {data_type} results found.[/yellow]")
        return
        
    # Limit the number of results
    results = results[:limit]
    
    if data_type == "devices":
        # Display device results
        table = Table(title=f"Discovered Devices (Showing {len(results)} of {data_store.count(data_type)})")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Method", style="blue")
        table.add_column("Timestamp", style="yellow")
        
        for device in results:
            table.add_row(
                device.get("ip", "unknown"),
                device.get("status", "unknown"),
                device.get("method", "unknown"),
                format_timestamp(device.get("timestamp", ""))
            )
            
    elif data_type == "services":
        # Display service results
        table = Table(title=f"Detected Services (Showing {len(results)} of {data_store.count(data_type)})")
        table.add_column("IP Address", style="cyan")
        table.add_column("Port", style="green", justify="right")
        table.add_column("Service", style="blue")
        table.add_column("State", style="yellow")
        
        for service in results:
            table.add_row(
                service.get("ip", "unknown"),
                str(service.get("port", "unknown")),
                service.get("service", "unknown"),
                service.get("state", "unknown")
            )
            
    elif data_type == "fingerprints":
        # Display fingerprinting results
        table = Table(title=f"OS Fingerprints (Showing {len(results)} of {data_store.count(data_type)})")
        table.add_column("IP Address", style="cyan")
        table.add_column("OS", style="green")
        table.add_column("Confidence", style="blue")
        table.add_column("TTL", style="yellow")
        
        for fp in results:
            confidence = fp.get("confidence", 0)
            confidence_str = f"{confidence * 100:.1f}%" if isinstance(confidence, (int, float)) else "unknown"
            
            table.add_row(
                fp.get("ip", "unknown"),
                fp.get("os", "unknown"),
                confidence_str,
                str(fp.get("ttl", "unknown"))
            )
            
    console.print(table)
        
@cli.command()
def debug_info() -> None:
    """
    Display debug information.
    
    This command displays system and configuration information for debugging.
    """
    import platform
    
    console.print("[bold blue]Debug Information:[/bold blue]")
    
    # System information
    console.print("[bold]System Information:[/bold]")
    console.print(f"Python version: {platform.python_version()}")
    console.print(f"System: {platform.system()} {platform.release()} ({platform.machine()})")
    
    # Configuration
    console.print("\n[bold]Configuration:[/bold]")
    config = config_manager.get_full_config()
    
    if config:
        config_table = Table()
        config_table.add_column("Key", style="cyan")
        config_table.add_column("Value", style="green")
        
        for key, value in config.items():
            if isinstance(value, dict):
                config_table.add_row(key, f"<dict with {len(value)} items>")
            else:
                config_table.add_row(key, str(value))
                
        console.print(config_table)
    else:
        console.print("[yellow]No configuration loaded.[/yellow]")
    
    # Loaded modules
    console.print("\n[bold]Loaded Modules:[/bold]")
    plugin_dict = plugin_manager.get_all_plugins()
    
    if plugin_dict:
        plugin_table = Table()
        plugin_table.add_column("Module", style="cyan")
        plugin_table.add_column("Type", style="green")
        
        for name, instance in plugin_dict.items():
            if isinstance(instance, DiscoveryModule):
                plugin_type = "Discovery"
            elif isinstance(instance, ServiceDetectionModule):
                plugin_type = "Service Detection"
            elif isinstance(instance, FingerprintingModule):
                plugin_type = "Fingerprinting"
            else:
                plugin_type = "Data Store"
                
            plugin_table.add_row(name, plugin_type)
            
        console.print(plugin_table)
    else:
        console.print("[yellow]No modules loaded.[/yellow]")
    
    # Data store info
    data_store = plugin_manager.get_plugin('JSONStore')
    if data_store:
        console.print("\n[bold]Data Store Information:[/bold]")
        console.print(f"Data directory: {data_store.data_dir}")
        
        data_table = Table()
        data_table.add_column("Type", style="cyan")
        data_table.add_column("Count", style="green")
        
        for data_type in ["devices", "services", "fingerprints"]:
            count = data_store.count(data_type)
            data_table.add_row(data_type, str(count))
            
        console.print(data_table)

def main() -> None:
    """Main entry point for the CLI application."""
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        logging.getLogger(__name__).exception("Unhandled exception")
        sys.exit(1)

if __name__ == "__main__":
    main() 