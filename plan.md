# Modular Network Scanner Project Plan

## Project Overview

A sophisticated, stealthy, cross-platform network scanner for Linux (primarily Arch) and macOS that discovers devices, identifies operating systems, detects running services, and scans for vulnerabilities, with minimal resource footprint and maximum stealth capabilities.

## Core Design Principles

- High Modularity: Independent components with clean interfaces
- Plugin Architecture: Extensible through standardized plugins
- API-First Design: Well-documented interfaces for all modules
- Agent-Friendly Structure: Consistent patterns across components
- Configuration-Driven: Behavior controlled through config files, not code changes
- Cross-Platform: Runs reliably on Linux and macOS

## Technology Stack

### Backend Language: Python
- Platform-independent implementation
- Rich ecosystem for networking and security tools
- Excellent system integration capabilities
- Support for async operations and multiprocessing

### Frontend Options (by preference)
1. Qt for Python (PySide6)
   - Lightweight, native look-and-feel on both platforms
   - Rich component library for complex visualizations
   - Better performance than Electron-based solutions

2. Flask + WebView
   - Local web server with native WebView wrapper
   - Modern web UI with minimal resource overhead
   - Responsive design that works well on varied displays

3. Tkinter
   - Zero external dependencies (comes with Python)
   - Simple deployment, minimal footprint
   - Lower learning curve for Python developers

## Module Architecture

### 1. Core Framework
network_scanner/
├── core/
│   ├── event_bus.py       # Central message broker
│   ├── plugin_manager.py  # Dynamic module loading
│   ├── config_manager.py  # Configuration handling
│   ├── scheduler.py       # Task scheduling
│   └── logging.py         # Centralized logging

### 2. Discovery Modules
network_scanner/
├── discovery/
│   ├── base.py            # Abstract base class
│   ├── passive_arp.py     # ARP monitoring
│   ├── active_ping.py     # ICMP scanning
│   ├── nmap_scanner.py    # Nmap integration
│   └── mdns_discovery.py  # mDNS/Bonjour

### 3. Fingerprinting Modules
network_scanner/
├── fingerprinting/
│   ├── base.py            # Abstract base class
│   ├── os_detection.py    # OS fingerprinting
│   ├── device_type.py     # Device categorization
│   ├── p0f_integration.py # Passive fingerprinting
│   └── ttl_analyzer.py    # TTL-based detection

### 4. Service Detection Modules
network_scanner/
├── service_detection/
│   ├── base.py            # Abstract base class
│   ├── port_scanner.py    # Port scanning
│   ├── banner_grabber.py  # Service banner analysis
│   ├── ssl_analyzer.py    # SSL/TLS inspection
│   └── service_matcher.py # Service identification

### 5. Vulnerability Scanner Modules
network_scanner/
├── vulnerability/
│   ├── base.py            # Abstract base class
│   ├── nuclei_scanner.py  # Nuclei integration
│   ├── vulners_api.py     # Vulners database
│   ├── cve_matcher.py     # Version-based CVE matching
│   └── openvas_client.py  # OpenVAS/Greenbone

### 6. Data Management Modules
network_scanner/
├── data/
│   ├── base.py            # Abstract base class
│   ├── device_store.py    # Device information
│   ├── network_graph.py   # Network relationships
│   ├── vulnerability_db.py # Vulnerability storage
│   └── exporters/         # Data export formats

### 7. UI Modules
network_scanner/
├── ui/
│   ├── base.py            # Abstract base class
│   ├── cli/               # Command-line interface
│   ├── qt/                # Qt-based GUI
│   ├── web/               # Web-based interface
│   └── api/               # REST API endpoints

### 8. Stealth Modules
network_scanner/
├── stealth/
│   ├── base.py            # Abstract base class
│   ├── timing.py          # Scan timing controls
│   ├── obfuscation.py     # Traffic obfuscation
│   ├── detection_avoidance.py # Anti-IDS techniques
│   └── footprint_reducer.py # Minimize detectability

## Interfaces and APIs

### 1. Standard Module Interface
Every module implements:
- initialize(config): Setup with configuration
- start(): Begin operation
- stop(): Halt operation
- status(): Return current status
- get_capabilities(): List supported features

### 2. Event-Based Communication
- Central event bus for publish/subscribe pattern
- Standardized event format with JSON schema
- Async event handling
- Event persistence for missed messages

### 3. Plugin System
- Dynamically loadable modules
- Standard discovery mechanism
- Version compatibility checking
- Runtime dependency resolution

### 4. Configuration System
- YAML-based configuration
- Environment variable overrides
- Command-line parameter support
- Runtime reconfiguration API

## Agent-Friendly Implementation Pattern

### 1. Module Implementation Template
Example:

from network_scanner.discovery.base import DiscoveryModule

class MyCustomScanner(DiscoveryModule):
    """
    Custom network scanner implementation.
    
    Required config:
        - scan_interval: int - Seconds between scans
        - target_range: str - CIDR notation of scan target
    """
    
    def initialize(self, config):
        """Setup the scanner with provided configuration."""
        self.interval = config.get('scan_interval', 300)
        self.target = config.get('target_range', '192.168.1.0/24')
        return True
        
    def start(self):
        """Begin scanning operation."""
        # Implementation here
        
    # Additional required methods...

### 2. Consistent Method Signatures
All scanners/detectors use consistent methods:
- scan(target): Perform a scan
- get_results(): Return last scan results
- is_supported(target): Check if target can be scanned

### 3. Standardized Result Format
All results follow a standard schema:

{
  "timestamp": "2023-08-17T12:34:56Z",
  "module": "passive_arp",
  "target": "192.168.1.0/24",
  "results": [
    {
      "ip": "192.168.1.10",
      "mac": "00:11:22:33:44:55",
      "confidence": 0.95,
      "attributes": {}
    }
  ],
  "metadata": {}
}

## Key Functional Components

### 1. Network Discovery Capabilities
- Passive Discovery
  - ARP monitoring with Scapy
  - promiscuous mode packet capture
  - mDNS/Bonjour service monitoring

- Active Discovery
  - Configurable python-nmap integration
  - Custom TCP/UDP probe crafting with Scapy
  - ARP scanning for layer 2 discovery

### 2. OS Fingerprinting Capabilities
- p0f integration for passive fingerprinting
- TCP/IP stack behavior analysis
- TTL and window size analysis
- HTTP User-Agent parsing

### 3. Service Detection Capabilities
- Banner grabbing with timeout controls
- Protocol-specific probes
- TLS/SSL certificate analysis
- Service version extraction

### 4. Vulnerability Scanning Capabilities
- Nuclei Integration
  - Template-based scanning
  - Low resource footprint
  - Extensible with custom templates
  - Active community maintenance

- Vulners API Integration
  - Match service versions against known vulnerabilities
  - Offline database support
  - Severity-based categorization

- OpenVAS/Greenbone Integration (optional plugin)
  - Comprehensive scanning capabilities
  - Regular database updates
  - Detailed vulnerability reports

### 5. Stealth Capabilities
- Timing randomization engine
- IP/MAC address rotation
- Traffic pattern analysis to avoid detection
- Self-cloaking capabilities
- ARP cache poisoning detection
- Rate limiting below IDS detection thresholds

## Implementation Architecture

### Privilege Separation
- UI process runs as regular user
- Scanner daemon runs with elevated privileges
- Secure IPC via Unix sockets with authentication
- Proper integration with polkit (Linux) and Authorization Services (macOS)

### Service-Based Design
- Microservices architecture with ZeroMQ messaging
- Individual scanner components can be enabled/disabled
- API-driven design for extensibility
- Plugin system for custom scanners and detectors

### Asynchronous Operation
- Async scanning operations with asyncio
- Non-blocking UI design
- Progress reporting via message queue
- Background scanning capabilities

## Advanced Features

### Visualization
- Interactive network topology maps
- Service relationship diagrams
- Vulnerability severity heat-maps
- Historical change tracking
- Differential reporting between scans

### Self-Protection
- Scanner activity log sanitization
- Encrypted storage of results
- Traffic encryption between components
- Anti-detection measures

## Development and Testing

### Development Tools
- Module scaffold generator
- Schema validation for outputs
- Automated testing framework
- Performance benchmarking tools

### Testing Strategy
- Virtual networks with Docker/Vagrant
- Mock device generation for testing
- Security auditing of the tool itself
- Cross-platform CI/CD pipeline

### Packaging
- Python Poetry for dependency management
- AppImage for Linux distribution
- DMG package for macOS
- Homebrew formula and AUR package

## Implementation Strategy

1. Start with interfaces: Implement the abstract base classes first
2. One module at a time: Complete individual scanning modules independently
3. Integration via event bus: Connect modules through the event system
4. Unit test focus: Each module independently testable
5. Configuration-driven: Behavior controlled through config files

## Security Considerations
- Ethical usage guidelines
- Notification system for critical vulnerabilities
- Safe defaults to prevent accidental DoS
- Responsible disclosure templates 