# Network Scanner

A sophisticated, modular network scanner designed for Linux and macOS that discovers devices, identifies operating systems, detects running services, and scans for vulnerabilities.

## Features

- **Modular Architecture**: Independent components with clean interfaces
- **Plugin System**: Extend functionality through plugins
- **Cross-Platform**: Runs on Linux and macOS
- **Multiple Scanning Modes**: From passive discovery to active vulnerability scanning
- **Stealth Options**: Configure scan timing and patterns to avoid detection
- **CLI Interface**: Powerful command-line interface with debugging capabilities

## Installation

### Prerequisites

- Python 3.7+
- pip

### Install from Source

```bash
# Clone the repository
git clone https://github.com/username/network-scanner.git
cd network-scanner

# Install the package
pip install -e .
```

## Usage

### Basic Network Scan

```bash
# Scan the local network
netscanner scan --target 192.168.1.0/24

# Passive mode only
netscanner scan --target 192.168.1.0/24 --passive

# With OS fingerprinting
netscanner scan --target 192.168.1.0/24 --fingerprint
```

### Debug Mode

```bash
# Enable debug output
netscanner --debug scan --target 192.168.1.0/24

# Save debug logs to file
netscanner --debug --log-file=debug.log scan --target 192.168.1.0/24
```

## Nmap Integration

The network scanner now includes Nmap integration for enhanced service and vulnerability detection. With this integration, you can scan targets for open ports and perform vulnerability scanning using Nmap scripts.

### Usage

Use the following command to perform an Nmap scan:

    venv/bin/python3 -m network_scanner.ui.cli.main nmap --target <TARGET_IP_OR_HOSTNAME> [--ports <PORTS>] [--vuln]

- --target: Specify the target IP address or hostname.
- --ports: (Optional) Comma-separated list or range of ports to scan (e.g. '80,443,8080-8090').
- --vuln: (Optional) Enable vulnerability scanning using Nmap scripts.

### Example

    venv/bin/python3 -m network_scanner.ui.cli.main nmap --target 192.168.1.254 --ports 22,80,443 --vuln

This will perform a scan on the target, listing open services and checking for known vulnerabilities.

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT License 