# Network Scanner

A sophisticated, modular network scanner designed for Linux and macOS that discovers devices, identifies operating systems, detects running services, and scans for vulnerabilities.

## Features

- **Modular Architecture**: Independent components with clean interfaces
- **Plugin System**: Extend functionality through plugins
- **Cross-Platform**: Runs on Linux and macOS
- **Multiple Scanning Modes**: From passive discovery to active vulnerability scanning
- **Stealth Options**: Configure scan timing and patterns to avoid detection
- **CLI Interface**: Powerful command-line interface with debugging capabilities
- **RESTful API**: Backend API for integration with other tools or custom frontends
- **Web UI**: User-friendly web interface for easier interaction

## Installation

### Prerequisites

- Python 3.7+
- pip
- Root/sudo privileges (required for ARP scanning, ICMP ping, and some port scanning features)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/username/network-scanner.git
cd network-scanner

# Install the package
pip install -e .
```

## Usage

### Command-Line Interface

```bash
# Scan the local network (requires sudo for full functionality)
sudo netscanner scan --target 192.168.1.0/24

# Passive mode only
sudo netscanner scan --target 192.168.1.0/24 --passive

# With OS fingerprinting
sudo netscanner scan --target 192.168.1.0/24 --fingerprint
```

### Debug Mode

```bash
# Enable debug output
sudo netscanner --debug scan --target 192.168.1.0/24

# Save debug logs to file
sudo netscanner --debug --log-file=debug.log scan --target 192.168.1.0/24
```

## Nmap Integration

The network scanner includes Nmap integration for enhanced service and vulnerability detection. With this integration, you can scan targets for open ports and perform vulnerability scanning using Nmap scripts.

### Usage

Use the following command to perform an Nmap scan (requires sudo):

    sudo venv/bin/python3 -m network_scanner.ui.cli.main nmap --target <TARGET_IP_OR_HOSTNAME> [--ports <PORTS>] [--vuln]

- --target: Specify the target IP address or hostname.
- --ports: (Optional) Comma-separated list or range of ports to scan (e.g. '80,443,8080-8090').
- --vuln: (Optional) Enable vulnerability scanning using Nmap scripts.

### Example

    sudo venv/bin/python3 -m network_scanner.ui.cli.main nmap --target 192.168.1.254 --ports 22,80,443 --vuln

This will perform a scan on the target, listing open services and checking for known vulnerabilities.

## Backend API

The network scanner provides a RESTful API that can be used to integrate with other tools or to build custom frontends.

### Starting the API Server

```bash
# Start the API server on localhost:8000 (requires sudo for full scanning functionality)
sudo netscanner-api

# Specify host and port
sudo netscanner-api --host 0.0.0.0 --port 8080

# Enable debug mode
sudo netscanner-api --debug
```

### API Endpoints

- `GET /` - API information
- `GET /api/health` - Health check
- `POST /api/discover` - Discover devices on the network
- `POST /api/port-scan` - Scan ports on a target
- `POST /api/nmap-scan` - Perform an Nmap scan
- `POST /api/fingerprint` - Perform OS fingerprinting

### Example API Request

```bash
# Discover devices on the network
curl -X POST "http://localhost:8000/api/discover" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "passive": false, "stealth": false, "timeout": 1.0}'
```

## Web Interface

The network scanner includes a web-based user interface for easier interaction with the scanning features.

### Starting the Web Interface

```bash
# Start the web interface on localhost:5002 (requires sudo for full scanning functionality)
sudo netscanner-web

# Specify host and port
sudo FLASK_HOST=0.0.0.0 FLASK_PORT=8080 netscanner-web

# Enable debug mode
sudo FLASK_DEBUG=true netscanner-web
```

> **Note:** The web interface runs on port 5002 by default to avoid conflicts with AirPlay/AirTunes services that commonly use port 5000.

### Web UI Features

- **Dashboard**: Overview of recent scan results
- **Device Discovery**: Discover devices on your network
- **Port Scanning**: Scan for open ports and services
- **OS Fingerprinting**: Identify operating systems
- **Nmap Scanning**: Perform comprehensive Nmap scans
- **Results Viewer**: View and manage scan results

### Configuration

The web interface can be configured using environment variables:

- `FLASK_HOST`: Host to bind the web server to (default: 127.0.0.1)
- `FLASK_PORT`: Port to bind the web server to (default: 5002)
- `FLASK_DEBUG`: Enable debug mode (default: False)
- `API_BASE_URL`: URL of the backend API server (default: http://localhost:8000)

## Logging

The application logs detailed information to help with debugging and troubleshooting. Logs are stored in the `log/` directory with timestamped filenames.

To view the logs:

```bash
# View the latest log file
ls -la log/ | sort -r | head -n 1 | xargs cat

# Extract error and warning logs
python extract_logs.py log/your-log-file.log
```

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