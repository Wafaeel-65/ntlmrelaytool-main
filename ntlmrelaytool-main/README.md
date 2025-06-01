# NTLM Relay Tool

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive framework for capturing, analyzing, and relaying NTLM authentication attempts on network interfaces. This tool supports real-time packet capture, authentication poisoning, credential relaying to multiple service types, and centralized storage of results in MongoDB.

## 🚨 Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.** Users must:
- Have explicit written permission to test target networks
- Comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Not use this tool for malicious purposes

## ✨ Features

- **Multi-mode Operation**: Poison, relay, attack, and analysis modes
- **Protocol Support**: SMB, LDAP, HTTP/HTTPS endpoint relaying  
- **Real-time Capture**: Live NTLM authentication monitoring with scapy
- **Hash Processing**: NTLM hash extraction, analysis, and optional cracking
- **Persistent Storage**: MongoDB integration for authentication events and results
- **Network Poisoning**: Built-in responder for LLMNR/NBT-NS poisoning
- **Concurrent Operations**: Simultaneous poisoning and relaying capabilities
- **Extensible Architecture**: Modular design for easy customization

## 🔧 Requirements

### System Requirements
- **Python**: 3.11 or higher
- **Operating System**: Windows (WinPcap/Npcap), Linux, macOS
- **Privileges**: Administrator/root privileges required for packet capture
- **Database**: MongoDB instance (local or remote)

### Network Requirements
- Network interface with packet capture capabilities
- Target network access for relay operations
- Appropriate firewall configurations

## 📦 Installation

### Quick Setup
```bash
git clone https://github.com/Wafaeel-65/ntlmrelaytool.git
cd ntlmrelaytool
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS  
source venv/bin/activate

pip install -r requirements.txt
```

### Windows-Specific Setup
1. Install [Npcap](https://nmap.org/npcap/) for packet capture
2. Ensure you're running PowerShell as Administrator
3. Verify network interface access

### Linux Setup
```bash
# Install libpcap development files
sudo apt-get update
sudo apt-get install libpcap-dev python3-dev

# For packet capture without root (optional)
sudo setcap cap_net_raw+ep $(which python3)
```

## ⚙️ Configuration

### Database Setup
1. **MongoDB**: Start a local MongoDB instance or configure remote connection
   ```bash
   # Using Docker (recommended)
   python scripts/setup_mongodb.py
   
   # Or install MongoDB locally
   # Windows: Download from https://www.mongodb.com/try/download/community
   # Linux: sudo apt install mongodb
   ```

2. **Initialize Database Collections**:
   ```bash
   python scripts/setup_db.py
   ```

### Configuration Files
Copy and customize the configuration files:

```bash
# Copy default configurations
cp config/logging.ini.example config/logging.ini
cp config/mongodb.ini.example config/mongodb.ini
```

**`config/mongodb.ini`** - Database configuration:
```ini
[mongodb]
host = localhost
port = 27017
database = ntlm_relay
username = 
password = 
auth_source = admin
connection_timeout = 5000
```

**`config/logging.ini`** - Logging configuration:
```ini
[logger_root]
level=INFO
handlers=consoleHandler
```

## 🚀 Usage

### Prerequisites
- Run as Administrator/root for packet capture
- Ensure MongoDB is running
- Configure network interfaces

### List Network Interfaces
```bash
python scripts/list_interfaces.py
```

### Basic Commands

#### 1. Poisoning Mode (LLMNR/NBT-NS)
Capture NTLM authentication attempts through network poisoning:
```bash
python src/main.py poison --interface eth0
```

#### 2. Relay Mode
Relay captured NTLM authentication to target services:
```bash
# SMB relay
python src/main.py relay --interface eth0 --target 192.168.1.100

# LDAP relay
python src/main.py relay --interface eth0 --target ldap://192.168.1.100

# HTTP relay
python src/main.py relay --interface eth0 --target http://192.168.1.100
```

#### 3. Attack Mode (Combined)
Run poisoning and relaying simultaneously:
```bash
python src/main.py attack --interface eth0 --target 192.168.1.100
```

#### 4. List Captured Results
View stored authentication attempts and results:
```bash
python src/main.py list
```

### Advanced Usage

#### Debug Mode
Enable verbose logging for troubleshooting:
```bash
python src/main.py poison --interface eth0 --debug
```

#### Multiple Targets
For complex environments, edit the relay configuration to support multiple targets.

## 📁 Project Structure

```
ntlmrelaytool/
├── src/
│   ├── main.py                 # Main application entry point
│   ├── modules/
│   │   ├── capture/            # Packet capture and poisoning
│   │   │   ├── parser.py       # NTLM packet parsing
│   │   │   └── responder.py    # LLMNR/NBT-NS responder
│   │   ├── exploit/            # Attack modules
│   │   │   ├── relay.py        # NTLM relay functionality
│   │   │   ├── cracker.py      # Hash cracking utilities
│   │   │   └── ntlmrelayserver.py # Relay server implementation
│   │   └── storage/            # Data persistence
│   │       ├── database.py     # Database operations
│   │       └── models.py       # Data models
│   └── utils/                  # Utility modules
│       ├── config.py           # Configuration management
│       ├── hash_handler.py     # NTLM hash processing
│       ├── logger.py           # Logging utilities
│       ├── mongo_handler.py    # MongoDB interface
│       └── packet_sniffer.py   # Network packet capture
├── config/                     # Configuration files
├── docs/                       # Documentation
├── scripts/                    # Utility scripts
├── tests/                      # Unit tests
└── data/                       # Data files and wordlists
```

## 🧪 Testing

Run the test suite to ensure everything is working correctly:

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=src

# Run specific test modules
pytest tests/test_capture.py
pytest tests/test_exploit.py
pytest tests/test_storage.py

# Test database connectivity
python scripts/test_mongodb.py

# Test hash handling
python scripts/test_hash_handler.py
```

## 🔧 Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Windows: Run PowerShell as Administrator
# Linux/macOS: Use sudo or set capabilities
sudo setcap cap_net_raw+ep $(which python3)
```

#### MongoDB Connection Issues
```bash
# Check MongoDB status
python scripts/test_mongodb.py

# Start MongoDB manually
mongod --dbpath /data/db
```

#### Network Interface Problems
```bash
# List available interfaces
python scripts/list_interfaces.py

# Check interface permissions
# Windows: Ensure Npcap is installed
# Linux: Check if interface supports monitor mode
```

#### Import Errors
```bash
# Ensure all dependencies are installed
pip install -r requirements.txt

# Check Python path
python -c "import sys; print(sys.path)"
```

### Debug Mode
Enable debug logging for detailed troubleshooting:
```bash
python src/main.py poison --interface eth0 --debug
```

### Log Files
- Application logs: `app.log`
- NTLM relay logs: `ntlm_relay.log`
- Configuration: `config/logging.ini`

## 📚 Documentation

For comprehensive documentation, check the `docs/` directory:

- **`user_guide.md`**: Detailed usage instructions and examples
- **`technical.md`**: Technical implementation details
- **`report.md`**: Comprehensive technical report

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov

# Run tests before committing
pytest

# Follow PEP 8 style guidelines
```

## 🔒 Security Considerations

- **Network Isolation**: Test in isolated lab environments
- **Credential Handling**: Secure storage and transmission of captured credentials
- **Logging**: Sanitize logs to prevent credential exposure
- **Access Control**: Restrict tool access to authorized personnel only

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any security testing.

## 🙏 Acknowledgments

- [Impacket](https://github.com/SecureAuthCorp/impacket) for NTLM protocol implementation
- [Scapy](https://scapy.net/) for packet manipulation capabilities
- [MongoDB](https://www.mongodb.com/) for data persistence
- The security research community for NTLM attack methodologies