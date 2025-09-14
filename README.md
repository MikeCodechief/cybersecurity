# Cybersecurity
While I am still completing Google Cybersecurity certificate, This repo will have more update in the future.
I jsut fork GhostESP for creating a new version of hardware based on using ESP32-C3 with 1.8 TFT LCD and add GPS as new version of GhostESP
https://github.com/MikeCodechief/cybersecurity-Ghost_ESP
The new update for this repo will make it more closer to ESP Marauder 

# LAN Network Scanner

A Python-based network reconnaissance tool for discovering and analyzing devices on Local Area Networks (LANs). This tool is designed for cybersecurity professionals, network administrators, and penetration testers to perform network discovery and basic host enumeration.

## 🔍 Features

- **Automated Network Discovery**: Automatically detects local network range and gateway
- **Multi-threaded Scanning**: Concurrent host discovery for faster results
- **Comprehensive Host Enumeration**:
  - ICMP ping sweep
  - TCP port scanning on common services
  - Hostname resolution via reverse DNS
  - MAC address discovery through ARP
- **Cross-platform Compatibility**: Works on Windows, Linux, and macOS
- **Detailed Reporting**: Formatted output with option to save results
- **Customizable Port Lists**: Easy modification of target ports

## 🛡️ Ethical Use Statement

This tool is intended for:
- ✅ Network administration and monitoring
- ✅ Authorized penetration testing
- ✅ Security assessments of your own networks
- ✅ Educational purposes and learning

**⚠️ Important**: Only use this tool on networks you own or have explicit permission to test. Unauthorized network scanning may violate local laws and organizational policies.

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- Standard Python libraries (no additional packages required)

### Setup
```bash
# Clone the repository
git clone https://github.com/your-username/lan-network-scanner.git
cd lan-network-scanner

# Make the script executable (Linux/macOS)
chmod +x lan_scanner.py
```

## 📖 Usage

### Basic Usage
```bash
python lan_scanner.py
```

### Advanced Usage
The scanner automatically detects your network configuration, but you can modify the code for specific requirements:

```python
# Modify port list for custom services
ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995]

# Adjust thread count for performance tuning
scanner.scan_network(max_threads=100)
```

## 📊 Sample Output

```
LAN Computer Scanner
===================
Scanning network: 192.168.1.0/24
Local IP: 192.168.1.100
==================================================
Found: 192.168.1.1 (router.local)
Found: 192.168.1.50 (desktop-pc)
Scanned 254/254 addresses...

Scan completed in 45.32 seconds
Found 8 active hosts

================================================================================
ACTIVE HOSTS ON NETWORK
================================================================================
IP Address      Hostname                  MAC Address        Open Ports
--------------------------------------------------------------------------------
192.168.1.1     router.local              aa:bb:cc:dd:ee:ff  22, 80, 443
192.168.1.25    Unknown                   11:22:33:44:55:66  445
192.168.1.50    desktop-pc                aa:11:bb:22:cc:33  135, 445
192.168.1.101   smartphone.local          Unknown            None detected
```

## 🔧 Technical Details

### Network Discovery Process
1. **Local IP Detection**: Uses socket connection to determine local interface
2. **Network Range Calculation**: Assumes /24 CIDR (configurable)
3. **Host Discovery**: ICMP ping sweep across entire subnet
4. **Service Enumeration**: TCP connect scan on predefined ports
5. **Information Gathering**: DNS reverse lookup and ARP table queries

### Default Scanned Ports
- 22 (SSH)
- 23 (Telnet)
- 53 (DNS)
- 80 (HTTP)
- 135 (RPC)
- 139 (NetBIOS)
- 443 (HTTPS)
- 445 (SMB)
- 993 (IMAPS)
- 995 (POP3S)

## 🔒 Security Considerations

### Detection Evasion
- **VPN Impact**: Devices using VPN may not appear in scans
- **Firewall Filtering**: Modern devices often block ICMP and limit port responses
- **MAC Randomization**: Mobile devices may randomize MAC addresses
- **Private WiFi**: iOS/Android privacy features can hide devices

### Network Limitations
- Works best on same subnet (/24 networks)
- Some corporate networks may have additional segmentation
- Router ACLs might limit cross-device visibility
- Requires appropriate network permissions

## 🛠️ Troubleshooting

### Common Issues
1. **No devices found**: Check if devices have firewalls enabled
2. **Permission denied**: Run with administrator/sudo privileges for full MAC discovery
3. **Slow scanning**: Reduce thread count or increase timeouts
4. **Missing hostnames**: DNS resolution may be disabled on some devices

### Performance Optimization
```python
# Adjust for faster scanning (less reliable)
scanner.scan_network(max_threads=100)

# Adjust for more reliable results (slower)
scanner.scan_network(max_threads=20)
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for complying with all applicable local, state, and federal laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
# Fork the repository
# Clone your fork
git clone https://github.com/your-username/lan-network-scanner.git

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes and commit
git commit -am 'Add some feature'

# Push to the branch
git push origin feature/your-feature-name

# Submit a Pull Request
```

## 📚 Related Projects

- [Nmap](https://nmap.org/) - Advanced network discovery and security auditing
- [Masscan](https://github.com/robertdavidgraham/masscan) - Fast port scanner
- [arp-scan](https://github.com/royhills/arp-scan) - ARP-based network discovery

## 🏷️ Tags

`cybersecurity` `network-scanning` `penetration-testing` `reconnaissance` `python` `security-tools` `network-discovery` `ethical-hacking`
