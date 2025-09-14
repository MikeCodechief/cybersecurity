#!/usr/bin/env python3
"""
Integrated Network Reconnaissance Tool
Combines multiple network tools for comprehensive scanning
"""

import subprocess
import json
import xml.etree.ElementTree as ET
import os
import sys
from datetime import datetime
import threading
import time

class NetworkReconTool:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'nmap_results': {},
            'sniff_data': [],
            'network_info': {}
        }
        
    def check_dependencies(self):
        """Check if required tools are installed"""
        tools = {
            'nmap': 'nmap --version',
            'tshark': 'tshark --version',
            'arp': 'arp',
            'netstat': 'netstat --version'
        }
        
        available = {}
        for tool, cmd in tools.items():
            try:
                subprocess.run(cmd.split(), capture_output=True, check=True)
                available[tool] = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                available[tool] = False
                print(f"Warning: {tool} not found. Some features unavailable.")
        
        return available
    
    def nmap_scan(self, target, scan_type='basic'):
        """Enhanced NMAP scanning with multiple techniques"""
        scan_configs = {
            'basic': '-sn',  # Ping scan
            'port': '-sS -O',  # SYN scan with OS detection
            'aggressive': '-A -T4',  # Aggressive scan
            'stealth': '-sS -T2 -f',  # Stealth scan
            'udp': '-sU --top-ports 100',  # UDP scan
            'vuln': '--script vuln'  # Vulnerability scan
        }
        
        cmd = f"nmap {scan_configs.get(scan_type, '-sn')} -oX - {target}"
        
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                # Parse XML output
                root = ET.fromstring(result.stdout)
                hosts = []
                
                for host in root.findall('.//host'):
                    host_info = {}
                    
                    # IP Address
                    addr = host.find('.//address[@addrtype="ipv4"]')
                    if addr is not None:
                        host_info['ip'] = addr.get('addr')
                    
                    # MAC Address
                    mac = host.find('.//address[@addrtype="mac"]')
                    if mac is not None:
                        host_info['mac'] = mac.get('addr')
                        host_info['vendor'] = mac.get('vendor', '')
                    
                    # Hostname
                    hostname = host.find('.//hostname')
                    if hostname is not None:
                        host_info['hostname'] = hostname.get('name')
                    
                    # OS Detection
                    os_info = host.find('.//osmatch')
                    if os_info is not None:
                        host_info['os'] = os_info.get('name')
                        host_info['accuracy'] = os_info.get('accuracy')
                    
                    # Open Ports
                    ports = []
                    for port in host.findall('.//port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            port_info = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': port.find('service').get('name') if port.find('service') is not None else ''
                            }
                            ports.append(port_info)
                    host_info['ports'] = ports
                    
                    if host_info:
                        hosts.append(host_info)
                
                self.results['nmap_results'][scan_type] = hosts
                return hosts
                
        except Exception as e:
            print(f"NMAP scan failed: {e}")
            return []
    
    def packet_capture(self, interface='any', duration=30, packet_count=100):
        """Capture network packets using tshark"""
        try:
            # Basic packet capture
            cmd = f"tshark -i {interface} -c {packet_count} -T json"
            
            print(f"Starting packet capture for {duration} seconds...")
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            # Set timer to kill process after duration
            timer = threading.Timer(duration, process.terminate)
            timer.start()
            
            stdout, stderr = process.communicate()
            timer.cancel()
            
            if stdout:
                try:
                    # Parse JSON output
                    packets = json.loads(stdout)
                    
                    # Extract relevant information
                    parsed_packets = []
                    for packet in packets:
                        if '_source' in packet:
                            layers = packet['_source']['layers']
                            packet_info = {
                                'timestamp': packet.get('_source', {}).get('layers', {}).get('frame', {}).get('frame.time'),
                                'src_ip': layers.get('ip', {}).get('ip.src'),
                                'dst_ip': layers.get('ip', {}).get('ip.dst'),
                                'protocol': layers.get('ip', {}).get('ip.proto'),
                                'length': layers.get('frame', {}).get('frame.len')
                            }
                            parsed_packets.append(packet_info)
                    
                    self.results['sniff_data'] = parsed_packets
                    return parsed_packets
                    
                except json.JSONDecodeError:
                    print("Failed to parse packet capture data")
                    
        except Exception as e:
            print(f"Packet capture failed: {e}")
            
        return []
    
    def network_topology_discovery(self):
        """Discover network topology using multiple methods"""
        topology = {}
        
        # Get routing table
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            else:  # Linux/Mac
                result = subprocess.run(['route', '-n'], capture_output=True, text=True)
            
            topology['routing_table'] = result.stdout
        except Exception as e:
            print(f"Failed to get routing table: {e}")
        
        # Get ARP table
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            topology['arp_table'] = result.stdout
        except Exception as e:
            print(f"Failed to get ARP table: {e}")
        
        # Get network interfaces
        try:
            if os.name != 'nt':
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                topology['interfaces'] = result.stdout
        except Exception as e:
            print(f"Failed to get interfaces: {e}")
        
        self.results['network_info'] = topology
        return topology
    
    def snmp_walk(self, target, community='public', oid='1.3.6.1.2.1.1'):
        """SNMP walking for network device information"""
        try:
            cmd = f"snmpwalk -v2c -c {community} {target} {oid}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return result.stdout.split('\n')
            else:
                print(f"SNMP walk failed for {target}")
                
        except Exception as e:
            print(f"SNMP error: {e}")
            
        return []
    
    def vulnerability_scan(self, target):
        """Run vulnerability scans using NMAP scripts"""
        vuln_scripts = [
            '--script vuln',
            '--script smb-vuln*',
            '--script http-vuln*',
            '--script ssl*'
        ]
        
        vulnerabilities = {}
        
        for script in vuln_scripts:
            try:
                cmd = f"nmap {script} {target}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=180)
                
                if result.returncode == 0:
                    script_name = script.replace('--script ', '')
                    vulnerabilities[script_name] = result.stdout
                    
            except Exception as e:
                print(f"Vulnerability scan failed for {script}: {e}")
        
        return vulnerabilities
    
    def comprehensive_scan(self, target_network, capture_duration=30):
        """Run comprehensive network reconnaissance"""
        print(f"Starting comprehensive scan of {target_network}")
        print("=" * 60)
        
        # Check dependencies
        available_tools = self.check_dependencies()
        
        # Phase 1: Basic Network Discovery
        print("Phase 1: Network Discovery...")
        if available_tools.get('nmap'):
            hosts = self.nmap_scan(target_network, 'basic')
            print(f"Found {len(hosts)} hosts")
            
            # Phase 2: Detailed Port Scanning
            print("Phase 2: Port Scanning...")
            for host in hosts[:5]:  # Limit to first 5 hosts
                ip = host.get('ip')
                if ip:
                    detailed_info = self.nmap_scan(ip, 'port')
                    if detailed_info:
                        host.update(detailed_info[0])
        
        # Phase 3: Network Topology
        print("Phase 3: Network Topology Discovery...")
        topology = self.network_topology_discovery()
        
        # Phase 4: Packet Capture (if tshark available)
        if available_tools.get('tshark'):
            print(f"Phase 4: Packet Capture ({capture_duration}s)...")
            try:
                packets = self.packet_capture(duration=capture_duration)
                print(f"Captured {len(packets)} packets")
            except PermissionError:
                print("Packet capture requires root/admin privileges")
        
        return self.results
    
    def generate_report(self, output_file='recon_report.json'):
        """Generate comprehensive report"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            # Generate human-readable summary
            summary_file = output_file.replace('.json', '_summary.txt')
            with open(summary_file, 'w') as f:
                f.write("Network Reconnaissance Report\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n\n")
                
                # Host summary
                for scan_type, hosts in self.results['nmap_results'].items():
                    f.write(f"\n{scan_type.upper()} SCAN RESULTS:\n")
                    f.write("-" * 30 + "\n")
                    for host in hosts:
                        f.write(f"IP: {host.get('ip', 'Unknown')}\n")
                        f.write(f"Hostname: {host.get('hostname', 'Unknown')}\n")
                        f.write(f"MAC: {host.get('mac', 'Unknown')}\n")
                        f.write(f"OS: {host.get('os', 'Unknown')}\n")
                        f.write(f"Open Ports: {len(host.get('ports', []))}\n")
                        f.write("-" * 20 + "\n")
                
                # Packet capture summary
                if self.results['sniff_data']:
                    f.write(f"\nPACKET CAPTURE: {len(self.results['sniff_data'])} packets\n")
            
            print(f"\nReports saved:")
            print(f"- Detailed: {output_file}")
            print(f"- Summary: {summary_file}")
            
        except Exception as e:
            print(f"Report generation failed: {e}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python integrated_scanner.py <target_network>")
        print("Example: python integrated_scanner.py 192.168.1.0/24")
        sys.exit(1)
    
    target = sys.argv[1]
    
    scanner = NetworkReconTool()
    
    try:
        results = scanner.comprehensive_scan(target)
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Scan failed: {e}")

if __name__ == "__main__":
    main()
