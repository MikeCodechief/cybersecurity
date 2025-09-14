#!/usr/bin/env python3
"""
LAN Computer Scanner
A Python program to discover computers and devices on the same Local Area Network (LAN)
"""

import socket
import subprocess
import threading
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
import platform
import re

class LANScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network = self.get_network_range()
        self.active_hosts = []
        
    def get_local_ip(self):
        """Get the local IP address of this machine"""
        try:
            # Connect to a remote server to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"
    
    def get_network_range(self):
        """Determine the network range based on local IP"""
        try:
            # Assume /24 subnet (most common for home networks)
            network = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
            return network
        except Exception:
            return ipaddress.IPv4Network("192.168.1.0/24")
    
    def ping_host(self, ip):
        """Ping a single host to check if it's alive"""
        try:
            # Determine ping command based on OS
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def port_scan(self, ip, ports=[22, 23, 53, 80, 135, 139, 443, 445, 993, 995]):
        """Scan common ports on a host"""
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((str(ip), port))
                    if result == 0:
                        open_ports.append(port)
            except Exception:
                continue
        return open_ports
    
    def get_hostname(self, ip):
        """Try to resolve hostname for an IP"""
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except Exception:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Try to get MAC address using ARP (works best on same subnet)"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a", str(ip)], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse Windows ARP output
                    for line in result.stdout.split('\n'):
                        if str(ip) in line:
                            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                            if mac_match:
                                return mac_match.group(0)
            else:
                result = subprocess.run(["arp", "-n", str(ip)], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Parse Linux/Mac ARP output
                    for line in result.stdout.split('\n'):
                        if str(ip) in line:
                            parts = line.split()
                            for part in parts:
                                if re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', part):
                                    return part
        except Exception:
            pass
        return "Unknown"
    
    def scan_host(self, ip):
        """Comprehensive scan of a single host"""
        if self.ping_host(ip):
            hostname = self.get_hostname(ip)
            mac_address = self.get_mac_address(ip)
            open_ports = self.port_scan(ip)
            
            host_info = {
                'ip': str(ip),
                'hostname': hostname,
                'mac': mac_address,
                'ports': open_ports,
                'status': 'active'
            }
            
            self.active_hosts.append(host_info)
            return host_info
        return None
    
    def scan_network(self, max_threads=50):
        """Scan the entire network range"""
        print(f"Scanning network: {self.network}")
        print(f"Local IP: {self.local_ip}")
        print("=" * 50)
        
        start_time = time.time()
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all IP addresses for scanning
            futures = []
            for ip in self.network.hosts():
                future = executor.submit(self.scan_host, ip)
                futures.append(future)
            
            # Process results as they complete
            completed = 0
            for future in futures:
                try:
                    result = future.result(timeout=10)
                    completed += 1
                    
                    # Show progress
                    if completed % 20 == 0:
                        print(f"Scanned {completed}/{len(futures)} addresses...")
                    
                    if result:
                        print(f"Found: {result['ip']} ({result['hostname']})")
                        
                except Exception as e:
                    completed += 1
                    continue
        
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        print(f"Found {len(self.active_hosts)} active hosts")
        
        return self.active_hosts
    
    def display_results(self):
        """Display scan results in a formatted table"""
        if not self.active_hosts:
            print("No active hosts found.")
            return
        
        print("\n" + "=" * 80)
        print("ACTIVE HOSTS ON NETWORK")
        print("=" * 80)
        print(f"{'IP Address':<15} {'Hostname':<25} {'MAC Address':<18} {'Open Ports'}")
        print("-" * 80)
        
        for host in sorted(self.active_hosts, key=lambda x: ipaddress.IPv4Address(x['ip'])):
            ports_str = ", ".join(map(str, host['ports'])) if host['ports'] else "None detected"
            if len(ports_str) > 20:
                ports_str = ports_str[:17] + "..."
            
            print(f"{host['ip']:<15} {host['hostname'][:24]:<25} "
                  f"{host['mac']:<18} {ports_str}")
    
    def save_results(self, filename="lan_scan_results.txt"):
        """Save results to a text file"""
        try:
            with open(filename, 'w') as f:
                f.write(f"LAN Scan Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Network: {self.network}\n")
                f.write(f"Local IP: {self.local_ip}\n")
                f.write("=" * 80 + "\n\n")
                
                for host in sorted(self.active_hosts, key=lambda x: ipaddress.IPv4Address(x['ip'])):
                    f.write(f"IP: {host['ip']}\n")
                    f.write(f"Hostname: {host['hostname']}\n")
                    f.write(f"MAC: {host['mac']}\n")
                    f.write(f"Open Ports: {', '.join(map(str, host['ports'])) if host['ports'] else 'None detected'}\n")
                    f.write("-" * 40 + "\n")
            
            print(f"\nResults saved to: {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    """Main function to run the LAN scanner"""
    print("LAN Computer Scanner")
    print("===================")
    
    scanner = LANScanner()
    
    try:
        # Perform the network scan
        active_hosts = scanner.scan_network()
        
        # Display results
        scanner.display_results()
        
        # Ask user if they want to save results
        if active_hosts:
            save_choice = input("\nSave results to file? (y/n): ").lower().strip()
            if save_choice == 'y':
                scanner.save_results()
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
