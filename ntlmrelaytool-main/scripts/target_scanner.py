#!/usr/bin/env python3
"""
Target Scanner - Network discovery and service enumeration for NTLM relay targets
"""

import socket
import threading
import argparse
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import subprocess
import platform

class TargetScanner:
    def __init__(self, max_threads=50):
        self.max_threads = max_threads
        self.results = {
            'smb_hosts': [],
            'http_hosts': [],
            'ldap_hosts': [],
            'all_hosts': []
        }
        
    def scan_port(self, host, port, timeout=2):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def check_smb_signing(self, host):
        """Check if SMB signing is required (affects relay viability)"""
        try:
            # Use nmap if available to check SMB signing
            if platform.system() == "Windows":
                # Try to get SMB info using net view (basic check)
                cmd = f"net view \\\\{host}"
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
                return "accessible" if result.returncode == 0 else "inaccessible"
            else:
                # For Linux, try using smbclient or enum4linux if available
                cmd = f"timeout 5 smbclient -L {host} -N"
                result = subprocess.run(cmd, shell=True, capture_output=True)
                if result.returncode == 0:
                    return "accessible"
                else:
                    return "requires_auth"
        except Exception as e:
            return f"error: {str(e)}"
    
    def scan_host(self, host):
        """Comprehensive scan of a single host"""
        host_info = {
            'ip': host,
            'hostname': None,
            'ports': {},
            'smb_accessible': False,
            'relay_viable': False
        }
        
        # Try to resolve hostname
        try:
            hostname = socket.gethostbyaddr(host)[0]
            host_info['hostname'] = hostname
        except:
            pass
        
        # Common ports to check
        ports_to_check = {
            445: 'SMB',
            139: 'NetBIOS-SSN',
            80: 'HTTP',
            8080: 'HTTP-Alt',
            443: 'HTTPS',
            389: 'LDAP',
            636: 'LDAPS',
            135: 'RPC',
            3389: 'RDP'
        }
        
        # Scan ports
        for port, service in ports_to_check.items():
            if self.scan_port(host, port):
                host_info['ports'][port] = service
                
                # Check if SMB is accessible
                if port == 445:
                    host_info['smb_accessible'] = True
                    smb_status = self.check_smb_signing(host)
                    host_info['smb_status'] = smb_status
                    # SMB relay is generally viable if SMB is accessible and doesn't require signing
                    host_info['relay_viable'] = smb_status in ['accessible', 'requires_auth']
        
        return host_info
    
    def ping_host(self, host):
        """Check if host is alive"""
        try:
            if platform.system() == "Windows":
                cmd = f"ping -n 1 -w 1000 {host}"
            else:
                cmd = f"ping -c 1 -W 1 {host}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_network(self, network, ping_first=True):
        """Scan entire network range"""
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print(f"Error: Invalid network format: {e}")
            return
        
        hosts_to_scan = []
        
        print(f"[*] Scanning network: {network}")
        print(f"[*] Total hosts to check: {net.num_addresses}")
        
        if ping_first:
            print("[*] Phase 1: Discovering live hosts...")
            # First pass: ping sweep to find live hosts
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                ping_futures = {executor.submit(self.ping_host, str(ip)): str(ip) 
                               for ip in net.hosts()}
                
                for future in as_completed(ping_futures):
                    ip = ping_futures[future]
                    try:
                        if future.result():
                            hosts_to_scan.append(ip)
                            print(f"[+] Live host found: {ip}")
                    except Exception as e:
                        print(f"[-] Error pinging {ip}: {e}")
        else:
            hosts_to_scan = [str(ip) for ip in net.hosts()]
        
        print(f"[*] Phase 2: Port scanning {len(hosts_to_scan)} live hosts...")
        
        # Second pass: detailed port scan
        with ThreadPoolExecutor(max_workers=min(self.max_threads, len(hosts_to_scan))) as executor:
            scan_futures = {executor.submit(self.scan_host, host): host 
                           for host in hosts_to_scan}
            
            for future in as_completed(scan_futures):
                host = scan_futures[future]
                try:
                    result = future.result()
                    if result['ports']:  # Only include hosts with open ports
                        self.results['all_hosts'].append(result)
                        
                        # Categorize by service
                        if 445 in result['ports'] or 139 in result['ports']:
                            self.results['smb_hosts'].append(result)
                        if 80 in result['ports'] or 443 in result['ports'] or 8080 in result['ports']:
                            self.results['http_hosts'].append(result)
                        if 389 in result['ports'] or 636 in result['ports']:
                            self.results['ldap_hosts'].append(result)
                        
                        print(f"[+] Host {host}: {', '.join([f'{port}({svc})' for port, svc in result['ports'].items()])}")
                        if result.get('relay_viable'):
                            print(f"    [!] Potential relay target!")
                        
                except Exception as e:
                    print(f"[-] Error scanning {host}: {e}")
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        
        print(f"Total hosts with services: {len(self.results['all_hosts'])}")
        print(f"SMB hosts: {len(self.results['smb_hosts'])}")
        print(f"HTTP hosts: {len(self.results['http_hosts'])}")
        print(f"LDAP hosts: {len(self.results['ldap_hosts'])}")
        
        # Show potential relay targets
        relay_targets = [host for host in self.results['smb_hosts'] if host.get('relay_viable')]
        if relay_targets:
            print(f"\n[!] POTENTIAL RELAY TARGETS ({len(relay_targets)}):")
            for target in relay_targets:
                hostname = f" ({target['hostname']})" if target['hostname'] else ""
                print(f"    {target['ip']}{hostname}")
                if 'smb_status' in target:
                    print(f"        SMB Status: {target['smb_status']}")
        else:
            print("\n[!] No viable relay targets found")
        
        # Show recommended commands
        if relay_targets:
            print(f"\n[*] RECOMMENDED COMMANDS:")
            print(f"# Test poisoning on your interface:")
            print(f"python src/main.py poison --interface eth0")
            print(f"\n# Try relay attacks against targets:")
            for target in relay_targets[:3]:  # Show first 3 targets
                print(f"python src/main.py attack --interface eth0 --target {target['ip']}")

def main():
    parser = argparse.ArgumentParser(description="Network scanner for NTLM relay targets")
    parser.add_argument("network", nargs='?', help="Network to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--no-ping", action="store_true", help="Skip ping sweep phase")
    parser.add_argument("--single-host", help="Scan single host instead of network")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.single_host and not args.network:
        parser.error("Either network or --single-host must be specified")
    if args.single_host and args.network:
        parser.error("Cannot specify both network and --single-host")
    
    scanner = TargetScanner(max_threads=args.threads)
    
    try:
        if args.single_host:
            print(f"[*] Scanning single host: {args.single_host}")
            result = scanner.scan_host(args.single_host)
            print(f"\nResults for {args.single_host}:")
            print(f"Hostname: {result.get('hostname', 'Unknown')}")
            print(f"Open ports: {result['ports']}")
            if result.get('smb_accessible'):
                print(f"SMB Status: {result.get('smb_status', 'Unknown')}")
                print(f"Relay viable: {result.get('relay_viable', False)}")
        else:
            scanner.scan_network(args.network, ping_first=not args.no_ping)
            scanner.print_summary()
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error during scan: {e}")

if __name__ == "__main__":
    main()
