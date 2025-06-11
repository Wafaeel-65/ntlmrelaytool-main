import re
from typing import Dict, List, Optional
import binascii
import struct

def extract_ntlm_info(payload: str) -> Optional[Dict]:
    """
    Extract NTLM information from a captured payload.
    
    Args:
        payload (str): Hex string of captured payload
        
    Returns:
        Optional[Dict]: Dictionary containing parsed NTLM information or None
    """
    try:
        # Convert hex string to bytes
        payload_bytes = binascii.unhexlify(payload)
        
        # Check for NTLMSSP signature
        if b'NTLMSSP' not in payload_bytes:
            return None
            
        # Find NTLMSSP offset
        ntlmssp_offset = payload_bytes.find(b'NTLMSSP')
        if ntlmssp_offset == -1:
            return None
            
        # Extract NTLM message type
        msg_type = struct.unpack("<I", payload_bytes[ntlmssp_offset+8:ntlmssp_offset+12])[0]
        
        # Base result
        result = {
            'type': msg_type,
            'payload': payload,
            'complete_hash': False
        }
            
        # Extract additional info from Type 3 (Authentication) messages
        if msg_type == 3:
            try:
                # Get domain and username using offset/length fields
                ntlm_header = payload_bytes[ntlmssp_offset:]
                
                # Extract domain info
                domain_len = struct.unpack("<H", ntlm_header[28:30])[0]
                domain_offset = struct.unpack("<I", ntlm_header[32:36])[0]
                if domain_len > 0 and domain_offset > 0:
                    domain = ntlm_header[domain_offset:domain_offset+domain_len]
                    try:
                        result['domain'] = domain.decode('utf-16-le')
                    except:
                        result['domain'] = domain.decode('ascii', errors='ignore')
                
                # Extract username info
                username_len = struct.unpack("<H", ntlm_header[36:38])[0]
                username_offset = struct.unpack("<I", ntlm_header[40:44])[0]
                if username_len > 0 and username_offset > 0:
                    username = ntlm_header[username_offset:username_offset+username_len]
                    try:
                        result['username'] = username.decode('utf-16-le')
                    except:
                        result['username'] = username.decode('ascii', errors='ignore')
                
                # Extract host info
                host_len = struct.unpack("<H", ntlm_header[44:46])[0]
                host_offset = struct.unpack("<I", ntlm_header[48:52])[0]
                if host_len > 0 and host_offset > 0:
                    hostname = ntlm_header[host_offset:host_offset+host_len]
                    try:
                        result['hostname'] = hostname.decode('utf-16-le')
                    except:
                        result['hostname'] = hostname.decode('ascii', errors='ignore')
                
                # Mark as complete hash if we have the required fields
                if 'username' in result:
                    result['complete_hash'] = True
                    
            except Exception as e:
                print(f"Warning: Error extracting Type 3 fields: {e}")
                # Continue even if extraction fails - we still have the basic info
                pass
                
        return result
        
    except Exception as e:
        print(f"Error parsing NTLM payload: {e}")
        return None

def parse_hashes(raw_data: str) -> List[Dict]:
    """
    Parse captured NTLM data and extract structured hash information.
    
    Args:
        raw_data (str): Raw captured data
        
    Returns:
        List[Dict]: List of dictionaries containing structured hash information
    """
    hashes = []
    
    # Handle both string and dict input
    if isinstance(raw_data, dict):
        ntlm_info = extract_ntlm_info(raw_data.get('payload', ''))
        if ntlm_info:
            ntlm_info.update({
                'source': raw_data.get('source'),
                'destination': raw_data.get('destination')
            })
            hashes.append(ntlm_info)
    else:
        # Split the raw data into lines
        lines = raw_data.strip().split('\n')
        for line in lines:
            if 'payload' in line.lower():
                try:
                    # Extract payload from log line
                    payload = re.search(r"'payload': '([^']+)'", line)
                    if payload:
                        ntlm_info = extract_ntlm_info(payload.group(1))
                        if ntlm_info:
                            # Extract source/destination from log line
                            source = re.search(r"'source': '([^']+)'", line)
                            dest = re.search(r"'destination': '([^']+)'", line)
                            if source and dest:
                                ntlm_info.update({
                                    'source': source.group(1),
                                    'destination': dest.group(1)
                                })
                            hashes.append(ntlm_info)
                except Exception as e:
                    print(f"Error parsing line: {e}")
                    continue
    
    return hashes