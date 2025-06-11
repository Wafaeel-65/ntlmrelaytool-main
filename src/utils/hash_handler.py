import struct
import base64
from typing import Tuple, Dict, List
from passlib.hash import nthash

def process_ntlm_hash(hash_data: Dict) -> Tuple[str, str, str]:
    """
    Process NTLM hash data and extract username, domain, and hash value.
    
    Args:
        hash_data (dict): Dictionary containing NTLM hash data
            Expected format: {
                'username': str,
                'domain': str,
                'hash': str
            }
    
    Returns:
        Tuple[str, str, str]: (username, domain, hash_value)
    """
    username = hash_data.get('username', '')
    domain = hash_data.get('domain', '')
    hash_value = hash_data.get('hash', '')
    
    # Validate hash format
    if hash_value and not _is_valid_ntlm_hash(hash_value):
        raise ValueError("Invalid NTLM hash format")
        
    return username, domain, hash_value

def verify_hash(password: str, ntlm_hash: str) -> bool:
    """
    Verify if a password matches an NTLM hash.
    
    Args:
        password (str): Clear text password to verify
        ntlm_hash (str): NTLM hash to compare against
    
    Returns:
        bool: True if password matches hash, False otherwise
    """
    if not password or not ntlm_hash:
        return False
    
    calculated_hash = calculate_ntlm_hash(password)
    return calculated_hash.lower() == ntlm_hash.lower()

def calculate_ntlm_hash(password: str) -> str:
    """
    Calculate NTLM hash from a password using passlib.
    
    Args:
        password (str): Password to hash
    
    Returns:
        str: NTLM hash of the password
    """
    return nthash.hash(password)

def _is_valid_ntlm_hash(hash_value: str) -> bool:
    """
    Validate NTLM hash format.
    
    Args:
        hash_value (str): Hash value to validate
    
    Returns:
        bool: True if valid NTLM hash format, False otherwise
    """
    if len(hash_value) != 32:
        return False
        
    try:
        int(hash_value, 16)
        return True
    except ValueError:
        return False

def parse_hashes(ntlm_data: Dict) -> List[Dict]:
    """
    Parse NTLM authentication data and extract hash information.
    
    Args:
        ntlm_data (Dict): Dictionary containing source, destination and payload data
            Expected format: {
                'source': str,
                'destination': str,
                'payload': str (hex encoded)
            }
    
    Returns:
        List[Dict]: List of parsed NTLM messages with their details
    """
    results = []
    try:
        payload = bytes.fromhex(ntlm_data['payload'])
        
        # Find NTLMSSP signature
        offset = payload.find(b'NTLMSSP\x00')
        if offset == -1:
            return results

        # Get message type
        msg_type = struct.unpack("<I", payload[offset+8:offset+12])[0]
        
        base_result = {
            'type': msg_type,
            'source': ntlm_data['source'],
            'destination': ntlm_data['destination']
        }

        if msg_type == 1:  # Negotiate
            results.append({**base_result, 'details': 'NTLM Negotiate Message'})
            
        elif msg_type == 2:  # Challenge
            results.append({**base_result, 'details': 'NTLM Challenge Message'})
            
        elif msg_type == 3:  # Authenticate
            # Extract lengths and offsets
            lm_len, lm_off = struct.unpack("<HI", payload[offset+16:offset+22])
            ntlm_len, ntlm_off = struct.unpack("<HI", payload[offset+24:offset+30])
            domain_len, domain_off = struct.unpack("<HI", payload[offset+28:offset+34])
            user_len, user_off = struct.unpack("<HI", payload[offset+36:offset+42])
            host_len, host_off = struct.unpack("<HI", payload[offset+44:offset+50])
            
            # Extract values
            if domain_len > 0:
                domain = payload[domain_off:domain_off+domain_len].decode('utf-16-le')
            else:
                domain = ''
                
            if user_len > 0:
                username = payload[user_off:user_off+user_len].decode('utf-16-le')
            else:
                username = ''
                
            if host_len > 0:
                hostname = payload[host_off:host_off+host_len].decode('utf-16-le')
            else:
                hostname = ''
                
            # Extract NTLM hash if present
            ntlm_hash = ''
            if ntlm_len > 0:
                ntlm_hash = payload[ntlm_off:ntlm_off+ntlm_len].hex()
            
            results.append({
                **base_result,
                'username': username,
                'domain': domain,
                'hostname': hostname,
                'ntlm_hash': ntlm_hash,
                'complete_hash': bool(ntlm_hash),
                'details': 'NTLM Authentication Message'
            })
            
    except Exception as e:
        results.append({
            'type': 0,
            'error': str(e),
            'details': 'Error parsing NTLM data'
        })
        
    return results