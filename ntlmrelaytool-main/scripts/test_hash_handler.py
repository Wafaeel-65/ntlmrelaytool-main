import os
import sys
import logging

# Add the project root directory to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.utils.hash_handler import process_ntlm_hash, verify_hash, calculate_ntlm_hash

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def main():
    logger = setup_logging()

    # Calculate hash for a known password first
    test_password = 'Password123'
    known_hash = calculate_ntlm_hash(test_password)

    # Test hash processing with the known hash
    hash_data = {
        'username': 'administrator',
        'domain': 'contoso.local',
        'hash': known_hash
    }
    
    try:
        username, domain, hash_value = process_ntlm_hash(hash_data)
        logger.info(f"Processed hash data:")
        logger.info(f"Username: {username}")
        logger.info(f"Domain: {domain}")
        logger.info(f"Hash: {hash_value}")

        # Test hash verification with matching password
        is_valid = verify_hash(test_password, hash_value)
        logger.info(f"Password verification result: {is_valid}")

        # Show the calculated hash
        logger.info(f"Calculated hash for '{test_password}': {known_hash}")

    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()