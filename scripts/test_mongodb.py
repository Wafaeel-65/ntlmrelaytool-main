import sys
import os
import logging
from datetime import datetime

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.utils.mongo_handler import MongoDBHandler

def test_mongodb_connection():
    """Test MongoDB connection and basic operations"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize MongoDB handler
        mongo = MongoDBHandler()
        
        # Test storing a capture
        test_capture = {
            'source': '192.168.1.100',
            'destination': '192.168.1.200',
            'username': 'testuser',
            'domain': 'testdomain',
            'hash': 'testhash123',
            'ntlm_type': 3
        }
        
        capture_id = mongo.store_capture(test_capture)
        if capture_id:
            logger.info(f"Successfully stored test capture with ID: {capture_id}")
            
            # Test retrieving captures
            captures = mongo.get_captures({'_id': capture_id})
            if captures:
                logger.info("Successfully retrieved test capture")
                logger.info(f"Capture details: {captures[0]}")
                
                # Test updating capture
                update_success = mongo.update_capture(capture_id, {'status': 'tested'})
                if update_success:
                    logger.info("Successfully updated test capture")
                    
                # Clean up test data
                delete_success = mongo.delete_capture(capture_id)
                if delete_success:
                    logger.info("Successfully cleaned up test data")
                    
            return True
            
    except Exception as e:
        logger.error(f"MongoDB test failed: {e}")
        return False
        
if __name__ == "__main__":
    success = test_mongodb_connection()
    sys.exit(0 if success else 1)