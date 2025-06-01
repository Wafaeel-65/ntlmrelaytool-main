from pymongo import MongoClient, ASCENDING, TEXT
import sys
import os
import logging
from configparser import ConfigParser

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

def setup_mongodb():
    """Setup MongoDB database and collections with proper indexes"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    try:
        # Load config
        config_path = os.path.join(project_root, 'config', 'mongodb.ini')
        if not os.path.exists(config_path):
            logger.error(f"Configuration file not found: {config_path}")
            return False
            
        config = ConfigParser()
        config.read(config_path)
        
        # Build connection string
        connection_string = f"mongodb://{config['mongodb']['host']}:{config['mongodb']['port']}"
        if config['mongodb'].get('username') and config['mongodb'].get('password'):
            auth = f"{config['mongodb']['username']}:{config['mongodb']['password']}@"
            connection_string = f"mongodb://{auth}{config['mongodb']['host']}:{config['mongodb']['port']}"
        
        # Connect to MongoDB
        client = MongoClient(connection_string)
        db = client[config['mongodb']['database']]
        
        # Create collections with validation
        db.create_collection('captures', validator={
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['timestamp', 'source'],
                'properties': {
                    'timestamp': {'bsonType': 'date'},
                    'source': {'bsonType': 'string'},
                    'username': {'bsonType': 'string'},
                    'domain': {'bsonType': 'string'},
                    'hash': {'bsonType': 'string'}
                }
            }
        })
        
        db.create_collection('plugins', validator={
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['nom_plugin', 'created_at'],
                'properties': {
                    'nom_plugin': {'bsonType': 'string'},
                    'created_at': {'bsonType': 'date'},
                    'description': {'bsonType': 'string'},
                    'version': {'bsonType': 'string'}
                }
            }
        })
        
        db.create_collection('results', validator={
            '$jsonSchema': {
                'bsonType': 'object',
                'required': ['timestamp', 'plugin_id'],
                'properties': {
                    'timestamp': {'bsonType': 'date'},
                    'plugin_id': {'bsonType': 'string'},
                    'status': {'bsonType': 'string'},
                    'details': {'bsonType': 'string'}
                }
            }
        })
        
        # Create indexes
        captures = db.captures
        captures.create_index([("timestamp", ASCENDING)])
        captures.create_index([("source", ASCENDING)])
        captures.create_index([("username", ASCENDING)])
        captures.create_index([("domain", ASCENDING)])
        captures.create_index([("hash", ASCENDING)])
        
        plugins = db.plugins
        plugins.create_index([("created_at", ASCENDING)])
        plugins.create_index([("nom_plugin", ASCENDING)], unique=True)
        plugins.create_index([("description", TEXT)])
        
        results = db.results
        results.create_index([("timestamp", ASCENDING)])
        results.create_index([("plugin_id", ASCENDING)])
        results.create_index([("status", ASCENDING)])
        
        logger.info("MongoDB setup completed successfully")
        logger.info(f"Database: {config['mongodb']['database']}")
        logger.info(f"Collections created with validation schemas")
        logger.info("Indexes created for better query performance")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup MongoDB: {e}")
        return False
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    success = setup_mongodb()
    sys.exit(0 if success else 1)