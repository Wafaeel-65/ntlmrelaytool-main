from configparser import ConfigParser
import os

def load_db_config(filename='database.ini', section='database'):
    """Load database configuration from .ini file"""
    
    # Get the absolute path to the config directory
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                              'config', 
                              filename)
    
    # Create a parser
    parser = ConfigParser()
    
    # Read the configuration file
    if not os.path.exists(config_path):
        raise Exception(f'{config_path} not found.')
    
    parser.read(config_path)

    # Get section
    if not parser.has_section(section):
        raise Exception(f'Section {section} not found in {filename}')

    # Add config parameters to dictionary
    db_config = {}
    for param in parser.items(section):
        db_config[param[0]] = param[1]

    return db_config