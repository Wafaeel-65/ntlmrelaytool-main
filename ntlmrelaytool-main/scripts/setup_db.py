import sys
from pathlib import Path
import mysql.connector
from configparser import ConfigParser
import shutil
import os
import logging

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    'mysql': {
        'host': 'localhost',
        'database': 'dsi',
        'user': 'root',
        'password': 'password',
        'port': '3306'
    }
}

def create_default_config(config_path: Path) -> bool:
    """Create default configuration file"""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config = ConfigParser()
        config['mysql'] = DEFAULT_CONFIG['mysql']
        with open(config_path, 'w') as f:
            config.write(f)
        print(f"Created default config file at {config_path}")
        return True
    except Exception as e:
        print(f"Error creating config file: {e}")
        return False

def copy_schema_file() -> bool:
    """Copy SQL schema file to correct location"""
    try:
        source = Path(__file__).parent.parent.parent / 'Downloads' / 'dsi.sql'
        target = project_root / 'sql' / 'schema.sql'
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        print(f"Copied schema file to {target}")
        return True
    except Exception as e:
        print(f"Error copying schema file: {e}")
        return False

def read_sql_file(file_path: Path) -> str:
    """Read SQL file content"""
    with open(file_path, 'r') as f:
        return f.read()

def read_config(filename='database.ini'):
    """Read database configuration"""
    config = ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), '..', 'config', filename))
    return {
        'host': config['database']['host'],
        'user': config['database']['user'],
        'password': config['database']['password']
    }

def setup_database():
    """Setup database with proper order of operations"""
    connection = None
    cursor = None
    
    try:
        # Connect to MySQL server without password
        connection = mysql.connector.connect(
            host='localhost',
            user='root'
        )
        cursor = connection.cursor()
        logger.info("Setting up database...")

        # Create and use database
        cursor.execute("CREATE DATABASE IF NOT EXISTS dsi")
        cursor.execute("USE dsi")

        # Drop tables in correct order (child tables first)
        drop_tables = [
            "DROP TABLE IF EXISTS EXECUTE",
            "DROP TABLE IF EXISTS RESULTAT",
            "DROP TABLE IF EXISTS PLUGIN",
            "DROP TABLE IF EXISTS UTILISATEUR"
        ]

        for drop_command in drop_tables:
            try:
                cursor.execute(drop_command)
                logger.info(f"Dropped table: {drop_command}")
            except mysql.connector.Error as err:
                logger.warning(f"Drop table failed: {err}")
                continue

        # Create tables in correct order (parent tables first)
        create_tables = [
            """CREATE TABLE IF NOT EXISTS UTILISATEUR (
                ID_UTILISATEUR INT NOT NULL AUTO_INCREMENT,
                PRENOM_UTILISATEUR VARCHAR(100),
                ROLE_UTILISATEUR VARCHAR(50),
                EMAIL_UTILISATEUR VARCHAR(100),
                DERNIERE_CONNEXION DATETIME,
                PRIMARY KEY (ID_UTILISATEUR)
            )""",
            """CREATE TABLE IF NOT EXISTS PLUGIN (
                ID_PLUGIN INT NOT NULL AUTO_INCREMENT,
                NOM_PLUGIN VARCHAR(100),
                DATE_CREATION DATETIME,
                DESCRIPTION TEXT,
                VERSION VARCHAR(20),
                NTLM_KEY VARCHAR(255),
                PRIMARY KEY (ID_PLUGIN)
            )""",
            """CREATE TABLE IF NOT EXISTS RESULTAT (
                ID_RESULTAT INT NOT NULL AUTO_INCREMENT,
                ID_PLUGIN INT NOT NULL,
                DATE_RESULTAT DATETIME,
                STATUT VARCHAR(50),
                DETAILS TEXT,
                PRIMARY KEY (ID_RESULTAT),
                FOREIGN KEY (ID_PLUGIN) REFERENCES PLUGIN(ID_PLUGIN)
            )""",
            """CREATE TABLE IF NOT EXISTS EXECUTE (
                ID_UTILISATEUR INT NOT NULL,
                ID_PLUGIN INT NOT NULL,
                DATE_EXECUTION DATETIME,
                PRIMARY KEY (ID_UTILISATEUR, ID_PLUGIN),
                FOREIGN KEY (ID_UTILISATEUR) REFERENCES UTILISATEUR(ID_UTILISATEUR),
                FOREIGN KEY (ID_PLUGIN) REFERENCES PLUGIN(ID_PLUGIN)
            )"""
        ]

        for create_command in create_tables:
            try:
                cursor.execute(create_command)
                logger.info(f"Created table: {create_command[:50]}...")
            except mysql.connector.Error as err:
                logger.error(f"Create table failed: {err}")
                raise

        # Commit transaction
        connection.commit()
        logger.info("Database setup completed successfully")
        return True

    except mysql.connector.Error as err:
        if connection:
            connection.rollback()
        logger.error(f"Error: {err}")
        return False

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
            logger.info("MySQL connection closed.")

if __name__ == "__main__":
    success = setup_database()
    if not success:
        exit(1)