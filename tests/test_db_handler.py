import pytest
import sqlite3
import os
from src.utils.db_handler import DatabaseHandler

@pytest.fixture
def test_db_path(tmp_path):
    db_path = tmp_path / "test.db"
    return str(db_path)

@pytest.fixture
def db_handler(test_db_path):
    handler = DatabaseHandler(db_path=test_db_path)
    handler.connect()
    # Create test tables
    handler.execute_query("""
        CREATE TABLE IF NOT EXISTS plugins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom_plugin TEXT NOT NULL,
            description TEXT,
            version TEXT,
            ntlm_key TEXT,
            date_creation TIMESTAMP
        )
    """)
    yield handler
    handler.disconnect()
    if os.path.exists(test_db_path):
        os.remove(test_db_path)

def test_connection(db_handler):
    assert db_handler.is_connected() == True

def test_add_plugin(db_handler):
    db_handler.add_plugin(
        "test_plugin",
        "Test Description",
        "1.0.0",
        "test_key"
    )
    result = db_handler.execute_query("SELECT * FROM plugins")
    assert len(result) == 1
    assert result[0][1] == "test_plugin"

def test_get_plugin_by_id(db_handler):
    db_handler.add_plugin(
        "test_plugin",
        "Test Description", 
        "1.0.0",
        "test_key"
    )
    plugin = db_handler.get_plugin_by_id(1)
    assert plugin is not None
    assert plugin["nom_plugin"] == "test_plugin"

def test_get_nonexistent_plugin(db_handler):
    plugin = db_handler.get_plugin_by_id(999)
    assert plugin is None