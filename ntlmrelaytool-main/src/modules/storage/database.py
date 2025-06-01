import sqlite3
from typing import Optional, List, Any

class Database:
    def __init__(self, db_path: str = "ntlm_relay.db"):
        self.db_path = db_path
        self.connection = None
        self.connect()

    def connect(self) -> None:
        try:
            self.connection = sqlite3.connect(self.db_path)
        except sqlite3.Error as e:
            raise Exception(f"Database connection failed: {e}")

    def disconnect(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def execute_query(self, query: str, params: Optional[tuple] = None) -> List[Any]:
        if not self.connection:
            self.connect()
        try:
            cursor = self.connection.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            self.connection.commit()
            return cursor.fetchall()
        except sqlite3.Error as e:
            raise Exception(f"Query execution failed: {e}")