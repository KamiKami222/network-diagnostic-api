import sqlite3

def connect_logs_db():
    return sqlite3.connect("instance/logs.db")

def connect_internal_db():
    return sqlite3.connect("instance/internal.db")

def initialize_databases():
    with connect_logs_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS api_key_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hashed TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        );
        """)
    with connect_internal_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS internal_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_hashed TEXT NOT NULL UNIQUE
        );
        """)
