import sqlite3
import json
import time
from typing import Optional
from fastapi import HTTPException
import config


def get_db_conn():
    conn = sqlite3.connect(config.DB_NAME)
    # Returns Dict instead of Tuple
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Insures clean state
def init_db():
    conn = sqlite3.connect(config.DB_NAME)
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS users')
    cursor.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        algo_type TEXT NOT NULL,
        salt TEXT, 
        password_hash TEXT NOT NULL,
        totp_secret TEXT
    )
    ''')
    conn.commit()
    conn.close()


def user_exists(username: str, cursor: sqlite3.Cursor) -> bool:
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        return True
    return False


def insert_user_to_db(username: str, algo: str, salt: Optional[str], hash_val: str, totp_secret: Optional[str],
                      cursor: sqlite3.Cursor, conn: sqlite3.Connection):
    try:
        cursor.execute('''
            INSERT INTO users (username, algo_type, salt, password_hash, totp_secret)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            username,
            algo,
            salt,
            hash_val,
            totp_secret
        ))
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=str(e))


def log_attempt(username: str, hash_mode: str, result: str, latency_ms: float, protection_flags: list):

    log_entry = {
        "timestamp": time.time(),
        "group_seed": config.GROUP_SEED,
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags,
        "result": result,
        "latency_ms": latency_ms
    }
    try:
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error writing to log: {e}")