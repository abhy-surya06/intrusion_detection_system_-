import sqlite3
import time

DB_NAME = 'sentinel.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            ip TEXT,
            method TEXT,
            url TEXT,
            attack_type TEXT,
            blocked INTEGER,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_request(ip, method, url, attack_type, blocked, details=""):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, ip, method, url, attack_type, blocked, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (time.time(), ip, method, url, attack_type, 1 if blocked else 0, details))
    conn.commit()
    conn.close()

def get_logs(limit=100):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_attack_stats():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT attack_type, COUNT(*) FROM logs WHERE blocked=1 GROUP BY attack_type')
    stats = c.fetchall()
    conn.close()
    return stats