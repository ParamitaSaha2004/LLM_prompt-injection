import pymysql
import sqlite3
import os
import re
from werkzeug.security import generate_password_hash
from config import Config

# Global database type flag
USE_SQLITE = False
SQLITE_DB_PATH = os.path.join(os.path.dirname(__file__), "promptshield.db")

class SQLiteCursorWrapper:
    def __init__(self, sqlite_cursor):
        self.cursor = sqlite_cursor

    def execute(self, query, params=None):
        # Translate MySQL queries to SQLite queries on the fly
        # 1. Translate parameter placeholder from %s to ?
        query = query.replace('%s', '?')
        
        # 2. Translate Date difference functions
        if "DATE_SUB(NOW(), INTERVAL 15 DAY)" in query:
            query = query.replace("DATE_SUB(NOW(), INTERVAL 15 DAY)", "datetime('now', '-15 days')")
        if "DATE_SUB(NOW(), INTERVAL 15 DAY)" in query.upper():
            query = query.replace("DATE_SUB(NOW(), INTERVAL 15 DAY)", "datetime('now', '-15 days')")
            
        # 3. SQLite does not support DATE() function in group by the same way, but date(timestamp) works
        query = query.replace("DATE(timestamp)", "date(timestamp)")
        
        if params is not None:
            # pymysql takes params as tuple/list/dict. sqlite3 takes tuple/list/dict.
            # Handle single item tuples
            return self.cursor.execute(query, params)
        else:
            return self.cursor.execute(query)

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self):
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    @property
    def lastrowid(self):
        return self.cursor.lastrowid


class SQLiteConnectionWrapper:
    def __init__(self, sqlite_conn):
        self.conn = sqlite_conn

    def cursor(self):
        return SQLiteCursorWrapper(self.conn.cursor())

    def commit(self):
        return self.conn.commit()

    def rollback(self):
        return self.conn.rollback()

    def close(self):
        return self.conn.close()


def get_server_connection():
    """Establish a connection to the MySQL server without specifying the DB."""
    return pymysql.connect(
        host=Config.MYSQL_HOST,
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        cursorclass=pymysql.cursors.DictCursor
    )

def get_db_connection():
    """Establish connection to the active database (MySQL or SQLite fallback)."""
    global USE_SQLITE
    if USE_SQLITE:
        conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable Foreign Keys support in SQLite
        conn.execute("PRAGMA foreign_keys = ON;")
        return SQLiteConnectionWrapper(conn)
        
    try:
        return pymysql.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print(f"MySQL connection failed: {e}. Falling back to SQLite.")
        USE_SQLITE = True
        return get_db_connection()

def init_db():
    """Initialize the database (MySQL with automatic SQLite fallback)."""
    global USE_SQLITE
    schema_path = os.path.join(os.path.dirname(__file__), "db_schema.sql")

    # Step 1: Try initializing MySQL
    try:
        # Connect to server and create database if not exists
        conn = get_server_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {Config.MYSQL_DB};")
            conn.commit()
        finally:
            conn.close()

        # Execute MySQL schema
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                if os.path.exists(schema_path):
                    with open(schema_path, "r", encoding="utf-8") as f:
                        sql_commands = f.read().split(";")
                        for command in sql_commands:
                            command = command.strip()
                            if command:
                                cursor.execute(command)
                    conn.commit()
                    print("MySQL database initialized successfully.")
                    seed_default_users(conn)
            return
        except Exception as ex:
            print(f"MySQL schema execution failed: {ex}. Switching database mode to SQLite.")
            conn.rollback()
            conn.close()
    except Exception as e:
        print(f"MySQL server connection failed: {e}. Switching database mode to SQLite.")

    # Step 2: Initialize SQLite fallback
    USE_SQLITE = True
    print(f"Initializing SQLite database at: {SQLITE_DB_PATH}")
    
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        cursor = conn.cursor()
        if os.path.exists(schema_path):
            with open(schema_path, "r", encoding="utf-8") as f:
                sql_text = f.read()
                
                # Translate MySQL query features to SQLite features
                sql_text = re.sub(r'(?i)CREATE DATABASE[^;]+;', '', sql_text)
                sql_text = re.sub(r'(?i)USE [^;]+;', '', sql_text)
                
                # Replace AUTO_INCREMENT syntax
                sql_text = sql_text.replace('INT AUTO_INCREMENT PRIMARY KEY', 'INTEGER PRIMARY KEY AUTOINCREMENT')
                sql_text = sql_text.replace('INT AUTO_INCREMENT', 'INTEGER PRIMARY KEY AUTOINCREMENT')
                sql_text = sql_text.replace('TIMESTAMP DEFAULT CURRENT_TIMESTAMP', 'DATETIME DEFAULT CURRENT_TIMESTAMP')
                
                # Drop foreign key syntax alterations (SQLite doesn't support ALTER table foreign key drops, but table creation dropping is fine)
                sql_commands = sql_text.split(";")
                for command in sql_commands:
                    command = command.strip()
                    if command:
                        cursor.execute(command)
            conn.commit()
            print("SQLite database initialized successfully.")
            
            # Wrap connection to seed users
            wrapped_conn = SQLiteConnectionWrapper(conn)
            seed_default_users(wrapped_conn)
    except Exception as e:
        print(f"Error initializing SQLite database: {e}")
        conn.rollback()
    finally:
        conn.close()

def seed_default_users(conn):
    """Seed default admin and demo user accounts if they do not exist."""
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            if result['count'] == 0:
                admin_pass = generate_password_hash("adminpassword")
                user_pass = generate_password_hash("userpassword")
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                    ("admin", "admin@promptshield.local", admin_pass, "admin")
                )
                cursor.execute(
                    "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                    ("demo_user", "user@promptshield.local", user_pass, "user")
                )
                conn.commit()
                print("Default security user accounts seeded successfully.")
    except Exception as e:
        print(f"Failed to seed user accounts: {e}")
