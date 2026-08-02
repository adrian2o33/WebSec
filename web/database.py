import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT DEFAULT 'Free',
            premium_since TEXT,
            cancel_date TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_info TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            last_active TEXT NOT NULL,
            session_token TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def create_user(username, email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        cursor.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            (username, email, password_hash)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def _check_expired_plan(user_dict):
    if not user_dict:
        return None
    if user_dict.get('plan') == 'Premium' and user_dict.get('cancel_date'):
        cancel_date_str = user_dict['cancel_date'][:10]
        today_str = datetime.now().isoformat()[:10]
        if today_str >= cancel_date_str:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET plan = 'Free', premium_since = NULL, cancel_date = NULL WHERE id = ?", (user_dict['id'],))
            conn.commit()
            conn.close()
            user_dict['plan'] = 'Free'
            user_dict['cancel_date'] = None
            user_dict['premium_since'] = None
    return user_dict

def authenticate_user(email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return _check_expired_plan(dict(user))
    return None

def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return _check_expired_plan(dict(user)) if user else None

def update_user_plan(user_id, plan, cancel_date=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat() if plan == 'Premium' else None
    
    if cancel_date is not None:
        cursor.execute('UPDATE users SET cancel_date = ? WHERE id = ?', (cancel_date, user_id))
    else:
        cursor.execute('UPDATE users SET plan = ?, premium_since = ?, cancel_date = NULL WHERE id = ?', (plan, now, user_id))
    conn.commit()
    conn.close()

def update_username(user_id, new_username):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_email(user_id, new_email):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_password(user_id, new_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    password_hash = generate_password_hash(new_password)
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
    conn.commit()
    conn.close()

def add_device(user_id, device_info, ip_address, session_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        'INSERT INTO devices (user_id, device_info, ip_address, last_active, session_token) VALUES (?, ?, ?, ?, ?)',
        (user_id, device_info, ip_address, now, session_token)
    )
    device_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return device_id

def get_user_devices(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM devices WHERE user_id = ? ORDER BY last_active DESC', (user_id,))
    devices = cursor.fetchall()
    conn.close()
    return [dict(d) for d in devices]

def remove_device(device_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM devices WHERE id = ? AND user_id = ?', (device_id, user_id))
    conn.commit()
    conn.close()

def validate_device_session(device_id, session_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM devices WHERE id = ? AND session_token = ?', (device_id, session_token))
    valid = cursor.fetchone() is not None
    conn.close()
    return valid

# Initialize DB if it doesn't exist on import
init_db()
