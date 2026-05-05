import os
import logging
import sqlite3
import re
import getpass
import hashlib

# Set up logging
logging.basicConfig(filename='login.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables for credentials
username = os.environ.get('LOGIN_USERNAME')
password = os.environ.get('LOGIN_PASSWORD')

# Validate input
def validate_input(username, password):
    if not re.match('^[a-zA-Z0-9_]+$', username):
        logging.error('Invalid username')
        return False
    if not re.match('^[a-zA-Z0-9_]{8,}$', password):
        logging.error('Invalid password')
        return False
    return True

# Hash passwords for secure storage
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Fix SQL injection vulnerability using parameterized queries
def get_user_data(username):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        return user_data
    except sqlite3.Error as e:
        logging.error(f'SQL error: {e}')
        return None

# Fix password reset to not expose passwords
def reset_password(username, new_password):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hash_password(new_password), username))
        conn.commit()
        conn.close()
        logging.info(f'Password reset for {username}')
        return True
    except sqlite3.Error as e:
        logging.error(f'SQL error: {e}')
        return False

# Login function with proper input validation and error handling
def login(username, password):
    try:
        user_data = get_user_data(username)
        if user_data is None:
            logging.error('User not found')
            return False
        stored_password = user_data[1]
        if hash_password(password) != stored_password:
            logging.error('Invalid password')
            return False
        logging.info(f'Login successful for {username}')
        return True
    except Exception as e:
        logging.error(f'Error: {e}')
        return False

# Main function
def main():
    while True:
        print('1. Login')
        print('2. Reset password')
        print('3