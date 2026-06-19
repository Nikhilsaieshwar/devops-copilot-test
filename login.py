import os
import logging
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.fernet import Fernet
from flask import abort

# Initialize the Flask app
app = Flask(__name__)

# Load environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Initialize the bcrypt library for password hashing
bcrypt = Bcrypt(app)

# Initialize the Fernet library for secure encryption
fernet = Fernet(os.environ.get('ENCRYPTION_KEY'))

# Initialize CORS
CORS(app)

# Define a function to validate user input
def validate_input(data):
    if not data:
        return False
    if not isinstance(data, dict):
        return False
    required_fields = ['username', 'password']
    for field in required_fields:
        if field not in data:
            return False
    return True

# Define a function to get user data from the database
def get_user_data(username):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            return user
        else:
            return None
    except Exception as e:
        logging.error(f"Error getting user data: {e}")
        return None

# Define a function to handle login
def login(username, password):
    try:
        user = get_user_data(username)
        if user:
            if bcrypt.check_password_hash(user.password, password):
                return jsonify({'message': 'Login successful'}), 200
            else:
                return jsonify({'message': 'Invalid password'}), 401
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        logging.error(f"Error handling login: {e}")
        return jsonify({'message': 'Internal server error'}), 500

# Define a function to handle password reset
def reset_password(username, new_password):
    try:
        user = get_user_data(username)
        if user:
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            return jsonify({'message': 'Password reset successful'}), 200
        else:
            return jsonify({'message': 'User not found