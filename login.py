import os
import logging
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from cryptography.fernet import Fernet

# Initialize the Flask app
app = Flask(__name__)
CORS(app)

# Load environment variables
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Initialize the bcrypt library for password hashing
bcrypt = Bcrypt(app)

# Initialize the Fernet library for secure encryption
fernet = Fernet(os.environ.get('SECRET_KEY'))

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Define the login function
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # Validate user input
    if not username or not password:
        return jsonify({'error': 'Invalid input'}), 400

    # Get the user from the database
    user = User.query.filter_by(username=username).first()

    # Check if the user exists
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Compare the provided password with the stored password
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid password'}), 401

    # Generate a secure token
    token = fernet.encrypt(os.urandom(16))

    # Return the token
    return jsonify({'token': token.decode('utf-8')}), 200

# Define the register function
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    # Validate user input
    if not username or not password:
        return jsonify({'error': 'Invalid input'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create a new user
    user = User(username=username, password=hashed_password)
    db.session.add