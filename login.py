import os
import logging
from flask import Flask, request, redirect, url_for, jsonify
from flask_login import login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['LOGGING_LEVEL'] = logging.INFO

# Initialize logging
logging.basicConfig(level=app.config['LOGGING_LEVEL'])
logger = logging.getLogger(__name__)

# Initialize database
db = SQLAlchemy(app)

# Initialize password hashing
bcrypt = Bcrypt(app)

# Initialize Fernet for secure data encryption
fernet = Fernet.generate_key()
cipher_suite = Fernet(fernet)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

# Login function
def login(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# Logout function
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# Register function
def register(username, password):
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    user = User(username, password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# Reset password function
def reset_password(username, old_password, new_password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(old_password):
        user.password = bcrypt.generate_password_hash(new_password).