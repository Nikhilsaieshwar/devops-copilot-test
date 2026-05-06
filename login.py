import os
import logging
from flask import request, redirect, url_for
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Initialize Flask-Bcrypt for password hashing
bcrypt = Bcrypt()

# Initialize Flask-SQLAlchemy for database operations
db = SQLAlchemy()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Use environment variables or a secure secrets manager for hardcoded credentials
username = os.environ.get('USERNAME')
password = os.environ.get('PASSWORD')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

def get_user_data(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user
    else:
        return None

def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = get_user_data(username)
    if user and user.check_password(password):
        login_user(user)
        return redirect(url_for('index'))
    else:
        return 'Invalid username or password', 401

def logout():
    logout_user()
    return redirect(url_for('index'))

def reset_password():
    username = request.form.get('username')
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    user = get_user_data(username)
    if user and user.check_password(old_password):
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return 'Password reset successfully'
    else:
        return 'Invalid old password', 401

def register():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user:
        return 'Username already exists', 400
    else:
        new_user = User(username, password)
        db.session.add(new_user)
        db.session.commit()
        return 'User created successfully'