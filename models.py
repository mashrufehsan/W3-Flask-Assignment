from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from datetime import datetime
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class RoleEnum(Enum):
    USER = 'user'
    ADMIN = 'admin'


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.now())
    update_date = db.Column(db.DateTime, onupdate=datetime.now())
    active = db.Column(db.Boolean, default=True)

    def __init__(self, username, first_name, last_name, email, password, role=RoleEnum.USER):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = generate_password_hash(password)
        self.role = role


class ResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    create_date = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, username, token):
        self.username = username
        self.token = token
