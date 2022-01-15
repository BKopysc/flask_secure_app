from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(254), unique=True)
    password = db.Column(db.String(100))
    restore_password = db.Column(db.String(100))
    name = db.Column(db.String(50))
    surname = db.Column(db.String(50))
    login_attempts = db.Column(db.Integer)
    last_login = db.Column(db.DateTime)

class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))
    iv = db.Column(db.String(50))

class PasswordShared(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.Integer, db.ForeignKey('password.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))