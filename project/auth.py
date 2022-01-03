from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email') #unikalny
    name = request.form.get('name')
    surname = request.form.get('surname')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user: #jesli email istnieje to wracamy 
        flash('Email address is signed up!')
        return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, surname=surname, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
def logout():
    return 'Logout'