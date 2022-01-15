from re import S
from typing_extensions import Required
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
import datetime
from .models import User
from . import db
import string

auth = Blueprint('auth', __name__)

special_chars = ['"', '\'', ';', '<','>','[',']', ' ','~','`','%']

def check_email(email):
    not_allowed_chars = special_chars
    for sym in not_allowed_chars:
        if sym in email:
            return False
    return True

def check_person_info(name):
    not_allowed_chars = list(string.digits)+list(string.punctuation)
    for sym in not_allowed_chars:
        if sym in name:
            return False
    return True

def check_password(passwd):
    not_allowed_chars = ['<','>','`']
    for sym in not_allowed_chars:
        if sym in passwd:
            return False
    return True

def check_password_strength(passwd):
    required_digits = list(string.digits)
    required_special_char = list(string.punctuation)
    required_big_letter = list(string.ascii_uppercase)
    min_length = 8

    req_digits = 0
    req_special = 0
    req_big = 0

    if(len(passwd) < 8):
        return 'len'
    
    for sym in required_digits:
        if sym in passwd:
            req_digits += 1
    if(req_digits == 0):
        return 'digits'

    for sym in required_special_char:
        if sym in passwd:
            req_special +=1
    if(req_special == 0):
        return 'special'

    for sym in required_big_letter:
        if sym in passwd:
            req_big +=1
    if(req_big == 0):
        return 'big'
    
    return 'strong'



@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    #remember = True if request.form.get('remember') else False

    if(check_email(email) == False):
        flash('Email contains not allowed chars!', 'error')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()

    if not user :  # uzytkownik nie istnieje
        flash('Wrong email or password!', 'error')
        return redirect(url_for('auth.login'))
    
    time_now = datetime.datetime.now()

    if user and user.login_attempts is None:
        user.login_attempts = 0
        db.session.commit()
    elif user and user.login_attempts > 5:
        time_last = user.last_login
        time_var = int((time_now-time_last).total_seconds())
        if(time_var < 60):
            flash('To many wrong attempts! Wait some time!', 'error')
            return redirect(url_for('auth.login'))
        else:
            user.login_attempts = 0
            user.last_login = time_now
            db.session.commit()

    #time.sleep(1) # opoznienie sekunde (po stronie serwera wiec chyba zle)

    if not check_password_hash(user.password, password):
        flash('Wrong email or password!', 'error')
        user.login_attempts = user.login_attempts + 1
        user.last_login = time_now
        db.session.commit()
        return redirect(url_for('auth.login'))

    login_user(user)
    user.login_attempts = 0
    db.session.commit()
    return redirect(url_for('main.index'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')

def ren_signup_again(data):
    #print('data=', data)
    return render_template('signup.html',user_data=data)

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')  # unikalny
    name = request.form.get('name')
    surname = request.form.get('surname')
    password = request.form.get('password')

    user_data = [email,name,surname]
    #user_data = email

    if(len(email) == 0 or len(name) == 0 or len(surname) == 0):
        flash('Some fields are empty!','error')
        return redirect(url_for('auth.signup'))

    if(check_email(email) == False):
        flash('Email contains not allowed chars!','error')
        return redirect(url_for('auth.signup'))

    user = User.query.filter_by(email=email).first()
    if user:  # jesli email istnieje to wracamy
        flash('Email address is signed up!','exists')
        return redirect(url_for('auth.signup'))
    
    if(check_person_info(name) == False or check_person_info(surname) == False):
        flash('Name/Surname contains not allowed chars!','error')
        return redirect(url_for('auth.signup'))

    res = check_password_strength(password)
    if(res == 'len'):
        flash('Password must have at least 8 characters!','error')
        return render_template('signup.html',user_data=user_data)
    elif(res == 'digits'):
        flash('Password must have at least one digit!','error')
        return render_template('signup.html',user_data=user_data)
        #return redirect(url_for('auth.signup'))
    elif(res == 'special'):
        flash('Password must have at least one special character (e.g.: @, $, ?, !)!','error')
        return render_template('signup.html',user_data=user_data)
        #return redirect(url_for('auth.signup'))
    elif(res == 'big'):
        flash('Password must have at least one BIG letter!','error')
        print("big letter")
        return render_template('signup.html',user_data=user_data)
        #return redirect(url_for('auth.signup'))

    new_user = User(email=email, name=name, surname=surname,
                    password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
