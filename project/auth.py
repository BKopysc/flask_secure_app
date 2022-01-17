from re import S
from typing_extensions import Required
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
import datetime
from .models import User
from . import db
import string
from .utils.cipher_util import get_random_password
from .utils.checker_util import check_password_strength, check_email, check_person_info, check_password_flash

auth = Blueprint('auth', __name__)

#special_chars = ['"', '\'', ';', '<', '>', '[', ']', ' ', '~', '`', '%']


@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    #remember = True if request.form.get('remember') else False
    if(len(email) == 0 or len(password) == 0):
        flash('Some fields are empty!', 'error')
        return redirect(url_for('auth.login'))
    if(len(email) > 50 or len(password) > 50):
        flash('Some fields are too long!', 'error')
        return redirect(url_for('auth.login'))
    if(check_email(email) == False):
        flash('Email contains not allowed chars!', 'error')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()

    if not user:  # uzytkownik nie istnieje
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

    # time.sleep(1) # opoznienie sekunde (po stronie serwera wiec chyba zle)

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
    return render_template('signup.html', user_data=data)


@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')  # unikalny
    name = request.form.get('name')
    surname = request.form.get('surname')
    password = request.form.get('password')
    re_password = request.form.get('repassword')

    user_data = [email, name, surname]
    #user_data = email

    if(len(email) == 0 or len(name) == 0 or len(surname) == 0 or len(password) == 0 or len(re_password) == 0):
        flash('Some fields are empty!', 'error')
        return render_template('signup.html', user_data=user_data)

    if(len(email) > 50 or len(name) > 50 or len(surname) > 50 or len(password) > 50 or len(re_password) > 50):
        flash('Some fields are too long!', 'error')
        return render_template('signup.html', user_data=user_data)

    if(check_email(email) == False):
        flash('Email contains not allowed chars!', 'error')
        return render_template('signup.html', user_data=user_data)

    user = User.query.filter_by(email=email).first()
    if user:  # jesli email istnieje to wracamy
        flash('Email address is signed up!', 'exists')
        return render_template('signup.html', user_data=user_data)

    if(check_person_info(name) == False or check_person_info(surname) == False):
        flash('Name/Surname contains not allowed chars!', 'error')
        return render_template('signup.html', user_data=user_data)
        # return redirect(url_for('auth.signup'))

    pass_ren = check_password_flash(password)
    if(pass_ren == True):
        return render_template('signup.html', user_data=user_data)

    if(password != re_password):
        flash('Passwords are not equals!', 'error')
        return render_template('signup.html', user_data=user_data)

    restore_password = get_random_password()
    hash_restore_password = generate_password_hash(
        restore_password, method='sha256')
    hash_password = generate_password_hash(password, method='sha256')
    new_user = User(email=email, name=name, surname=surname,
                    password=hash_password, restore_password=hash_restore_password)

    db.session.add(new_user)
    db.session.commit()

    flash('You have been successfull signed up!', "positive_message")
    # return redirect(url_for('auth.login'))
    return render_template('restorePassword.html', restore_password=restore_password)


@auth.route('/signup/restorePassword')
def restore_password():
    return render_template('changeForgottenPassword.html')


@auth.route('/signup/restorePassword', methods=['POST'])
def restore_password_post():
    email = request.form.get('email')  # unikalny
    restore_password = request.form.get('restore_password')
    password = request.form.get('password')
    re_password = request.form.get('repassword')

    user_data = [email, restore_password]

    if(len(email) == 0 or len(password) == 0 or len(re_password) == 0 or  len(restore_password) == 0):
        flash('Some fields are empty!', 'error')
        return redirect(url_for('auth.restore_password'))

    if(len(email) > 50 or len(password) > 50 or len(re_password) > 50 or  len(restore_password) > 50):
        flash('Some fields are to long!', 'error')
        return redirect(url_for('auth.restore_password'))

    if(check_email(email) == False):
        flash('Email contains not allowed chars!', 'error')
        return redirect(url_for('auth.restore_password'))

    user = User.query.filter_by(email=email).first()
    if(user):
        restore_password_hash = check_password_hash(
            user.restore_password, restore_password)
        if(not restore_password_hash):
            flash('Restore password is wrong!', 'error')
            return render_template('changeForgottenPassword.html', user_data=user_data)

        pass_ren = check_password_flash(password)
        if(pass_ren == True):
            return render_template('changeForgottenPassword.html', user_data=user_data)

        if(password != re_password):
            flash('New Passwords are not equals!', 'error')
            return render_template('changeForgottenPassword.html', user_data=user_data)

        new_restore_password = get_random_password()
        hash_restore_password = generate_password_hash(
            new_restore_password, method='sha256')
        hash_password = generate_password_hash(password, method='sha256')

        user.restore_password = hash_restore_password
        user.password = hash_password
        db.session.commit()
        flash('Password changed! Look for a new restoration password!',
              'positive_message')
        return render_template('restorePassword.html', restore_password=new_restore_password)

    return render_template('changeForgottenPassword.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
