from flask import Blueprint, render_template, session
from flask_login import login_required, current_user
from . import db
from .models import User, Password
main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

@main.route('/passwords')
@login_required
def passwords():
    user_id = current_user.id
    user_email = current_user.email

    pass_query = Password.query.filter_by(owner_id=user_id).all()
    pass_data = []
    for passw in pass_query:
        dict = {
            "owner": user_email,
            "name": passw.name,
            "shared": passw.shared,
            "password": passw.password
        }
        pass_data.append(dict)
    
    return render_template('passwords.html',name = pass_data, user_passwords = pass_data)


