from .models import User
from . import db
from flask_login import login_required, current_user
from flask import Blueprint, render_template, redirect, url_for, request, flash

profile = Blueprint('profile',__name__)

@profile.route('/profile')
@login_required
def show_profile():
    user_data = {
        "name": current_user.name,
        "surname": current_user.surname
    }
    return render_template('profile.html', user_data=user_data)

@profile.route('/changePassword')
@login_required
def change_password():
    return render_template('changePassword.html')

@profile.route('/changePassword',methods=['POST'])
@login_required
def change_password_post():
    return render_template('changePassword.html')