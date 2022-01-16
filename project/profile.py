from .models import Password, User
from . import db
from flask_login import login_required, current_user
from flask import Blueprint, render_template, redirect, url_for, request, flash
from .utils.checker_util import check_password_flash
from werkzeug.security import generate_password_hash, check_password_hash
from .utils.cipher_util import get_random_password

profile = Blueprint('profile',__name__)

@profile.route('/profile')
@login_required
def show_profile():
    user_data = {
        "name": current_user.name,
        "surname": current_user.surname
    }
    return render_template('profile.html', user_data=user_data)

@profile.route('/profile/changePassword')
@login_required
def change_password():
    return render_template('changePassword.html')

@profile.route('/profile/changePassword',methods=['POST'])
@login_required
def change_password_post():
    password = request.form.get('password')
    repassword = request.form.get('repassword')

    if(password == "" or repassword == ""):
        flash('Some fields are empty!', 'error')
        return redirect(url_for('profile.change_password'))

    if(len(password) > 50  or len(repassword) > 50):
        flash('Some fields are too long', 'error')
        return redirect(url_for('profile.change_password'))

    user = User.query.filter_by(id=current_user.id).first()
    if(not user):
        flash("error",'error')
        return render_template('changePassword.html')
    
    res = check_password_flash(password)
    if(res):
        return render_template('changePassword.html')

    if(password != repassword):
        flash('Passwords are not equals!','error')
        return render_template('changePassword.html')    

    password_hash = generate_password_hash(password, method='sha256')
    user.password = password_hash

    new_restore_password = get_random_password()
    hash_restore_password = generate_password_hash(new_restore_password, method='sha256')
    user.restore_password = hash_restore_password

    db.session.commit()

    flash('Password changed! Look for a new restoration password!','positive_message')
    return render_template('restorePassword.html', restore_password = new_restore_password, is_login = True)

