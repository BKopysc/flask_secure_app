from flask import Blueprint, render_template, request, flash, redirect, url_for
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
            "id": passw.id,
            "owner": user_email,
            "name": passw.name,
            "shared": passw.shared,
            "password": passw.password
        }
        pass_data.append(dict)
    
    return render_template('passwords.html',name = pass_data, user_passwords = pass_data)

@main.route('/passwords', methods =['POST'])
@login_required
def passwords_post():
    name = request.form.get('name')
    password = request.form.get('password')
    secret = request.form.get('secret')

    if(name == "" or password == "" or secret == ""):
        flash('Some fields are empty!', 'error')
        return redirect(url_for('main.passwords'))
    
    if(check_name(name) == False):
        flash('Name contains not allowed chars!', 'error')
        return redirect(url_for('main.passwords'))       

    new_password = Password(owner_id = current_user.id, name=name, shared="none", password = password)
    db.session.add(new_password)
    db.session.commit()
    flash(f'Password {name} added!', 'positive_message')
    return redirect(url_for('main.passwords'))

@main.route('/passwords/delete/<int:id>')
@login_required
def delete(id):
    password_to_delete = Password.query.get_or_404(id)
    try:
        if(current_user.id == password_to_delete.owner_id):
            db.session.delete(password_to_delete)
            db.session.commit()
            flash(f'Password for {password_to_delete.name} deleted!', 'positive_message')
        else:
            flash('No permission!', 'critical_message')
        return redirect(url_for('main.passwords'))
    except:
        flash('Error!', 'critical_message')
        return redirect(url_for('main.passwords'))


special_chars = ['"', '\'', ';', '<','>','[',']', ' ','~','`','%']

def check_name(name):
    not_allowed_chars = special_chars
    for sym in not_allowed_chars:
        if sym in name:
            return False
    return True

#def check_secret(secret):

