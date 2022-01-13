from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from . import db
from .models import User, Password, PasswordShared
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
    share_query = PasswordShared.query.filter_by(owner_id=user_id).all()
    pass_data = []
    for passw in pass_query:
        dict = {
            "id": passw.id,
            "owner": user_email,
            "name": passw.name,
            "shared": '---',
            "password": passw.password
        }
        pass_data.append(dict)

    ctr = 0
    for passw in share_query:
        if (pass_data[ctr]['id']==passw.password_id):
            #dopisz mail
            if(pass_data[ctr]['shared'] == '---'):
                pass_data[ctr]['shared'] = []
                pass_data[ctr]['shared'].append(passw.user_id)
            else:
                pass_data[ctr]['shared'].append(passw.user_id)
    
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

@main.route('/passwords/delete/<int:id>', methods=['POST'])
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

@main.route('/passwords/share/<int:id>', methods=['POST'])
@login_required
def share(id):
    password_to_share = Password.query.get_or_404(id)
    second_user_mail = request.form.get('email')
    try:
        url = ("/passwords/share/"+str(id))
        if(current_user.id == password_to_share.owner_id):
            if(second_user_mail== ""):
                flash('Some fields are empty!', 'errorShare')
                flash(url,'errorShare')
                return redirect(url_for('main.passwords'))
            
            second_user = User.query.filter_by(email=second_user_mail).first()

            if(second_user == None):
                flash('User doesn\'t exists!', 'errorShare')
                flash(url,'errorShare')
                return redirect(url_for('main.passwords'))
            else:
                new_share = PasswordShared(password_id=password_to_share.id, owner_id = current_user.id, user_id = second_user.id)
                db.session.add(new_share)
                db.session.commit()
            flash(f'Password for {password_to_share.name} shared!', 'positive_message')
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

