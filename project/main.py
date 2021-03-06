from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from . import db
from .models import User, Password, PasswordShared
from sqlalchemy import and_
from .utils.cipher_util import encrypt_AES, decrypt_AES
from .utils.checker_util import check_name, check_password, check_secret

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')

# @main.route('/profile')
# @login_required
# def profile():
#     return render_template('profile.html', name=current_user.name)

# wyswietlanie serwisow/hasel


def index_passwords(decrypted={}, decrypted_share={}):
    user_id = current_user.id
    user_email = current_user.email

    pass_query = Password.query.filter_by(owner_id=user_id).all()
    share_query = PasswordShared.query.filter_by(owner_id=user_id).all()
    share_to_you_query = PasswordShared.query.filter_by(user_id=user_id).all()
    pass_data = []
    shared_data = []

    for passw in pass_query:
        #passw_dec = passw.password
        passw_dec = "****"
        if(decrypted):
            if(decrypted['id'] == passw.id):
                passw_dec = decrypt_AES(
                    passw.password, decrypted['secret'], passw.iv)
        dict = {
            "id": passw.id,
            "owner": user_email,
            "name": passw.name,
            "shared": [],
            "shared_count": 0,
            "password": passw_dec
        }
        pass_data.append(dict)

    shared_info = []

    for passw in share_query:
        for ps in pass_data:
            if (ps['id'] == passw.password_id):
                ps['shared_count'] += 1
                ps['shared'].append(passw.user_id)

    for passw in share_to_you_query:
        try:
            get_pass_query = Password.query.get_or_404(passw.password_id)
            get_owner_query = User.query.get_or_404(passw.owner_id)
            passw_dec = "********"
            if(decrypted_share):
                if(decrypted_share['id'] == passw.id):
                    passw_dec = decrypt_AES(
                        get_pass_query.password, decrypted_share['secret'], get_pass_query.iv)
            dict = {
                "id": passw.id,
                "owner_email": get_owner_query.email,
                "name": get_pass_query.name,
                "password": passw_dec
            }
            shared_data.append(dict)
        except:
            render_template('passwords.html')
    return pass_data, shared_data


@main.route('/passwords')
@login_required
def passwords():
    pass_data, shared_data = index_passwords()

    return render_template('passwords.html', name=pass_data, user_passwords=pass_data, shared_passwords=shared_data)

# dodawanie nowego serwisu/hasla


@main.route('/passwords', methods=['POST'])
@login_required
def passwords_post():
    name = request.form.get('name')
    password = request.form.get('password')
    secret_key = request.form.get('secret')

    if(len(name) == 0 or len(password) == 0 or len(secret_key) == 0):
        flash('Some fields are empty!', 'errorAdd')
        return redirect(url_for('main.passwords'))

    if(len(name) > 50 or len(password) > 50 or len(secret_key) > 50):
        flash('Some fields are too long!', 'errorAdd')
        return redirect(url_for('main.passwords'))

    if(check_name(name) == False):
        flash('Name contains not allowed chars!', 'errorAdd')
        return redirect(url_for('main.passwords'))

    if(check_password(password) == False):
        flash('Password contains not allowed chars!', 'errorAdd')
        return redirect(url_for('main.passwords'))

    if(check_secret(secret_key) == False):
        flash('Secret Key contains not allowed chars!', 'errorAdd')
        return redirect(url_for('main.passwords'))

    encrypted = encrypt_AES(secret_key, password)
    encrypted_password = encrypted[0]
    iv = encrypted[1]

    new_password = Password(owner_id=current_user.id,
                            name=name, password=encrypted_password, iv=iv)
    db.session.add(new_password)
    db.session.commit()
    flash(f'Password {name} added!', 'positive_message')
    return redirect(url_for('main.passwords'))


@main.route('/passwords/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    password_to_delete = Password.query.get_or_404(id)
    password_share = PasswordShared.query.filter_by(password_id=id)
    try:
        if(current_user.id == password_to_delete.owner_id):
            db.session.delete(password_to_delete)
            for passw in password_share:
                db.session.delete(passw)
            db.session.commit()
            flash(
                f'Password for {password_to_delete.name} deleted!', 'positive_message')
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
            if(second_user_mail == ""):
                flash('Some fields are empty!', 'errorShare')
                flash(url, 'errorShare')
                return redirect(url_for('main.passwords'))
            if(second_user_mail == current_user.email):
                flash('You entered your email!', 'errorShare')
                flash(url, 'errorShare')
                return redirect(url_for('main.passwords'))
            second_user = User.query.filter_by(email=second_user_mail).first()
            if(second_user == None):
                flash('User doesn\'t exists!', 'errorShare')
                flash(url, 'errorShare')
                return redirect(url_for('main.passwords'))

            check_if_exists = PasswordShared.query.filter(and_(
                PasswordShared.password_id == id, PasswordShared.user_id == second_user.id)).first()
            if(not check_if_exists):
                new_share = PasswordShared(
                    password_id=password_to_share.id, owner_id=current_user.id, user_id=second_user.id)
                db.session.add(new_share)
                db.session.commit()
                flash(
                    f'Password for {password_to_share.name} shared!', 'positive_message')
            else:
                flash('You shared for this user already!', 'errorShare')
                flash(url, 'errorShare')
        else:
            flash('No permission!', 'critical_message')

        return redirect(url_for('main.passwords'))
    except:
        flash('Error!', 'critical_message')
        return redirect(url_for('main.passwords'))


@main.route('/passwords/shareView/<int:id>')
@login_required
def shareView(id):
    password_query = Password.query.filter_by(id=id).first()
    if(not password_query):
        flash('Error', 'critical_message')
        return redirect(url_for('main.passwords'))
    if(password_query.owner_id != current_user.id):
        flash('You don\'t have permission!', 'critical_message')
        return redirect(url_for('main.passwords'))

    name = password_query.name
    share_query = PasswordShared.query.filter_by(password_id=id).all()
    share_data = []

    for passw in share_query:
        user_query = User.query.filter_by(id=passw.user_id).first()
        dict = {
            "id": passw.id,
            "owner_id": passw.owner_id,
            "user_name": user_query.email
        }
        share_data.append(dict)
    return render_template("share.html", name=name, share_data=share_data)


@main.route('/passwords/share/delete/<int:id>', methods=['POST'])
@login_required
def share_delete(id):
    password_query = PasswordShared.query.filter_by(id=id).first()
    id_origin = password_query.password_id
    if(password_query.owner_id != current_user.id):
        flash('You don\'t have permission!', 'critical_message')
        return redirect(url_for('main.passwords'))

    db.session.delete(password_query)
    db.session.commit()
    flash('Share deleted!', 'positive_message')
    return redirect(url_for('main.shareView', id=id_origin))


@main.route('/passwords/decrypt/<int:id>', methods=['POST'])
@login_required
def decrypt(id):
    secret = request.form.get('secret')

    if(len(secret) == 0):
        flash('Secret are empty!', 'critical_message')
        return redirect(url_for('main.passwords'))
    if(len(secret) > 50):
        flash('Secret are too long!', 'critical_message')
        return redirect(url_for('main.passwords'))
    if(check_secret(secret) == False):
        flash('Secret contains not allowed chars!','critical_message')
        return redirect(url_for('main.passwords'))

    flash("Check decryption!", 'positive_message')
    dic_dec = {
        "id": id,
        "secret": secret
    }
    pass_data, shared_data = index_passwords(decrypted=dic_dec)
    return render_template('passwords.html', name=pass_data, user_passwords=pass_data, shared_passwords=shared_data)


@main.route('/passwords/shared/decrypt/<int:id>', methods=['POST'])
@login_required
def decrypt_shared(id):
    secret = request.form.get('secret')

    if(len(secret) == 0):
        flash('Secret are empty!', 'critical_message')
        return redirect(url_for('main.passwords'))
    if(len(secret) > 50):
        flash('Secret are too long!', 'critical_message')
        return redirect(url_for('main.passwords'))
    if(check_secret(secret) == False):
        flash('Secret contains not allowed chars!', 'critical_message')
        return redirect(url_for('main.passwords'))

    flash("Check decryption!", 'positive_message')
    dic_dec = {
        "id": id,
        "secret": secret
    }
    pass_data, shared_data = index_passwords(decrypted_share=dic_dec)
    return render_template('passwords.html', name=pass_data, user_passwords=pass_data, shared_passwords=shared_data)

# def check_secret(secret):
