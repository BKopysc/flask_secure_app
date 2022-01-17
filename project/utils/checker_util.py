import string
from flask import flash

special_chars = ['"', '\'', ';', '<', '>', '[', ']', ' ', '~', '`', '%']

def check_name(name):
    not_allowed_chars = special_chars
    for sym in not_allowed_chars:
        if sym in name:
            return False
    return True

#special_chars = ['"', '\'', ';', '<','>','[',']', ' ','~','`','%']

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
    not_allowed_chars = ['<','>','`',';',' ']
    for sym in not_allowed_chars:
        if sym in passwd:
            return False
    return True

def check_secret(secret):
    not_allowed_chars = ['<','>','`',';',' ']
    for sym in not_allowed_chars:
        if sym in secret:
            return False
    for c in secret:
        if(ord(c) < 33 or ord(c) > 126):
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
    not_all = 0

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

    not_allowed_chars = ['<','>','`']
    for sym in not_allowed_chars:
        if sym in passwd:
            not_all +=1
    if(not_all != 0):
        return 'not_allowed'
    
    
    return 'strong'

def check_password_flash(password):
    res = check_password_strength(password)
    err = True
    if(len(password) > 50):
        flash('Password is to long!','error')
    elif(res == 'len'):
        flash('Password must have at least 8 characters!','error')
    elif(res == 'digits'):
        flash('Password must have at least one digit!','error')
    elif(res == 'special'):
        flash('Password must have at least one special character (e.g.: @, $, ?, !)!','error')
    elif(res == 'big'):
        flash('Password must have at least one BIG letter!','error')
    elif(res == 'not_allowed'):
        flash('Password contains not allowed chars!','error')
    else:
        err = False
    return err