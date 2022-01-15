from Cryptodome.Cipher import DES,AES
from Cryptodome.Random import get_random_bytes
import random
import string


def make_key(key):
    if(len(key) < 16):
        new_key = key+((16-len(key))*'0')
    elif(len(key) > 16 and len(key) < 24):
        new_key = key+((24-len(key))*'0')
    elif(len(key) > 24 and len(key) < 32):
        new_key = key+((32-len(key))*'0')
    elif(len(key) > 32):
        new_key = key[0:32]
    else:
        new_key = key
    return bytes(new_key,"utf8")

def make_data(data):
    data = bytes(data,'utf8')
    if (len(data) % 16 != 0):
        new_data = (((len(data)//16 + 1)*16) - len(data)) * b'\x00' + data
        return new_data
    else:
        return data

def remake_data(data):
    new_data = ""
    mark = '¿'
    out_of_range = False
    for ch in data:
        if(ch != 0):
            if(ch >= 33 and ch <=126):
                new_data += chr(ch)
            else:
                new_data += mark
                out_of_range = True
    if out_of_range:
        new_data = 'Error: wrong key'
    return(new_data)


def encrypt_AES(key_str, data_str):
    iv = get_random_bytes(16)
    key = make_key(key_str)
    data = make_data(data_str)

    aes = AES.new(key, AES.MODE_CBC, iv)
    encrypted = aes.encrypt(data)
    return [encrypted, iv]

def decrypt_AES(encrypted, key_str, iv):
    key = make_key(key_str)
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(encrypted)
    decrypted_data = remake_data(decrypted)
    return decrypted_data

def test(): # przyklad uzycia
    en = encrypt_AES('klucz','Korona123@!!')
    #print(en)
    res = decrypt_AES(en[0], 'klucz',en[1])
    print(res)

def get_random_password():
    source = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(source) for i in range(16)))
    return result_str
    #print(result_str)

#test()
#get_random_password()

