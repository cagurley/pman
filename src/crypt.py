import hashlib
import re
import secrets
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SPECIAL = '!@#$%^*()-_+=[{]}|'


def encrypt(phr, txt):
    txt = bytes(txt, encoding='utf-8')
    s = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', phr, s, 320000)
    iv = secrets.token_bytes(16)
    enc = Cipher(algorithms.AES(dk), modes.GCM(iv)).encryptor()
    h = enc.update(txt) + enc.finalize()
    t = enc.tag
    return iv, t, s, h


def decrypt(phr, iv, t, s, h):
    dk = hashlib.pbkdf2_hmac('sha256', phr, s, 320000)
    dec = Cipher(algorithms.AES(dk), modes.GCM(iv, t)).decryptor()
    return (dec.update(h) + dec.finalize()).decode()


def cs2bv(cs):
    return tuple(bytes.fromhex(val) for val in cs.split('$'))


def bv2cs(bv):
    return '$'.join([val.hex() for val in bv])


def generate_string(length, all_required, lower, upper, digit, special):
    valid = False
    pool = ''
    if lower:
        pool += string.ascii_lowercase
    if upper:
        pool += string.ascii_uppercase
    if digit:
        pool += string.digits
    if special:
        pool += SPECIAL
    while not valid:
        generated = ''.join([secrets.choice(pool) for _ in range(length)])
        valid = True
        if all_required:
            if lower and generated.upper() == generated:
                valid = False
            if upper and generated.lower() == generated:
                valid = False
            if digit and not re.match(r'\d', generated, re.A):
                valid = False
            if special and not re.match(rf'[{SPECIAL}]', generated):
                valid = False
    return generated
