import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
