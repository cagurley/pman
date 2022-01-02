import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


if __name__ == '__main__':
    p = bytes(input('Enter passphrase:  '), encoding='utf-8')
    s = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', p, s, 100000)
    with open('i.b', 'wb') as f:
        iv = secrets.token_bytes(16)
        f.write(iv + b'\n')
    with open('et.b', 'wb') as f:
        enc = Cipher(algorithms.AES(dk), modes.GCM(iv)).encryptor()
        bt = bytes(input("Enter text to encrypt:  "), 'utf-8')
        e = enc.update(bt) + enc.finalize()
        t = enc.tag
        f.writelines([e, t])
    dec = Cipher(algorithms.AES(dk), modes.GCM(iv, t)).decryptor()
    print(dec.update(e) + dec.finalize())
