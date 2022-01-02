import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3 as sq3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


CDIR = Path('./config')
CFILE = CDIR.joinpath('config.json')


def config():
    if not CDIR.is_dir():
        CDIR.mkdir()
    db_dir = CDIR.home().joinpath('.pman')
    if not db_dir.is_dir():
        db_dir.mkdir()
    with open(CFILE, 'w') as f:
        json.dump({"db": str(db_dir)}, f, indent=4)
    return True


def load_config():
    if not CFILE.is_file():
        config()
    with open(CFILE) as f:
        s = json.load(f)
        return s['db']


def db_connect(db_dir):
    db = Path(db_dir).joinpath('pman.db')
    init = False
    if not db.is_file():
        init = True
    con = sq3.connect(db)
    cur = con.cursor()
    if init:
        with con:
            cur.execute("""
                CREATE TABLE stored (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE,
                    display TEXT,
                    cipher_text TEXT
                )
            """)
    return con, cur


def db_disconnect(con, cur):
    cur.close()
    con.close()
    return True


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
    return str(dec.update(h) + dec.finalize())


def create_verification(phr, con, cur):
    s = input('\n'.join([
        'Please provide a sentence to be used to verify input of your master passphrase.',
        'This sentence should be:',
        '\t1. COMPLETELY UNRELATED TO YOUR PASSPHRASE',
        '\t2. at least 24 characters in length',
        '\t3. comprehensible to you as a sentence in a language you can read',
        'Please enter this sentence below:\n\n'
    ]))
    while True:
        if len(s) < 24:
            s = input('\nThe given sentence was too short. Please provide a sentence of at least 24 characters.\n\n')
            continue
        confirm = input('\nAre you satisfied with this sentence? (enter [y] to accept)  ')
        if len(confirm) == 1 and confirm[0].lower() == 'y':
            break
        s = input('Provide a different sentence.\n\n')
    ct = '$'.join([val.hex() for val in encrypt(phr, s)])
    with con:
        cur.execute("INSERT INTO stored (name, display, cipher_text) VALUES (?, ?, ?)",
                    ['phrase_verification', 'PHRASE VERIFICATION', ct])
    return True


def verify_phrase(phr, con, cur):
    verification = None
    while not verification:
        with con:
            cur.execute("SELECT cipher_text FROM stored WHERE name = 'phrase_verification'")
        verification = cur.fetchone()
        if not verification:
            print('You have not yet provided a verification sentence. Please do so now.')
            create_verification(phr, con, cur)
        else:
            verification = verification[0]
    return decrypt(phr, *[bytes.fromhex(val) for val in verification.split('$')])


def load_phrase(con, cur):
    while True:
        p = bytes(input('Please provide your master passphrase:  '), encoding='utf-8')
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            verify_phrase(p, con, cur)
        except InvalidTag as it:
            print('Incorrect passphrase; try again.')
            continue
        else:
            break
    input('Passphrase verified. Press enter to continue. ')
    return p


if __name__ == '__main__':
    try:
        conn, curs = db_connect(load_config())
        try:
            phrase = load_phrase(conn, curs)
        finally:
            db_disconnect(conn, curs)
    except Exception as e:
        print(repr(e))
