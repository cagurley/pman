import hashlib
import os
import secrets
from time import sleep
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from src import manage


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


def view_stored(con, cur):
    with con:
        cur.execute("SELECT display FROM stored ORDER BY name")
        vals = cur.fetchall()
    print('===STORED CREDENTIALS===\n')
    for val in vals:
        print('\t' + val[0])
    return None


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
        if confirm.lower() == 'y':
            break
        s = input('Provide a different sentence.\n\n')
    ct = '$'.join([val.hex() for val in encrypt(phr, s)])
    with con:
        cur.execute("INSERT INTO stored (name, display, cipher_text) VALUES (?, ?, ?)",
                    ['~phrase_verification', 'PHRASE VERIFICATION', ct])
    return True


def create_new_verification(phr, con, cur):
    with con:
        cur.execute("DELETE FROM stored WHERE name = '~phrase_verification'")
    return create_verification(phr, con, cur)


def verify_phrase(phr, con, cur):
    verification = None
    while not verification:
        with con:
            cur.execute("SELECT cipher_text FROM stored WHERE name = '~phrase_verification'")
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
        clear_terminal()
        try:
            verify_phrase(p, con, cur)
        except InvalidTag:
            print('Incorrect passphrase; try again.')
            continue
        else:
            break
    input('Passphrase verified. Press enter to continue. ')
    return p


def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')
    return None


def prompt_menu(phr, con, cur):
    while True:
        clear_terminal()
        print('\n'.join([
            '===pman Main Menu===\n',
            'Please review the options below:',
            '\t[1]  View stored credentials',
            '\t[v]  Reset verification sentence',
            '\t[e]  Exit'
        ]))
        sel = input('\nPlease enter your selection:  ').lower()
        if sel == '1':
            view_stored(con, cur)
        elif sel == 'v':
            create_new_verification(phr, con, cur)
        elif sel == 'e':
            print('Thank you for using pman; goodbye.')
            sleep(3)
            break
        input('\nPress enter to return to main menu.')
    return True


if __name__ == '__main__':
    try:
        conn, curs = manage.db_connect(manage.load_config())
        try:
            phrase = load_phrase(conn, curs)
            prompt_menu(phrase, conn, curs)
        finally:
            manage.db_disconnect(conn, curs)
    except Exception as e:
        print(repr(e))
