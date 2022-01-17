import re
from src import crypt


def add_stored(con, cur, phr):
    disp = input('\nPlease enter the service associated with the password as you would like it to be displayed:  ')
    while True:
        name = re.sub(r'\s', '_', disp)
        name = re.sub(r'[^\w\d]', '', name).lower()
        with con:
            cur.execute("SELECT 1 FROM stored WHERE name = ? ORDER BY name", [name])
            if cur.fetchone():
                disp = input('\nThe provided name has already been used; please enter a name not yet used:  ')
            else:
                break
    pw = input('\nNow enter the password to be associated with the given service:  ')
    while not pw:
        pw = input('\nNo password was provided; please enter the associated password:  ')
    ct = crypt.bv2cs(crypt.encrypt(phr, pw))
    with con:
        cur.execute("INSERT INTO stored (name, display, cipher_text) VALUES (?, ?, ?)", [name, disp, ct])
    return True


def view_stored(con, cur):
    with con:
        cur.execute("SELECT display FROM stored ORDER BY name")
        vals = cur.fetchall()
    print('===STORED CREDENTIALS===\n')
    for val in vals:
        print('\t' + val[0])
    return None


def reencrypt_stored(oldp, newp, con, cur):
    with con:
        cur.execute("SELECT id, cipher_text FROM stored")
        rows = cur.fetchall()
        for row in rows:
            pt = crypt.decrypt(oldp, *crypt.cs2bv(row[1]))
            ct = crypt.bv2cs(crypt.encrypt(newp, pt))
            cur.execute("UPDATE stored SET cipher_text = ? WHERE id = ?", [ct, row[0]])
    return True


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
    ct = crypt.bv2cs(crypt.encrypt(phr, s))
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
    return crypt.decrypt(phr, *crypt.cs2bv(verification))


def prompt_phrase(prompt):
    while True:
        p = input(prompt)
        if len(p) < 24:
            input('\nPassphrase must be at least 24 characters in length; try again.\n')
        else:
            break
    return bytes(p, encoding='utf-8')
