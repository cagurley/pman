from src import crypt


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
    ct = '$'.join([val.hex() for val in crypt.encrypt(phr, s)])
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
    return crypt.decrypt(phr, *[bytes.fromhex(val) for val in verification.split('$')])
