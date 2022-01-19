import re
from src import crypt
from src.manage import clear


def display2name(disp):
    name = re.sub(r'\s+', '_', disp)
    return re.sub(r'\W', '', name, re.A).lower()


def generate_password():
    params_loop = True
    while params_loop:
        length = 24
        lower, upper, digit, special = True, True, True, True
        all_required = False
        print('\nDefault password generation parameters are as follows:\n'
              + '\n\tlength: 24'
              + '\n\tvalid characters: lowercase, uppercase, digits, and special'
              + '\n\tat least one of each character group is NOT required')
        default = input('\nIf you would like to change the default parameters, enter [y]:  ')
        if len(default) > 0 and default[0].lower() == 'y':
            inp = input('\nIf you would like to use a different length, enter it now:  ')
            if len(inp) > 0:
                if re.match(r'\d+$', inp, re.A) and int(inp) > 0:
                    length = int(inp)
                else:
                    print('Invalid length value; reverting to default.')
            inp = input('\nIf you would like to exclude any of the default character classes, enter [y]:  ')
            if len(inp) > 0 and inp[0].lower() == 'y':
                groups = [True, True, True, True]
                inp = input('Exclude lowercase letters? (enter [y] if yes)  ')
                if len(inp) > 0 and inp[0].lower() == 'y':
                    groups[0] = False
                inp = input('Exclude uppercase letters? (enter [y] if yes)  ')
                if len(inp) > 0 and inp[0].lower() == 'y':
                    groups[1] = False
                inp = input('Exclude digits? (enter [y] if yes)  ')
                if len(inp) > 0 and inp[0].lower() == 'y':
                    groups[2] = False
                inp = input('Exclude special characters? (enter [y] if yes)  ')
                if len(inp) > 0 and inp[0].lower() == 'y':
                    groups[3] = False
                if not any(groups):
                    print('Cannot exclude all character groups; reverting to default.')
                else:
                    lower, upper, digit, special = groups
                    using = []
                    if lower:
                        using.append('lowercase')
                    if upper:
                        using.append('uppercase')
                    if digit:
                        using.append('digits')
                    if special:
                        using.append('special')
                    print(f"Now using these character groups: {', '.join(using)}")
            inp = input('\nIf you would like to require at least one character from each group, enter [y]:  ')
            if len(inp) > 0 and inp[0].lower() == 'y':
                all_required = True
        params_loop = False
        gen_loop = True
        while gen_loop:
            pw = crypt.generate_string(length, all_required, lower, upper, digit, special)
            print(f'Generated the following password:  {pw}')
            while True:
                inp = input('\nEnter [y] to accept, [r] to regenerate, or [c] to change parameters:  ').lower()
                if len(inp) > 0:
                    inp = inp[0]
                if inp == 'c':
                    params_loop = True
                    gen_loop = False
                    break
                elif inp == 'r':
                    break
                elif inp == 'y':
                    gen_loop = False
                    break
    return pw


def prompt_service(con, cur):
    disp = input('\nPlease enter the service associated with the password as you would like it to be displayed:  ')
    disp = disp.strip()
    while True:
        name = display2name(disp)
        with con:
            cur.execute("SELECT 1 FROM stored WHERE name = ? ORDER BY name", [name])
            if len(name) < 0 or cur.fetchone():
                disp = input('\nThe provided name has already been used; please enter a name not yet used:  ')
            else:
                break
    return name, disp


def prompt_password(phr):
    wiz = input('\nNow you will be guided through the password generation wizard (recommended); '
                + 'if you would rather provide your own password, enter [n]:  ')
    if len(wiz) > 0 and wiz[0].lower() == 'n':
        pw = input('\nNow enter the password to be associated with the given service:  ')
        while not pw:
            pw = input('\nNo password was provided; please enter the associated password:  ')
    else:
        pw = generate_password()
    return crypt.bv2cs(crypt.encrypt(phr, pw))


def add_stored(con, cur, phr):
    name, disp = prompt_service(con, cur)
    ct = prompt_password(phr)
    with con:
        cur.execute("INSERT INTO stored (name, display, cipher_text) VALUES (?, ?, ?)", [name, disp, ct])
    print(f'\nNew password for service {disp} stored.\n')
    return True


def print_stored(results):
    print('\n===STORED CREDENTIALS===\n')
    for i, row in enumerate(results):
        print(f'{i+1:4}.\t' + row[1])
    return None


def prompt_from_results(con, cur, phr, rows):
    sel = input('\nIf you would like to retrieve a password from a listed service, enter its number now:  ')
    if rows and re.match(r'\d+$', sel) and 0 < int(sel) <= len(rows):
        sel = int(sel) - 1
        rid = rows[sel][0]
        with con:
            cur.execute("SELECT display, cipher_text FROM stored WHERE id = ? LIMIT 1", [rid])
            row = cur.fetchone()
        print(f'Password for {row[0]}:  {crypt.decrypt(phr, *crypt.cs2bv(row[1]))}')
        print('\n'.join([
            'Would you like to do modify this credential?\n',
            '[1]\tUpdate service name',
            '[2]\tChange password',
            '[x]\tDelete credential'
        ]))
        while True:
            sel = input('\nSelection (default is none):  ').lower()
            if len(sel) == 0:
                break
            elif sel == '1':
                name, disp = prompt_service(con, cur)
                with con:
                    cur.execute("UPDATE stored SET name = ?, display = ? WHERE id = ?", [name, disp, rid])
                break
            elif sel == '2':
                sel = input('Are you sure you want to change the password for this service? ([y] to confirm)  ').lower()
                if len(sel) > 0 and sel == 'y':
                    ct = prompt_password(phr)
                    with con:
                        cur.execute("UPDATE stored SET cipher_text = ? WHERE id = ?", [ct, rid])
                    break
            elif sel == 'x':
                sel = input('\nWARNING!!! THIS WILL PERMANENTLY DELETE THIS CREDENTIAL.\n'
                            + 'Are you sure you want to delete? (type [DELETE] to confirm)  ')
                if sel == 'DELETE':
                    with con:
                        cur.execute("DELETE FROM stored WHERE id = ?", [rid])
                    break
        return True
    elif len(sel) > 0:
        print('Invalid selection; try again.')
    else:
        return False


def view_stored(con, cur, phr):
    view = True
    while view:
        with con:
            cur.execute("SELECT id, display FROM stored WHERE name <> '~phrase_verification' ORDER BY name")
            rows = cur.fetchall()
        print_stored(rows)
        view = prompt_from_results(con, cur, phr, rows)
        clear()
    return None


def search_stored(con, cur, phr):
    inp = input('\nEnter a search term for the desired service:  ').strip()
    search = '%' + display2name(inp) + '%'
    view = True
    while view:
        with con:
            cur.execute("SELECT id, display FROM stored WHERE name LIKE ? and name <> '~phrase_verification' ORDER BY name", [search])
            found = cur.fetchall()
        print_stored(found)
        view = prompt_from_results(con, cur, phr, found)
        clear()
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
        '\nPlease provide a sentence to be used to verify input of your master passphrase.',
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
