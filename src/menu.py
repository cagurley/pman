import os
from time import sleep
from cryptography.exceptions import InvalidTag
from src import crud


def load_phrase(con, cur):
    while True:
        p = bytes(input('Please provide your master passphrase:  '), encoding='utf-8')
        clear()
        try:
            crud.verify_phrase(p, con, cur)
        except InvalidTag:
            print('Incorrect passphrase; try again.')
            continue
        else:
            break
    input('Passphrase verified. Press enter to continue. ')
    return p


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    return None


def prompt(phr, con, cur):
    while True:
        clear()
        print('\n'.join([
            '===pman Main Menu===\n',
            'Please review the options below:',
            '\t[1]  View stored credentials',
            '\t[v]  Reset verification sentence',
            '\t[e]  Exit'
        ]))
        sel = input('\nPlease enter your selection:  ').lower()
        if sel == '1':
            crud.view_stored(con, cur)
        elif sel == 'v':
            crud.create_new_verification(phr, con, cur)
        elif sel == 'e':
            print('Thank you for using pman; goodbye.')
            sleep(3)
            break
        input('\nPress enter to return to main menu.')
    clear()
    return True
