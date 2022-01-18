import os
from time import sleep
from cryptography.exceptions import InvalidTag
from src import crud


MAIN_MENU = """
===pman Main Menu===

Please review the options below:
    [1]  View stored credentials
    [2]  Search stored credentials
    [3]  Add stored credential
    [v]  Reset verification sentence
    [c]  Change master passphrase
    [e]  Exit
"""


def load_phrase(con, cur):
    while True:
        p = crud.prompt_phrase('Please provide your master passphrase:  ')
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
        print(MAIN_MENU)
        sel = input('Please enter your selection:  ').lower()
        if sel == '1':
            crud.view_stored(con, cur)
        elif sel == '2':
            crud.search_stored(con, cur)
        elif sel == '3':
            crud.add_stored(con, cur, phr)
        elif sel == 'v':
            crud.create_new_verification(phr, con, cur)
        elif sel == 'c':
            print(
                '\n***WARNING***\n'
                + 'Changing your master passphrase is irreversible; '
                + 'you will need to use the new phrase for future access.\n'
            )
            confirm = input('Do you wish to continue? ([y] to accept)  ').lower()
            if confirm == 'y':
                new = crud.prompt_phrase('Please provide your new master passphrase:  ')
                crud.reencrypt_stored(phr, new, con, cur)
                phr = new
        elif sel == 'e':
            print('Thank you for using pman; goodbye.')
            sleep(3)
            break
        input('\nPress enter to return to main menu.')
    clear()
    return True
