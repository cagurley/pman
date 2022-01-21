import json
import os
from pathlib import Path
import sqlite3 as sq3


CDIR = Path('./config')
CFILE = CDIR.joinpath('config.json')


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    return None


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
    con = sq3.connect(db)
    cur = con.cursor()
    with con:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS stored (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                display TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)
    return con, cur


def db_disconnect(con, cur):
    cur.close()
    con.close()
    return True
