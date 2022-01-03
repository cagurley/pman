from src import manage, menu


if __name__ == '__main__':
    try:
        conn, curs = manage.db_connect(manage.load_config())
        try:
            phrase = menu.load_phrase(conn, curs)
            menu.prompt(phrase, conn, curs)
        finally:
            manage.db_disconnect(conn, curs)
    except Exception as e:
        print(repr(e))
