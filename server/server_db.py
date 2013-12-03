import sqlite3 as sqlite

class ServerDB:
    def __init__(self, db_file):
        self.conn = sqlite.connect(db_file)
        self.initialize_db()

    def initialize_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            create table if not exists User (
                user_id text,
                last_auth_counter int
            )
        """.strip())

    def _get_int_field(self, user_id, name):
        cur = self.conn.cursor()
        cur.execute('select ' + name + ' from User where user_id = ?', (user_id,))
        for row in cur: return int(row[0])
        return None

    def _set_field(self, user_id, name, value):
        cur = self.conn.cursor()
        cur.execute('update User set ' + name + ' = ? where user_id = ?', (value, user_id))

    def _get_str_field(self, user_id, name):
        cur = self.conn.cursor()
        cur.execute('select ' + name + ' from User where user_id = ?', (user_id,))
        for row in cur: return str(row[0])
        return None

    def new_user(self, user_id):
        cur = self.conn.cursor()
        cur.execute('insert into User (user_id, last_auth_counter) values (' +
                    '?, ?)', (user_id, 0))

    def get_last_auth_counter(self, user_id):
        return self._get_int_field(user_id, 'last_auth_counter')
    def set_last_auth_counter(self, user_id, last_auth_counter):
        self._set_field(user_id, 'last_auth_counter', last_auth_counter)