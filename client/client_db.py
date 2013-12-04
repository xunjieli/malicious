import sqlite3 as sqlite
from ..common.crypto import *

class ClientDB:
    def __init__(self, db_file):
        self.conn = sqlite.connect(db_file)
        self.initialize_db()
        self.user_id = None

    def initialize_db(self):
        cur = self.conn.cursor()
        cur.execute("""
            create table if not exists client (
                user_id text,
                private_key text,
                sign_key text,
                last_file_id int,
                last_auth_counter int
            )
        """.strip())

    def _get_int_field(self, user_id, name):
        cur = self.conn.cursor()
        cur.execute('select ' + name + ' from client where user_id = ?', (user_id,))
        for row in cur: return int(row[0])
        return None

    def _set_field(self, user_id, name, value):
        cur = self.conn.cursor()
        cur.execute('update client set ' + name + ' = ? where user_id = ?', (value, user_id))
        self.conn.commit()

    def _set_blob_field(self, user_id, name, value):
        cur = self.conn.cursor()
        cur.execute('update client set ' + name + ' = ? where user_id = ?', (buffer(value), user_id))
        self.conn.commit()

    def _get_str_field(self, user_id, name):
        cur = self.conn.cursor()
        cur.execute('select ' + name + ' from client where user_id = ?', (user_id,))
        for row in cur: return str(row[0])
        return None

    def new_user(self, user_id, private_key, sign_key):
        cur = self.conn.cursor()
        cur.execute('insert into client (user_id, private_key, sign_key, last_file_id, last_auth_counter) values (' +
                    '?, ?, ?, ?, ?)', (user_id, buffer(export_key(private_key)), buffer(export_key(sign_key)), -1, 0))
        self.conn.commit()
        self.select_user(user_id)

    def select_user(self, user_id):
        self.user_id = user_id

    def user_exists(self):
        return self._get_str_field(self.user_id, 'user_id') is not None

    def get_private_key(self):
        return import_key(self._get_str_field(self.user_id, 'private_key'))
    def set_private_key(self, private_key):
        self._set_blob_field(self.user_id, 'private_key', export_key(private_key))

    def get_sign_key(self):
        return import_key(self._get_str_field(self.user_id, 'sign_key'))
    def set_sign_key(self, sign_key):
        self._set_blob_field(self.user_id, 'sign_key', export_key(sign_key))

    def get_last_file_id(self):
        return self._get_int_field(self.user_id, 'last_file_id')
    def set_last_file_id(self, last_file_id):
        self._set_field(self.user_id, 'last_file_id', last_file_id)
    def new_file_id(self):
        file_id = self.get_last_file_id()
        self.set_last_file_id(file_id + 1)
        return file_id + 1

    def get_last_auth_counter(self):
        return self._get_int_field(self.user_id, 'last_auth_counter')
    def set_last_auth_counter(self, last_auth_counter):
        self._set_field(self.user_id, 'last_auth_counter', last_auth_counter)
    def new_auth_counter(self):
        counter = self.get_last_auth_counter()
        self.set_last_auth_counter(counter + 1)
        return counter + 1