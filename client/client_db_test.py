from client_db import *
import unittest
import os

class ClientDBTest(unittest.TestCase):

    def setUp(self):
        os.remove('/tmp/test_file.db')

    def tearDown(self):
        os.remove('/tmp/test_file.db')

    def test_basic_functionality(self):
        db = ClientDB('/tmp/test_file.db')
        private_key = 'some random private key'
        sign_key = 'some random sign key'
        db.new_user('test1', private_key, sign_key)
        self.assertEqual(private_key, db.get_private_key())
        self.assertEqual(sign_key, db.get_sign_key())
        self.assertEqual(0, db.get_last_file_id())
        self.assertEqual(0, db.get_last_auth_counter())
        self.assertEqual(1, db.new_file_id())
        self.assertEqual(1, db.new_auth_counter())
        self.assertEqual(2, db.new_file_id())
        self.assertEqual(2, db.new_auth_counter())
        self.assertEqual(2, db.get_last_file_id())
        self.assertEqual(2, db.get_last_auth_counter())
