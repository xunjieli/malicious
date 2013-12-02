from file_manager import *
from ..common import metadata
from ..common import crypto
import unittest

# test data

user_ids = ['testa', 'testb', 'testc', 'testd']
user_enc_keys = [crypto.generate_user_encryption_keypair() for _ in range(4)]
user_sign_keys = [crypto.generate_user_signature_keypair() for _ in range(4)]
file_key = crypto.generate_symmetric_key()
file_sig_key = crypto.generate_file_signature_keypair()

def public_part(key):
    return key[0], key[1]

class TestFileManager(unittest.TestCase):

    def setUp(self):
        # cleaning up if necessary
        for i in range(0,3):
            if file_exist(1, user_ids[i]):
                delete_file(1, user_ids[i], user_ids[i])

    def test_create_file(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        self.assertTrue(create_file(1, user_ids[0], metafile, datafile))

    def test_create_file_fail(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        try:
            create_file(1, user_ids[1], metafile, datafile)
            self.assertTrue(False)
        except:
            self.assertTrue(True)

    def test_create_file_fail_file_exist(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        self.assertTrue(create_file(1, user_ids[0], metafile, datafile))
        try:
            create_file(1, user_ids[0], metafile, datafile)
            self.assertTrue(False)
        except:
            self.assertTrue(True)

    def test_modify_datafile(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        self.assertTrue(create_file(1, user_ids[0], metafile, datafile))
        try:
            modify_datafile(1, user_ids[0], user_ids[0], "new string")
            with open(datafile_name(1, user_ids[0]), 'r+') as f:
                self.assertTrue(f.read() == "new string")
        except:
            self.assertTrue(False)

    def test_modify_datafile_collaborator(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        self.assertTrue(create_file(1, user_ids[0], metafile, datafile))
        #try:
        modify_datafile(1, user_ids[2], user_ids[0], "new string")
        with open(datafile_name(1, user_ids[0]), 'r+') as f:
             self.assertTrue(f.read() == "new string")
       # except:
        #    self.assertTrue(False)


    def test_modify_datafile_fail(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metafile = metadata.metadata_encode('test_file', False, file_key,
file_sig_key,user_sign_keys[0], owner, [
                (user_ids[1], False, public_part(user_enc_keys[1])),
                (user_ids[2], True, public_part(user_enc_keys[2]))
        ])
        datafile = 'this is datafile'
        self.assertTrue(create_file(1, user_ids[0], metafile, datafile))
        try:
            modify_datafile(1, user_ids[1], user_ids[0], "new string")
            self.assertTrue(False)
        except:
            self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
