from metadata import *
import unittest
import os
import pickle

def public_part(key):
    return key[0], key[1]

if os.path.isfile('metadata_test_keys'):
    user_ids, user_enc_keys, user_sign_keys, file_key, file_sig_key = pickle.load(open('metadata_test_keys', 'rb'))
else:
    print "Generating 16 keypairs... This takes a long time, but will only happen once"
    user_ids = ['testa', 'testb', 'testc', 'testd']
    user_enc_keys = [generate_user_encryption_keypair() for _ in range(4)]
    user_sign_keys = [generate_user_signature_keypair() for _ in range(4)]
    file_key = generate_symmetric_key()
    file_sig_key = generate_file_signature_keypair()
    pickle.dump((user_ids, user_enc_keys, user_sign_keys, file_key, file_sig_key), open('metadata_test_keys', 'wb'))

class TestCrypto(unittest.TestCase):

    def setUp(self):
        pass

    def test_pack_data_unpack_data(self):
        a, b, c = [Random.new().read(i) for i in [100, 400, 300]]
        packed = pack_data(a, b, c)
        self.assertEqual([a, b, c], unpack_data(packed, 3))
        self.assertEqual([a, b, c], unpack_data(packed))
        try:
            unpack_data(packed, 2)
            self.assertFalse(True)
        except UnpackException as e:
            pass

    def test_metadata_encode_decode(self):
        # User 0 is owner, user 1 has read, user 2 has read/write, user 3 has no access
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metadata = metadata_encode('test_file', False, file_key, file_sig_key,
user_sign_keys[0], owner, [
            (user_ids[1], False, public_part(user_enc_keys[1])),
            (user_ids[2], True, public_part(user_enc_keys[2])),
        ])

        decoded_metadatas = [
            metadata_decode(metadata, public_part(user_sign_keys[0]), user_ids[i], user_enc_keys[i])
            for i in range(4)
        ]

        owner_id = user_ids[0]
        users = [(user_ids[1], False), (user_ids[2], True)]
        self.assertEqual(
            ('test_file', False, public_part(file_sig_key), file_key, file_sig_key, owner_id, users),
            decoded_metadatas[0])

        self.assertEqual(
            ('test_file', False, public_part(file_sig_key), file_key, None, owner_id, users),
            decoded_metadatas[1])

        self.assertEqual(
            ('test_file', False, public_part(file_sig_key), file_key,
file_sig_key, owner_id, users),
            decoded_metadatas[2])

        self.assertEqual(
            ('test_file', False, public_part(file_sig_key), None, None,
owner_id, users),
            decoded_metadatas[3])

    def test_metadata_encode_decode_folder(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metadata = metadata_encode('test_file', True, file_key, file_sig_key,
user_sign_keys[0], owner, [])

        decoded_metadata = metadata_decode(metadata, public_part(user_sign_keys[0]), user_ids[0], user_enc_keys[0])
        self.assertEqual(
            ('test_file', True, public_part(file_sig_key), file_key, file_sig_key, 0, []),
              decoded_metadata)

    def test_metadata_encode_verify(self):
        owner = (user_ids[0], public_part(user_enc_keys[0]))
        metadata = metadata_encode('test_file', True, file_key, file_sig_key,
user_sign_keys[0], owner, [])
        metadata_sig, metadata_block = unpack_data(metadata)
        fake_metadata_block = 'fake' + metadata_block[4:]
        fake_metadata_sig = 'fake' + metadata_sig[4:]
        self.assertTrue(metadata_verify(pack_data(metadata_sig, metadata_block), public_part(user_sign_keys[0])))
        self.assertFalse(metadata_verify(pack_data(fake_metadata_sig, metadata_block), public_part(user_sign_keys[0])))
        self.assertFalse(metadata_verify(pack_data(metadata_sig, fake_metadata_block), public_part(user_sign_keys[0])))
        self.assertFalse(metadata_verify(pack_data(metadata_sig, metadata_block), public_part(user_sign_keys[1])))

if __name__ == '__main__':
    unittest.main()
