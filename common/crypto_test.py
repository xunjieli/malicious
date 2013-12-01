import unittest

from crypto import *

class TestCrypto(unittest.TestCase):

    def setUp(self):
        pass

    def test_pad_1(self):
        text = 'abcdefg'
        expected = 'abcdefg' + pack('B', 0x80) + pack('B', 0) * 8
        self.assertEqual(expected, pad(text, 16))

    def test_pad_2(self):
        text = 'abcdefghijklmnop'
        expected = 'abcdefghijklmnop' + pack('B', 0x80) + pack('B', 0) * 15
        self.assertEqual(expected, pad(text, 16))

    def test_unpad(self):
        padded = 'abcdefg' + pack('B', 0x80) + pack('B', 0) * 8
        self.assertEqual('abcdefg', unpad(padded))

    def test_pad_unpad(self):
        for i in range(33):
            text = Random.new().read(i)
            self.assertEqual(text, unpad(pad(text, 16)))

    def test_aes_encrypt_decrypt(self):
        key = Random.new().read(32)
        text = Random.new().read(1000)
        encrypted = symmetric_encrypt(text, key)
        decrypted = symmetric_decrypt(encrypted, key)
        self.assertEqual(text, decrypted)

    def test_aes_encrypt_decrypt_2(self):
        key = Random.new().read(32)
        text = Random.new().read(1024)
        encrypted = symmetric_encrypt(text, key)
        decrypted = symmetric_decrypt(encrypted, key)
        self.assertEqual(text, decrypted)

    def test_aes_encrypt_randomness(self):
        key = Random.new().read(32)
        text = Random.new().read(1000)
        e1 = symmetric_encrypt(text, key)
        e2 = symmetric_encrypt(text, key)
        self.assertNotEqual(e1, e2)
        self.assertNotEqual(e1[16:], e2[16:])

    def test_generate_symmetric_key(self):
        keys = set()
        for i in range(100):
            key = generate_symmetric_key()
            self.assertEqual(SYMMETRIC_KEY_SIZE, len(key))
            self.assertFalse(key in keys)
            keys.add(key)

    def test_asymmetric_key_generation(self):
        Ns = set()
        ds = set()
        for i in range(5):
            key = generate_asymmetric_keypair(1024)
            self.assertFalse(key[0] in Ns)
            self.assertFalse(key[2] in ds)
            Ns.add(key[0])
            ds.add(key[2])

    def test_asymmetric_encryption_decryption(self):
        N, e, d = generate_asymmetric_keypair(1024)
        text = generate_symmetric_key()
        encrypted = asymmetric_encrypt((N, e), text)
        decrypted = asymmetric_decrypt((N, e, d), encrypted)
        self.assertEqual(text, decrypted)

    def test_asymmetric_encryption_randomness(self):
        N, e, d = generate_asymmetric_keypair(1024)
        text = generate_symmetric_key()
        e1 = asymmetric_encrypt((N, e), text)
        e2 = asymmetric_encrypt((N, e), text)
        self.assertNotEqual(e1, e2)

    def test_sign_verify(self):
        N, e, d = generate_file_signature_keypair()
        text = Random.new().read(100000)
        signature = asymmetric_sign((N, e, d), text)
        result = asymmetric_verify((N, e), text, signature)
        self.assertTrue(result)

    def test_sign_randomness(self):
        N, e, d = generate_file_signature_keypair()
        text = Random.new().read(100000)
        s1 = asymmetric_sign((N, e, d), text)
        s2 = asymmetric_sign((N, e, d), text)
        self.assertNotEqual(s1, s2)

    def test_verify_correctness(self):
        N, e, d = generate_file_signature_keypair()
        text = Random.new().read(100000)
        falseText = text[1:]
        falseSignature = asymmetric_sign((N, e, d), falseText)
        result = asymmetric_verify((N, e), text, falseSignature)
        self.assertFalse(result)

    def test_export_import_key(self):
        N, e, d = generate_file_signature_keypair()
        self.assertEqual((N, e, d), import_key(export_key((N, e, d))))

    def test_user_encrypting_file_signature_key(self):
        N, e, d = generate_user_encryption_keypair()
        fN, fe, fd = generate_file_signature_keypair()
        encrypted = asymmetric_ecb_encrypt_blocks((N, e), export_key((fN, fe, fd)), USER_ENCRYPTION_KEY_MAX_MSG_SIZE)
        decrypted = asymmetric_ecb_decrypt_blocks((N, e, d), encrypted)
        self.assertEqual((fN, fe, fd), import_key(decrypted))


if __name__ == '__main__':
    unittest.main()
