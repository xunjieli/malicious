from auth import *
import pickle

import unittest

user_ids = ['testa', 'testb', 'testc', 'testd']
user_enc_keys = [generate_user_encryption_keypair() for _ in range(4)]
user_sign_keys = [generate_user_signature_keypair() for _ in range(4)]

def public_part(key):
    return key[0], key[1]

class TestAuth(unittest.TestCase):
    def setUp(self):
        class MockAuthDB:
            def __init__(self):
                self.counters = {}
            def get_auth_counter(self, user):
                if user in self.counters: return self.counters[user]
                return 0
            def set_auth_counter(self, user, c):
                self.counters[user] = c
        class MockKeyServer:
            def __init__(self):
                self.public_keys = {user: public_part(key) for (user, key) in zip(user_ids, user_enc_keys)}
                self.verify_keys = {user: public_part(key) for (user, key) in zip(user_ids, user_sign_keys)}
            def get_public_key(self, user):
                return self.public_keys[user]
            def get_verify_key(self, user):
                return self.verify_keys[user]
        self.mock_auth_db = MockAuthDB()
        self.mock_key_server = MockKeyServer()

    def test_normal_authentication(self):
        client_auth = ClientAuthenticator(user_enc_keys[0], user_sign_keys[0])
        server_auth = ServerAuthenticationManager(self.mock_key_server, self.mock_auth_db)
        encrypted_aes_key = server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(1))
        self.assertIsNotNone(encrypted_aes_key)
        client_auth.acceptHandshakeResponse(encrypted_aes_key)
        self.assertEqual(client_auth.aes_key, server_auth.users[user_ids[0]].aes_key)
        tokens = [client_auth.newToken() for _ in range(10)]
        token_results = [server_auth.verifyToken(user_ids[0], token) for token in tokens]
        self.assertEqual([True] * 10, token_results)

    def test_normal_authentication_with_loss_of_packets(self):
        client_auth = ClientAuthenticator(user_enc_keys[0], user_sign_keys[0])
        server_auth = ServerAuthenticationManager(self.mock_key_server, self.mock_auth_db)
        encrypted_aes_key = server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(1))
        self.assertIsNotNone(encrypted_aes_key)
        client_auth.acceptHandshakeResponse(encrypted_aes_key)
        self.assertEqual(client_auth.aes_key, server_auth.users[user_ids[0]].aes_key)
        tokens = [client_auth.newToken() for i in range(10) if i % 2 == 0]
        token_results = [server_auth.verifyToken(user_ids[0], token) for token in tokens]
        self.assertEqual([True] * 5, token_results)

    def test_DoS(self):
        # same test as test_normal_authentication, but interlaced with a bunch of fake authentication requests
        client_auth = ClientAuthenticator(user_enc_keys[0], user_sign_keys[0])
        fake_client_auth = ClientAuthenticator(user_enc_keys[1], user_sign_keys[1])
        fake_client_auth.aes_key = generate_symmetric_key()
        fake_client_auth.message_counter = 0
        server_auth = ServerAuthenticationManager(self.mock_key_server, self.mock_auth_db)
        def attack_false_signature():
            server_auth.acceptHandshakeRequest(user_ids[0], client_auth.makeHandshakeRequest(2)[0], client_auth.makeHandshakeRequest(1)[1])
        def attack_others_signature():
            server_auth.acceptHandshakeRequest(user_ids[0], *fake_client_auth.makeHandshakeRequest(2))
        def attack_replay_signature():
            server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(1))
        def attack_replay_signature_2():
            server_auth.acceptHandshakeRequest(user_ids[1], *client_auth.makeHandshakeRequest(1))
        def attack_false_token():
            server_auth.verifyToken(user_ids[0], fake_client_auth.newToken())
        def attacks():
            attack_false_signature()
            attack_replay_signature()
            attack_replay_signature_2()
            attack_others_signature()
            attack_false_token()

        attack_false_signature()
        encrypted_aes_key = server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(1))
        self.assertIsNotNone(encrypted_aes_key)
        attacks()
        client_auth.acceptHandshakeResponse(encrypted_aes_key)
        self.assertEqual(client_auth.aes_key, server_auth.users[user_ids[0]].aes_key)
        attacks()
        tokens = [client_auth.newToken() for _ in range(10)]
        token_results = [server_auth.verifyToken(user_ids[0], token) for token in tokens]
        self.assertEqual([True] * 10, token_results)
        attacks()
        tokens = [client_auth.newToken() for _ in range(10)]
        token_results = [server_auth.verifyToken(user_ids[0], token) for token in tokens]
        self.assertEqual([True] * 10, token_results)

    def test_failing_authentication(self):
        client_auth = ClientAuthenticator(user_enc_keys[0], user_sign_keys[0])
        fake_client_auth = ClientAuthenticator(user_enc_keys[1], user_sign_keys[1])
        fake_client_auth.aes_key = generate_symmetric_key()
        fake_client_auth.message_counter = 0
        server_auth = ServerAuthenticationManager(self.mock_key_server, self.mock_auth_db)
        self.mock_auth_db.counters[user_ids[0]] = 4

        #invalid everything
        self.assertIsNone(server_auth.acceptHandshakeRequest(user_ids[0], 'fake id', 'fake signature'))
        #invalid signature
        self.assertIsNone(server_auth.acceptHandshakeRequest(user_ids[0], client_auth.makeHandshakeRequest(5)[0],
                                                             client_auth.makeHandshakeRequest(300)[1]))
        #old counter
        self.assertIsNone(server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(4)))
        #signature from wrong user
        self.assertIsNone(server_auth.acceptHandshakeRequest(user_ids[0], *fake_client_auth.makeHandshakeRequest(6)))

        #correct auth
        encrypted_aes_key = server_auth.acceptHandshakeRequest(user_ids[0], *client_auth.makeHandshakeRequest(5))
        self.assertIsNotNone(encrypted_aes_key)
        client_auth.acceptHandshakeResponse(encrypted_aes_key)
        self.assertEqual(client_auth.aes_key, server_auth.users[user_ids[0]].aes_key)
        tokens = [client_auth.newToken() for _ in range(10)]
        token_results = [server_auth.verifyToken(user_ids[0], token) for token in tokens]
        self.assertEqual([True] * 10, token_results)

        #replay token
        self.assertFalse(server_auth.verifyToken(user_ids[0], tokens[9]))

        #correct token
        self.assertTrue(server_auth.verifyToken(user_ids[0], client_auth.newToken()))

        #other's token
        self.assertFalse(server_auth.verifyToken(user_ids[0], fake_client_auth.newToken()))

if __name__ == '__main__':
    unittest.main()
