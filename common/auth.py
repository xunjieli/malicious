from crypto import *

class ClientAuthenticator:
    def __init__(self, private_key, sign_key):
        self.private_key = private_key
        self.sign_key = sign_key
        self.message_counter = None
        self.aes_key = None

    # returns (counter, counter signature), both strings
    def makeHandshakeRequest(self, auth_counter):
        counter_str = pack('<I', auth_counter)
        return counter_str, asymmetric_sign(self.sign_key, counter_str)

    def acceptHandshakeResponse(self, encrypted_aes_key):
        self.aes_key = asymmetric_decrypt(self.private_key, encrypted_aes_key)
        self.message_counter = 0

    def newToken(self):
        self.message_counter += 1
        random_encryption = symmetric_encrypt(pack('B', 0) * 24 + pack('<I', self.message_counter), self.aes_key)
        return random_encryption


class _ServerAuthenticator:
    def __init__(self, user_id, last_counter, user_public_key, user_verify_key):
        self.user_id = user_id
        self.last_counter = last_counter
        self.user_public_key = user_public_key
        self.user_verify_key = user_verify_key
        self.aes_key = None
        self.message_counter = None


class ServerAuthenticationManager:
    def __init__(self, public_key_service, auth_db_service):
        self.public_key_service = public_key_service
        self.auth_db_service = auth_db_service
        self.users = {}

    def acceptHandshakeRequest(self, user_id, auth_counter, auth_counter_sig):
        try:
            if user_id not in self.users:
                self.users[user_id] = _ServerAuthenticator(user_id,
                                                           self.auth_db_service.get_auth_counter(user_id),
                                                           self.public_key_service.get_public_key(user_id),
                                                           self.public_key_service.get_verify_key(user_id))
            user = self.users[user_id]
            auth_counter_num = unpack('<I', auth_counter)[0]
            if auth_counter_num > user.last_counter and\
                    asymmetric_verify(user.user_verify_key, auth_counter, auth_counter_sig):
                self.auth_db_service.set_auth_counter(user_id, auth_counter_num)
                user.last_counter = auth_counter_num
                user.aes_key = generate_symmetric_key()
                user.message_counter = 0
                return asymmetric_encrypt(user.user_public_key, user.aes_key)
            else:
                return None
        except:
            return None

    def verifyToken(self, user_id, token):
        if user_id not in self.users:
            return False
        user = self.users[user_id]
        decrypted_token = symmetric_decrypt(token, user.aes_key)
        if len(decrypted_token) != 28:
            return False
        should_be_zeros = decrypted_token[:24]
        if should_be_zeros != pack('B', 0) * 24:
            return False
        message_counter = unpack('<I', decrypted_token[24:])[0]
        if message_counter <= user.message_counter:
            return False
        user.message_counter = message_counter
        return True

