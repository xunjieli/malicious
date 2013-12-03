from ..common.crypto import *
from ..common.auth import *
from ..common.rpc_status_codes import *

class FileServerRpcStub:
    def __init__(self, rpc_client, db_service):
        self.rpc_client = rpc_client
        self.db_service = db_service
        self.user_id = None
        self.user_private_key = None
        self.user_sign_key = None
        self.authenticator = None

    def set_user(self, user_id, user_private_key, user_sign_key):
        self.user_id = user_id
        self.user_private_key = user_private_key
        self.user_sign_key = user_sign_key

    def authenticate(self):
        self.authenticator = ClientAuthenticator(self.user_private_key, self.user_sign_key)
        auth_counter = self.db_service.new_auth_counter()
        result = self.rpc_client.call('authenticate', self.user_id,
                *self.authenticator.makeHandshakeRequest(auth_counter))
        if result[0] != RPC_OK:
            raise Exception("Authentication failure.")
        self.authenticator.acceptHandshakeResponse(result[1])

    def generic_call(self, name, *args):
        result = self.rpc_client.call(name, self.user_id, *args, self.authenticator.newToken())
        if result[0] == RPC_WRONG_TOKEN:
            self.authenticate()
            return self.generic_call(name, *args)
        if result[0] != RPC_OK:
            raise Exception("Error when calling: " + name)
        return result[1]

    read_file = lambda self, owner_id, file_id: self.generic_call('read_file', owner_id, file_id)
    read_metadata = lambda self, owner_id, file_id: self.generic_call('read_metadata', owner_id, file_id)
    upload_file = lambda self, file_id, metadata_file, data_file: self.generic_call('upload_file', file_id, metadata_file, data_file)
    modify_metadata = lambda self, owner_id, file_id, metadata_file: self.generic_call('modify_metadata', owner_id, file_id, metadata_file)
    modify_file = lambda self, owner_id, file_id, data_file: self.generic_call('modify_file', owner_id, file_id, data_file)
    remove_file = lambda self, owner_id, file_id: self.generic_call('remove_file', owner_id, file_id)

