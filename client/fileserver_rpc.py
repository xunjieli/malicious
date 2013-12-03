from ..common.crypto import *
from ..common.auth import *
from ..common.rpc_status_codes import *
from ..common.rpclib import *
# db_service is client-side to save auth_counter
# needs to support:
#   new_auth_counter(), which returns an incrementing int
class FileServerRpcStub:
    def __init__(self, rpc_client):
        self.rpc_client = rpc_client
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
        auth_counter_result = self.rpc_client.call('get_auth_counter', self.user_id)
        if auth_counter_result[0] != RPC_OK:
            raise Exception("Cannot get authentication counter")
        auth_counter = auth_counter_result[1] + 1
        result = self.rpc_client.call('authenticate', self.user_id,
                *self.authenticator.makeHandshakeRequest(auth_counter))
        if result[0] != RPC_OK:
            raise Exception("Authentication failure.")
        self.authenticator.acceptHandshakeResponse(result[1])

    def generic_call(self, name, *args):
        if self.authenticator is None: self.authenticate()
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


class FileServerConnector:
    def __init__(self, host, port):
        self.host = host
        self.port = port
    def call(self, method, *args):
        rpc = client_connect(self.host, self.port)
        result = rpc.call(method, *args)
        rpc.close()
        return result