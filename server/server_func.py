import file_manager
from ..common.rpc_status_codes import *

class ServerFuncs:
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager

    def rpc_authenticate(self, client_id, auth_counter, auth_counter_sig):
        encrypted_aes_key = self.auth_manager.acceptHandshakeRequest(client_id, auth_counter, auth_counter_sig)
        return encrypted_aes_key

    def check_token(self, client_id, token):
        return self.auth_manager.verifyToken(client_id, token)

    def rpc_read_file(self, client_id, owner_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            meta = file_manager.read_metadata(fileID, client_id, owner_id)
            data = file_manager.read_datafile(fileID, client_id, owner_id)
            return RPC_OK, (meta, data)
        except:
            print "Unexpected error read_file"
            return RPC_ERROR,

    def rpc_read_metadata(self, client_id, owner_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            return RPC_OK, file_manager.read_metadata(fileID, client_id, owner_id)
        except:
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_upload_file(self, client_id, fileID, metadata_file, data_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            file_manager.create_file(fileID, client_id, metadata_file, data_file)
            return RPC_OK, True
        except:
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_modify_metadata(self, client_id, owner_id, fileID, metadata_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            file_manager.modify_metadata(fileID, client_id, metadata_file)
            return RPC_OK, True
        except:
            print "Unexpected error read_metafile"
            return RPC_ERROR,


    def rpc_modify_file(self, client_id, owner_id, fileID, data_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            file_manager.modify_datafile(fileID, client_id, data_file)
            return RPC_OK, True
        except:
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_remove_file(self, client_id, owner_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        if file_manager.modify_datafile(fileID, client_id, data_file):
            return RPC_OK, True
        return RPC_ERROR

    def rpc_get_auth_counter(self, client_id):
        # TODO: Implement something here (use a DB for example)
        return RPC_OK, 0