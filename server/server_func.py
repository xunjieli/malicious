import file_manager
from ..common.rpc_status_codes import *
import traceback


class ServerFuncs(object):
    def __init__(self, auth_manager):
        self.auth_manager = auth_manager

    def rpc_authenticate(self, client_id, auth_counter, auth_counter_sig):
        encrypted_aes_key = self.auth_manager.acceptHandshakeRequest(client_id, auth_counter, auth_counter_sig)
        if encrypted_aes_key is not None:
            return RPC_OK, encrypted_aes_key
        return RPC_ERROR,

    def check_token(self, client_id, token):
        return self.auth_manager.verifyToken(client_id, token)

    def rpc_read_file(self, client_id, owner_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN(),
        try:
            meta = file_manager.read_metadata(fileID, client_id, owner_id)
            data = file_manager.read_datafile(fileID, client_id, owner_id)
            return RPC_OK, (meta, data)
        except PermissionDeniedError as e:
            return RPC_ERROR, e.value
        except Exception as e:
            traceback.print_exc()
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_read_metadata(self, client_id, owner_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN(),
        try:
            return RPC_OK, file_manager.read_metadata(fileID, client_id, owner_id)
        except PermissionDeniedError as e:
            return RPC_ERROR, e.value
        except Exception as e:
            traceback.print_exc()
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_upload_file(self, client_id, fileID, metadata_file, data_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN(),
        try:
            file_manager.create_file(fileID, client_id, metadata_file, data_file)
            return RPC_OK, True
        except Exception as e:
            traceback.print_exc()
            print "Unexpected error read_metafile"
            return RPC_ERROR,

    def rpc_modify_metadata(self, client_id, fileID, metadata_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        try:
            file_manager.modify_metadata(fileID, client_id, metadata_file)
            return RPC_OK, True
        except PermissionDeniedError as e:
            print "Unexpected error read_metafile: %s" % e.value
            return RPC_ERROR,e.value
        except Exception as e:
            traceback.print_exc()

    def rpc_modify_metadata(self, client_id, fileID, metadata_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN(),
        try:
            file_manager.modify_metadata(fileID, client_id, metadata_file)
            return RPC_OK, True
        except PermissionDeniedError as e:
            return RPC_ERROR,e.value
        except Exception as e:
            traceback.print_exc()
            return RPC_ERROR,

    def rpc_modify_file(self, client_id, owner_id, fileID, data_file, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN(),
        try:
            file_manager.modify_datafile(fileID, client_id, owner_id, data_file)
            return RPC_OK, True
        except PermissionDeniedError, e:
            print "Unexpected error read_metafile: %s", e.value
            return RPC_ERROR,e.value
        except FileNotFoundError, e:
            print "Unexpected error read_metafile"
            return RPC_ERROR,"File not found"
        except Exception as e:
            traceback.print_exc()
            return RPC_ERROR,

    def rpc_remove_file(self, client_id, fileID, token):
        if not self.check_token(client_id, token): return RPC_WRONG_TOKEN,
        if file_manager.delete_file(fileID, client_id):  #TODO
            return RPC_OK, True
        return RPC_ERROR,

    def rpc_get_auth_counter(self, client_id):
        return RPC_OK, self.auth_manager.get_auth_counter(client_id)
