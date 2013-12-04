from ..common.rpclib import *
from ..common.crypto import *
class PublicKeyRepoStub:
    def __init__(self, host, port):
        self.host = host
        self.port = port
    def get_public_key(self, user_id):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('get_public_key', user_id)
        rpc.close()
        return import_key(result)
    def get_verify_key(self, user_id):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('get_verification_key', user_id)
        rpc.close()
        return import_key(result)
    def set_public_key(self, user_id, key):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('set_public_key', user_id, export_key(key))
        rpc.close()
        return result
    def set_verify_key(self, user_id, key):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('set_verification_key', user_id, export_key(key))
        rpc.close()
        return result