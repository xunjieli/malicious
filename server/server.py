from server_func import ServerFuncs
from server_db import ServerDB
from ..common.rpclib import *
from ..common.auth import ServerAuthenticationManager

class PublicKeyRepoStub:
    def __init__(self, host, port):
        self.host = host
        self.port = port
    def get_public_key(self, user_id):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('get_public_key', user_id)
        rpc.close()
        return result
    def get_verify_key(self, user_id):
        rpc = client_connect(self.host, self.port)
        result = rpc.call('get_verification_key', user_id)
        rpc.close()
        return result

public_key_service = PublicKeyRepoStub('localhost', 5000)
server_db = ServerDB('server.db')
auth_manager = ServerAuthenticationManager(public_key_service, server_db)
server = ServerFuncs(auth_manager)
RpcServer().run_sockpath_fork(8000, server)
