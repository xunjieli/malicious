from server_func import ServerFuncs
from server_db import ServerDB
from ..common.rpclib import *
from ..common.auth import ServerAuthenticationManager
from ..common import global_configs
from ..public_key_repo.public_key_repo_client import *

def run():
    public_key_service = PublicKeyRepoStub('localhost', global_configs.KEYREPO_RELAY_PORT)
    server_db = ServerDB('server.db')
    auth_manager = ServerAuthenticationManager(public_key_service, server_db)
    server = ServerFuncs(auth_manager)
    RpcServer().run_sockpath_fork(global_configs.FILESERVER_PORT, server)

if __name__ == '__main__':
    run()