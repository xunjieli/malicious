from public_key_repo_func import RepoFuncs
from ..common.rpclib import *
from ..common.global_configs import *

"""
A trusted public key distribution server.
"""
def run():
    server = RepoFuncs()
    RpcServer().run_sockpath_fork(KEYREPO_PORT, server)

if __name__ == '__main__':
    run()
