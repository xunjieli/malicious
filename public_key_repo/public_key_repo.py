from public_key_repo_func import RepoFuncs
from ..common.rpclib import *

"""
A trusted public key distribution server.
"""
server = RepoFuncs()
RpcServer().run_sockpath_fork(5000, server)