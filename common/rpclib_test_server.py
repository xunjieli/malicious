from rpclib import *
class TestServer(object):
    def rpc_sum(self, t):
        return sum(t)

RpcServer().run_sockpath_fork(5000, TestServer())