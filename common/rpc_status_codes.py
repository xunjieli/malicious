OK = 1
WRONG_TOKEN = 2
ERROR = 3

class RPC_STATUS:
    def __init___(self, code, error_str):
        self.code = code
        self.error_str = error_str

class RPC_OK(RPC_STATUS):
    def __init__(self, error_str=None):
        super(RPC_OK, self).__init__(OK, error_str)

class RPC_ERROR(RPC_STATUS):
    def __init__(self, error_str=None):
        super(RPC_ERROR, self).__init__(ERROR, error_str)

class RPC_WRONG_TOKEN(RPC_STATUS):
    def __init__(self, error_str=None):
        super(RPC_WRONG_TOKEN, self).__init__(WRONG_TOKEN, error_str)

