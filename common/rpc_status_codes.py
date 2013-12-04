OK = 1
WRONG_TOKEN = 2
ERROR = 3

class RPC_STATUS:
    def __init__(self, code, error_str):
        self.code = code
        self.error_str = error_str

class RPC_OK(RPC_STATUS):
    def __init__(self, error_str=None):
        RPC_STATUS.__init__(self, OK, error_str)

class RPC_ERROR(RPC_STATUS):
    def __init__(self, error_str=None):
        RPC_STATUS.__init__(self, ERROR, error_str)

class RPC_WRONG_TOKEN(RPC_STATUS):
    def __init__(self, error_str=None):
        RPC_STATUS.__init__(self, WRONG_TOKEN, error_str)
