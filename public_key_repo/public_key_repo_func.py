class RepoFuncs:

    def rpc_set_public_key(self, userid, key):
        with open(userid + '.pkey', 'w+') as f:
                f.write(key)
        return True
    def rpc_get_public_key(self, userid):
        with open(userid + '.pkey', 'r+') as f:
                return f.read()

    def rpc_set_verification_key(self, userid, key):
        with open(userid + '.vkey', 'w+') as f:
                f.write(key)
        return True

    def rpc_get_verification_key(self, userid):
        with open(userid + '.vkey', 'r+') as f:
                return f.read()

