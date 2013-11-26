class RepoFuncs:

    def set_public_key(self, userid, key):
        with open(userid + '.pkey', 'w+') as f:
                f.write(key)
        return True
    def get_public_key(self, userid):
        with open(userid + '.pkey', 'r+') as f:
                return f.read()

    def set_verification_key(self, userid, key):
        with open(userid + '.vkey', 'w+') as f:
                f.write(key)
        return True

    def get_verification_key(self, userid):
        with open(userid + '.vkey', 'r+') as f:
                return f.read()

