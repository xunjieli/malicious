class MyFuncs:
    def set_public_key(self, userid, key):
        with open(userid + '.pkey', 'w+') as f:
                f.write(key)
        return True
    def get_public_key(self, userid):
        with open(userid + '.pkey', 'r+') as f:
                return f.read()
