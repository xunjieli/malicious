from rpclib import *
import unittest
from ..common import global_configs
class RpclibTest(unittest.TestCase):
    def testCall(self):
        conn = client_connect('localhost', global_configs.KEYREPO_PORT)
        self.assertEqual(sum((1,2,3,4,5)), conn.call('sum', (1,2,3,4,5)))
        conn.close()

if __name__ == '__main__':
    unittest.main()
