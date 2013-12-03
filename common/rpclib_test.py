from rpclib import *
import unittest
class RpclibTest(unittest.TestCase):
    def testCall(self):
        conn = client_connect('localhost', 5000)
        self.assertEqual(sum((1,2,3,4,5)), conn.call('sum', (1,2,3,4,5)))
        conn.close()

if __name__ == '__main__':
    unittest.main()
