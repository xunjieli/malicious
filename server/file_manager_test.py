from file_manager import *
import unittest

# test data
userid_a = "testuserA"
userid_b = "testuserB"
fileID_a = 1
fileID_b = 2

class TestFileManager(unittest.TestCase):

    def setUp(self):
        # cleaning up if necessary
        if file_exist(fileID_a, userid_a):
            delete_file(fileID_a, userid_a)
        if file_exist(fileID_b, userid_b):
            delete_file(fileID_b, userid_b)

    def test_create_file(self):
        metadata = 'this is metadata'
        datafile = 'this is datafile'
        try:
            create_file(fileID_a, userid_a, metadata, datafile)
            self.assertTrue(True)
        except Exception as e:
            print e
            self.assertTrue(False)

if __name__ == '__main__':
    unittest.main()
