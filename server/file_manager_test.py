from file_manager import *
import unittest

class TestFileManager(unittest.TestCase):

    def setUp(self):
        pass

    def test_create_file(self):
        metadata = 'this is metadata'
        datafile = 'this is datafile'
        try:
            create_file(0, 'testuser', metadata, datafile)
            self.assertTrue(True)
        except Exception as e:
            print e
            self.assertTrue(False)
    '''
    def test_pack_data_unpack_data(self):

        a, b, c = [Random.new().read(i) for i in [100, 400, 300]]
        packed = pack_data(a, b, c)
        self.assertEqual([a, b, c], unpack_data(packed, 3))
        self.assertEqual([a, b, c], unpack_data(packed))
        try:
            unpack_data(packed, 2)
            self.assertFalse(True)
        except UnpackException as e:
            pass
    '''

if __name__ == '__main__':
    unittest.main()
