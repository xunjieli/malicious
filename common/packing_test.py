from packing import *
import unittest
from crypto import *

class PackingTest(unittest.TestCase):
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
    def test_pack_object_unpack_object(self):
        obj = (2, -3, False, None, 'some string', generate_symmetric_key(),
               ['embedded list', (2, 3, False, (None, ()))])
        packed = pack_object(obj)
        self.assertEqual(str, type(packed))
        unpacked = unpack_object(packed)
        self.assertEqual(obj, unpacked)

if __name__ == '__main__':
    unittest.main()
