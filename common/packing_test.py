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
        obj = (2, -3, True, None, 'some string', generate_symmetric_key(),
               ['embedded list', (2, 3, False, (None, ()))])
        packed = pack_object(obj)
        self.assertEqual(str, type(packed))
        unpacked = unpack_object(packed)
        self.assertEqual(obj, unpacked)

    def assertUnpackingError(self, originalObj, format):
        try:
            packed = pack_object(originalObj)
            unpacked = unpack_object(packed, format)
            self.assertFalse(True)
        except UnpackException as e:
            return

    def assertUnpackingCorrect(self, originalObj, format):
        packed = pack_object(originalObj)
        unpacked = unpack_object(packed, format)
        self.assertEqual(originalObj, unpacked)

    def test_unpack_object_formats(self):
        self.assertUnpackingCorrect(2, IntFormat())
        self.assertUnpackingCorrect('1', StrFormat())
        self.assertUnpackingError(2, StrFormat())
        self.assertUnpackingError(None, StrFormat())
        self.assertUnpackingCorrect([(2,'abc'), (-4, '')],
            ListFormat(TupleFormat(IntFormat(), StrFormat())))
        self.assertUnpackingError([(2, 'abc'), (-8, '')],
            ListFormat(StrFormat()))
        self.assertUnpackingCorrect([(2, 'abc'), (-8, '')],
            format_from_prototype([(0, '')]))
        self.assertUnpackingError([(2, 'abc'), (-8, '')],
            format_from_prototype([(0,)]))
        self.assertUnpackingError((1, 2), TupleFormat(StrFormat(), IntFormat()))
        self.assertUnpackingCorrect((1, 2), format_from_prototype((0,0)))
        self.assertUnpackingError((1, 3), TupleFormat(IntFormat(), IntFormat(), IntFormat()))
        self.assertUnpackingCorrect([1, 2, 'str'],
            ListFormat(AnyFormat(IntFormat(), StrFormat())))
        self.assertUnpackingError([[1, 'str']],
            ListFormat(AnyFormat(ListFormat(IntFormat()), ListFormat(StrFormat()))))
        self.assertUnpackingCorrect([[1, 'str']],
            ListFormat(ListFormat(AnyFormat(IntFormat(), StrFormat()))))

if __name__ == '__main__':
    unittest.main()
