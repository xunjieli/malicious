from struct import pack, unpack
import base64

class UnpackException(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
    __repr__ = __str__

def pack_data(*data):
    """
    Pack a given list of strings into one string
    @param data: A list/tuple of any number of strings
    @return Encoded tuple as one string
    """
    n = len(data)
    lens = [len(x) for x in data]
    header = pack('<' + str(n + 1) + 'I', n, *lens)
    return header + ''.join(data)

def unpack_data(data, expected_len=None):
    n = unpack('<I', data[:4])[0]
    if expected_len is not None and expected_len != n:
        raise UnpackException('Packed data does not have the same number of entries')
    lens = unpack('<' + str(n) + 'I', data[4:4 + 4 * n])
    if any(x < 0 for x in lens) or sum(lens) != len(data) - (n+1)*4:
        raise UnpackException('Packed data does not have valid lengths: sum of ' + repr(lens) + " != " + str(len(data) - (n+1)*4))
    ptr = (n+1)*4
    result = []
    for l in lens:
        result.append(data[ptr: ptr+l])
        ptr += l
    return result

def pack_object(obj):
    obj_type = type(obj)
    if obj is None:
        flag = 1
        data = ''
    elif obj_type is str:
        flag = 2
        data = obj
    elif obj_type is int:
        flag = 3
        data = pack('<i', obj)
    elif obj_type is bool:
        flag = 4
        data = pack('B', 0xff if obj else 0)
    elif obj_type is tuple:
        flag = 5
        data = pack_data(*[pack_object(i) for i in obj])
    elif obj_type is list:
        flag = 6
        data = pack_data(*[pack_object(i) for i in obj])
    else:
        raise Exception('Cannot pack object of type ' + str(obj_type))
    return pack('B', flag) + data

def unpack_object(blob, format_spec=None):
    flag = unpack('B', blob[:1])[0]
    if flag == 1:
        result = None
    elif flag == 2:
        result = blob[1:]
    elif flag == 3:
        result = unpack('<i', blob[1:])[0]
    elif flag == 4:
        value = unpack('B', blob[1:])[0]
        if value == 0xff:
            result = True
        elif value == 0:
            result = False
        else:
            raise UnpackException("Invalid boolean value in unpack_object")
    elif flag == 5:
        blobs = unpack_data(blob[1:])
        result = tuple(unpack_object(blob) for blob in blobs)
    elif flag == 6:
        blobs = unpack_data(blob[1:])
        result = [unpack_object(blob) for blob in blobs]
    else:
        raise UnpackException("Invalid flag in unpack_object: " + str(flag))
    if format_spec is not None and not format_spec.match(result):
        raise UnpackException("Invalid format in unpack_object.")
    return result
class FormatSpec:
    def match(self, obj):
        pass

class WildcardFormat(FormatSpec):
    def match(self, obj):
        return True

class NoneFormat(FormatSpec):
    def match(self, obj):
        return obj is None

class IntFormat(FormatSpec):
    def match(self, obj):
        return type(obj) is int

class StrFormat(FormatSpec):
    def match(self, obj):
        return type(obj) is str

class BoolFormat(FormatSpec):
    def match(self, obj):
        return type(obj) is bool

class TupleFormat(FormatSpec):
    def __init__(self, *formats):
        self.formats = formats
    def match(self, obj):
        return type(obj) is tuple \
            and len(obj) == len(self.formats) \
            and all(self.formats[i].match(obj[i]) for i in range(len(obj)))

class ListFormat(FormatSpec):
    def __init__(self, child):
        self.child_format = child
    def match(self, obj):
        return type(obj) is list \
            and all(self.child_format.match(child) for child in obj)

class AnyFormat(FormatSpec):
    def __init__(self, *formats):
        self.formats = formats
    def match(self, obj):
        return any(f.match(obj) for f in self.formats)


def format_from_prototype(proto):
    t = type(proto)
    if proto is None:
        return NoneFormat()
    if t is int:
        return IntFormat()
    if t is str:
        return StrFormat()
    if t is bool:
        return BoolFormat()
    if t is tuple:
        formats = [format_from_prototype(child) for child in proto]
        return TupleFormat(*formats)
    if t is list:
        child = format_from_prototype(proto[0])
        return ListFormat(child)
    if isinstance(proto, FormatSpec):
        return proto
    raise Exception("Invalid type in format prototype")
