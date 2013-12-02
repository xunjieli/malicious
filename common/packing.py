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
        raise UnpackException('Packed data does not have valid lengths')
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
    elif obj_type == str:
        flag = 2
        data = obj
    elif obj_type == int:
        flag = 3
        data = pack('<i', obj)
    elif obj_type == bool:
        flag = 4
        data = pack('B', 0xff if obj else 0)
    elif obj_type == tuple:
        flag = 5
        data = pack_data(*[pack_object(i) for i in obj])
    elif obj_type == list:
        flag = 6
        data = pack_data(*[pack_object(i) for i in obj])
    else:
        raise Exception('Cannot pack object of type ' + str(obj_type))
    return pack('B', flag) + data

def unpack_object(blob):
    flag = unpack('B', blob[:1])[0]
    if flag == 1:
        return None
    if flag == 2:
        return blob[1:]
    if flag == 3:
        return unpack('<i', blob[1:])[0]
    if flag == 4:
        return unpack('B', blob[1:])[0]
    if flag == 5:
        blobs = unpack_data(blob[1:])
        return tuple(unpack_object(blob) for blob in blobs)
    if flag == 6:
        blobs = unpack_data(blob[1:])
        return [unpack_object(blob) for blob in blobs]
    raise UnpackException("Invalid flag in unpack_obj: " + flag)
