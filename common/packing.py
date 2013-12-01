from struct import pack, unpack

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
