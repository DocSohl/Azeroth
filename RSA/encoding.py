import base64
import struct

def pack_bigint(i):
    b = bytearray()
    while i:
        b.append(i & 0xFF)
        i >>= 8
    return b

def unpack_bigint(b):
    b = bytearray(b) # in case you're passing in a bytes/str
    return sum((1 << (bi*8)) * bb for (bi, bb) in enumerate(b))

def I2OSP(x, l):
    if x >= pow(256, l):
        raise ValueError("Integer too large")
    digits = b""
    while x:
        digits += struct.pack("B", x % 256)
        x //= 256
    for i in range(l - len(digits)):
        digits += struct.pack("B",0)
    return digits[::-1]

def OS2IP(X):
    X = X[::-1]
    x = 0
    for i in range(len(X)):
        x += ord(X[i:i+1]) * pow(256, i)
    return x

def b64_to_int(b):
    return unpack_bigint(base64.b64decode(b))

def int_to_b64(num):
    return base64.b64encode(pack_bigint(num)).decode('utf-8')

