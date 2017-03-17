from . import encoding

import os
import hashlib
import binascii
import struct

hLen = 64
k = 2048 // 8 # bitsize

class EncodingError(Exception): pass
class DecodingError(Exception): pass
class MaskingError(Exception): pass


def MGF(Z, l):
    # Mask Generation Function
    if l > (1 << 32) * hLen:
        raise MaskingError("Mask too long")
    T = b""
    for i in range((l // hLen)+1):
        T += hashlib.sha512(Z + encoding.I2OSP(i, 4)).digest()
    return T[:l]

def strxor(s1, s2):
    return b''.join(struct.pack("B", a ^ b) for a,b in zip(s1, s2))

def OAEP_encode(M, emLen, P = "Azeroth"):
    # Optimal Asymmetric Encryption Padding
    M = b"".join([struct.pack("B",ord(x)) for x in M])
    if len(P) > ((1 << 61) - 1):
        raise EncodingError("Label too long")
    if len(M) > emLen - 2 * hLen - 1:
        raise EncodingError("Message too long")
    PS = b"\x00" * (emLen - len(M) - 2 * hLen - 1)
    pHash = hashlib.sha512(P.encode()).digest()
    if len(pHash) != hLen:
        raise EncodingError("Hashing failed")
    DB = pHash + PS + b"\x01" + M
    seed = os.urandom(hLen)
    dbMask = MGF(seed, emLen - hLen)
    maskedDB = strxor(DB, dbMask)
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = strxor(seed, seedMask)
    EM = maskedSeed + maskedDB
    if len(EM) != emLen:
        raise EncodingError("Output size constraint failed")
    return EM

def OAEP_decode(EM, P = "Azeroth"):
    # Optimal Asymmetric Encryption Padding
    if len(P) > ((1 << 61) - 1):
        raise DecodingError("Label too long")
    if len(EM) < 2 * hLen + 1:
        raise DecodingError("Encoded message too short")
    maskedSeed = EM[:hLen]
    maskedDB = EM[hLen:]
    seedMask = MGF(maskedDB, hLen)
    seed = strxor(maskedSeed, seedMask)
    dbMask = MGF(seed, len(EM) - hLen)
    DB = strxor(maskedDB, dbMask)
    pHash = hashlib.sha512(P.encode()).digest()
    pHashp = DB[:hLen]
    PS = b""
    for i in range(len(pHashp),len(DB)):
        if DB[i:i+1] == b"\x00":
            PS += DB[i:i+1]
        elif DB[i:i+1] == b"\x01":
            M = DB[i+1:]
            break
        else:
            raise DecodingError("Missing seperator")
    if pHashp != pHash:
        raise DecodingError("Hashes do not match")
    M = "".join([chr(x) for x in M])
    return M


def encrypt(key, M, P = "Azeroth"):
    n = encoding.b64_to_int(key)
    EM = OAEP_encode(M, k - 1, P = P)
    m = encoding.OS2IP(EM)
    e = 65537
    c = pow(m, e, n)
    return encoding.int_to_b64(c)

def decrypt(public_key, private_key, message, P = "Azeroth"):
    n = encoding.b64_to_int(public_key)
    d = encoding.b64_to_int(private_key)
    c = encoding.b64_to_int(message)
    m = pow(c, d, n)
    EM = encoding.I2OSP(m, k - 1)
    M = OAEP_decode(EM, P = P)
    return M