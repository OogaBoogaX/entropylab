#
# (c) Copyright 2023 by Coinkite Inc. This file is in the public domain.
#
# - helpers and basics
#
import zlib
from base64 import b32encode, b32decode

def version_to_chars(v):
    # return number of **chars** that fit into indicated version QR
    # - assumes L for ECC
    # - assumes alnum encoding
    import pyqrcode

    assert 1 <= v <= 40
    ecc = "L"
    encoding = 2        # alnum

    return pyqrcode.tables.data_capacity[v][ecc][encoding]

def int2base36(n):
    # convert an integer to two digits of base 36 string. 00 thu ZZ
    # converse is just int(s, base=36)
    assert 0 <= n <= 1295

    tostr = lambda x: chr(48+x) if x < 10 else chr(65+x-10)

    a, b = divmod(n, 36)

    return tostr(a) + tostr(b)

def encode_data(raw, encoding=None):
    # return new encoding (if we upgraded) and the
    # characters after encoding (a string)
    # - default is Zlib or if compression doesn't help, base32
    # - returned data can be split, but must be done modX where X provided

    if encoding == 'H':
        # Hex mode is easy.
        return encoding, raw.hex().upper(), 2

    if not encoding or encoding == 'Z':
        # Trial compression, but skip if it embiggens the data
        z = zlib.compressobj(wbits=-10)
        cmp = z.compress(raw)
        cmp += z.flush()
        if len(cmp) >= len(raw):
            encoding = '2'
        else:
            encoding = 'Z'
            raw = cmp

    # Default: base32 encoding, no padding bytes
    data = b32encode(raw).decode('ascii').rstrip('=')

    return encoding, data, 8

def decode_data(parts, encoding):
    # give back the bytes after decoding
    # - already in order
    # - keeps the parts separate here to validate correct split from encoder
    if encoding == 'H':
        return b''.join(bytes.fromhex(p) for p in parts)

    # base32 decode, but insert padding for API
    rv = b''
    for p in parts:
        padding = (8 - (len(p) % 8)) % 8
        rv += b32decode(p + (padding*'='))

    if encoding == 'Z':
        # decompress
        z = zlib.decompressobj(wbits=-10)
        rv = z.decompress(rv)
        rv += z.flush()

    return rv
        

# EOF
