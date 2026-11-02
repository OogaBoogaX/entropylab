#
# (c) Copyright 2023 by Coinkite Inc. This file is in the public domain.
#
# - joins QR codes
#
from .utils import decode_data
from .consts import HEADER_LEN, KNOWN_FILETYPES

def join_qrs(parts):
    # take a bunch of scanned data. 
    # - put into order, decode, return type code and raw data bytes
    # - lazy desktop code here
    hdr = set(p[0:6] for p in parts)
    assert len(hdr) == 1, 'conflicting/variable filetype/encodings/sizes'
    hdr = hdr.pop()

    assert hdr[0:2] == 'B$', 'fixed header not found, expected B$'
    encoding = hdr[2]
    file_type = hdr[3]
    num_parts = int(hdr[4:6], 36)

    assert num_parts >= 1, 'zero parts?'
    assert encoding in 'H2Z', f'bad encoding: {encoding}'

    # ok to have dups here, just need them all
    data = {}
    for p in parts:
        idx = int(p[6:8], 36)
        assert idx < num_parts, f'got part {idx} but only expecting {num_parts}'

        if idx in data:
            assert data[idx] == p[8:], f'dup part 0x{idx:02x} has wrong content'
        else:
            data[idx] = p[8:]

    missing = set(range(num_parts)) - set(data)
    assert not missing, f'parts missing: {missing!r}'

    parts = [data[i] for i in range(num_parts)]

    raw = decode_data(parts, encoding)

    # maybe: decode objects here... U=>text, C=>obj, J=>obj

    return file_type, raw

# EOF
