#
# (c) Copyright 2023 by Coinkite Inc. This file is in the public domain.
#
#
# Constants and fixed values
#

# Standard defines a fixed-length header
HEADER_LEN = 8

# Human names
FILETYPE_NAMES = dict(P='PSBT', T='Transaction', J='JSON', C='CBOR', U='Unicode Text',
                        X='Executable', B='Binary',
                        R='KT Rx', S='KT Tx', E='KT PSBT')

# Codes for PSBT vs. TXN and so on
KNOWN_FILETYPES = set(FILETYPE_NAMES.keys())

# EOF
