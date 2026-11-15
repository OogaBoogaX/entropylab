#!/usr/bin/env python3
"""Regenerate offline BBQr vectors: python3 scripts/psbt-bbqr-reference.py.

Uses only Python's standard library and the checked-in, hash-pinned Coinkite
encode_data/int2base36/join_qrs implementation; never imports application code.
Framing uses explicit encoded-character widths (not QR image generation), so
Coinkite's optional pyqrcode package is not needed. No network is performed.
"""
import base64
import hashlib
import json
from pathlib import Path
import sys
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'test/fixtures/psbt-qr/bbqr'
COMMIT = '8dc7ef07d0d520763cc0001a885ca8d29ac8719a'
SOURCES = {
    'utils.py': '98ee24c30254f1e87080984a73a105b893b2aa6b1587a979d812c49cf34881e9',
    'join.py': '6a9c98770633ee4b52b31e26fca38bf286ba3f0e12b71157fc4a4916c1670a1d',
    'consts.py': '600147b178c25ff8a8a133d05c9324770fd6f4c7de4ec43c16743df2c27b1f46',
    'LICENSE': '8d4e9b4aa336afd26a386bc2ad8c3da4f8ebb8f7e9685c09bdba6b4e75894dad',
}
# Published BIP-370 minimal PSBT v2; also retained in test/psbt-wasm.test.mjs.
V2 = 'cHNidP8BAgQCAAAAAQQBAQEFAQIB+wQCAAAAAAEOIAsK2SFBnByHGXNdctxzn56p4GONH+TB7vD5lECEgV/IAQ8EAAAAAAABAwgACK8vAAAAAAEEFgAUxDD2TEdW2jENvRoIVXLvKZkmJywAAQMIi73rCwAAAAABBBYAFE3Rk6yWSlasG54cyoRU/i9HT4UTAA=='


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def record(path, data):
    path.write_bytes(data)
    return {'file': path.name, 'bytes': len(data), 'sha256': sha256(data)}


def main():
    for name, digest in SOURCES.items():
        actual = sha256((OUT / 'reference' / name).read_bytes())
        if actual != digest:
            raise SystemExit(f'pinned reference source changed: {name}')
    sys.path.insert(0, str(OUT))
    from reference.utils import encode_data, int2base36
    from reference.join import join_qrs

    record(OUT / 'bip370-minimal.b64', (V2 + '\n').encode('ascii'))
    inputs = [
        ('p2wpkh-1in-2out', ROOT / 'test/fixtures/psbt/p2wpkh-1in-2out.b64', 'PSBT v0, existing public fixture'),
        ('multisig-2of3-p2wsh', ROOT / 'test/fixtures/psbt/multisig-2of3-p2wsh.b64', 'PSBT v0 multisig, existing public fixture'),
        ('mixed-many-inputs', ROOT / 'test/fixtures/psbt/mixed-many-inputs.b64', 'PSBT v0, existing public fixture; output crosses the 1024-byte DEFLATE window'),
        ('bip370-minimal', OUT / 'bip370-minimal.b64', 'https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#test-vectors'),
    ]
    manifest = {
        'reference': {
            'repository': 'https://github.com/coinkite/BBQr', 'revision': COMMIT,
            'specification': f'https://github.com/coinkite/BBQr/blob/{COMMIT}/BBQr.md',
            'license': 'Public domain; upstream UNLICENSE.md retained as reference/LICENSE',
            'sources': [{'file': f'reference/{name}', 'upstream': 'UNLICENSE.md' if name == 'LICENSE' else f'python/bbqr/{name}', 'sha256': digest} for name, digest in SOURCES.items()],
            'apis': ['encode_data', 'int2base36', 'join_qrs'],
            'framing': '8-character B$ header; explicit character widths divisible by upstream split_mod; no pyqrcode dependency',
            'compression': 'Coinkite encode_data uses zlib.compressobj(wbits=-10), default level; compress entire message before splitting',
        },
        'generator': {'file': 'scripts/psbt-bbqr-reference.py', 'sha256': sha256(Path(__file__).read_bytes()), 'zlib': zlib.ZLIB_RUNTIME_VERSION},
        'limitations': ['BBQr has no whole-message checksum or session identity: same-header same-length cross-transfer mixing cannot always be detected. PSBT magic is not full PSBT validation or sender authentication.'],
        'fixtures': [],
    }
    for name, path, provenance in inputs:
        source_file = path.read_bytes()
        raw = base64.b64decode(source_file, validate=False)
        source = {'path': str(path.relative_to(ROOT)), 'fileSha256': sha256(source_file), 'bytes': len(raw), 'sha256': sha256(raw), 'provenance': provenance}
        for encoding in 'H2Z':
            actual, encoded, modulo = encode_data(raw, encoding)
            if actual != encoding:
                raise SystemExit(f'{name}: reference fell back from {encoding} to {actual}')
            for mode, width in [('single', len(encoded)), ('multipart', 128)]:
                if mode == 'multipart' and width % modulo:
                    raise SystemExit('invalid reference split width')
                count = (len(encoded) + width - 1) // width
                parts = [f'B${encoding}P{int2base36(count)}{int2base36(index)}{encoded[offset:offset + width]}' for index, offset in enumerate(range(0, len(encoded), width))]
                file_type, recovered = join_qrs(parts[::-1] + parts[:1])
                if file_type != 'P' or recovered != raw:
                    raise SystemExit('reference recovery differs from source')
                entry = record(OUT / f'{name}-{encoding.lower()}-{mode}.txt', ('\n'.join(parts) + '\n').encode('ascii'))
                entry.update({'encoding': encoding, 'mode': mode, 'parts': count, 'source': source})
                manifest['fixtures'].append(entry)

    raw = base64.b64decode((ROOT / 'test/fixtures/psbt/p2wpkh-1in-2out.b64').read_bytes())
    compressor = zlib.compressobj(wbits=-10)
    compressed = compressor.compress(raw) + compressor.flush()
    bomb_raw = b'psbt\xff' + bytes(1048576)
    compressor = zlib.compressobj(wbits=-10)
    bomb = compressor.compress(bomb_raw) + compressor.flush()
    compressor = zlib.compressobj(wbits=26)
    gzip = compressor.compress(raw) + compressor.flush()
    cases = [
        ('reserved-block-type', b'\x07', 'bad-part'),
        ('truncated-stream', compressed[:-1], 'bad-part'),
        ('trailing-byte', compressed + b'\x00', 'bad-part'),
        ('concatenated-streams', compressed + compressed, 'bad-part'),
        ('zlib-wrapper', zlib.compress(raw), 'bad-part'),
        ('gzip-wrapper', gzip, 'bad-part'),
        ('empty-inflated-payload', b'\x03\x00', 'not-psbt'),
        ('output-over-default-budget', bomb, 'too-large'),
    ]
    rejects = []
    for name, data, status in cases:
        _, encoded, _ = encode_data(data, '2')
        rejects.append({'name': name, 'frames': ['B$ZP0100' + encoded], 'status': status, 'compressedBytes': len(data), 'compressedSha256': sha256(data)})
    rejection_record = record(OUT / 'compressed-rejections.json', (json.dumps(rejects, indent=2) + '\n').encode())
    manifest['rejections'] = rejection_record
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    main()
