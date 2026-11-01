# Independent PSBT QR corpus

Reference: [SeedSigner](https://github.com/SeedSigner/SeedSigner), stable revision
`e0a80d4b33b8eb7fb1e9fd14a27b7cd11c7d2cd6`. Application license MIT;
vendored Foundation Devices UR transport BSD-2-Clause-Patent. License notices
are alongside this file. Protocol: BCR-2024-001 / BCR-2020-005.

Public input PSBTs come from `test/fixtures/psbt/`; their decoded byte hashes
and lengths are recorded per case in `manifest.json`. Static base64/hex cases
expect the original bytes. UR cases expect **exact reference serializer
bytes**, not merely an equivalent transaction: SeedSigner/embit may reorder
PSBT maps. Transaction fields are independently recorded from embit and checked
through the application's rust-bitcoin parser after transport.

The corpus covers all three public input fixtures at LOW, MEDIUM and HIGH
reference densities: systematic frames, fountain-only frames after skipping
all initial systematic frames, reversed fountain frames, deterministic
systematic-frame loss, and duplicates. Fountain-only emission stops when the
independent reference decoder succeeds, never based on EntropyLab's answers.

## Regeneration (development only)

Use a local checkout of the exact revision and a Python 3.12 environment with
SeedSigner's `embit`, `urtypes`, `qrcode` and `Pillow` dependencies. Nothing is
downloaded by these commands. The generator rejects a different reference
revision. Run from the repository root:

```sh
SEEDSIGNER_PATH=/tmp/seedprobe /tmp/pyvenv/bin/python scripts/psbt-qr-generate.py
SEEDSIGNER_PATH=/tmp/seedprobe /tmp/pyvenv/bin/python scripts/seed-signer-diff.py
node --test test/psbt-qr-fixtures.test.mjs test/psbt-qr-interop.test.mjs
```

For a reproducibility comparison, pass a second output directory as the
argument to the generator and compare every payload plus `manifest.json`.
The offline Node suite uses committed files only: no Python, local reference
checkout, network access, or generation step is required by `npm test`.

## Known malformed reference emission

The pinned reference's `helpers/ur2/crc32.py:crc32n` encodes a CRC using its
minimal integer byte width instead of exactly four bytes. For the Taproot
fixture at LOW density, systematic part 2 has a three-byte checksum. Its
Bytewords payload is 54 minimal characters instead of 56. This is **invalid
protocol data**: the raw systematic case and the isolated malformed frame
expect `bad-part`, not successful receipt. No checksum validation is relaxed
and no reference frame is repaired by the receiver.

Fountain-only cases model deterministic loss of malformed reference CRC
frames, then recover the exact reference PSBT bytes using valid frames.
The camera panel stops on `bad-part`; do not claim that it tolerates this raw
malformed LOW-density animation. Use a valid reference density/sequence.
Physical SeedSigner-display/camera/appliance qualification remains untested.

The bidirectional development tool also sends EntropyLab's actual static or
animated output, plus animated-output regressions for every fixture, through
SeedSigner's `DecodeQR.get_data_psbt()` and requires exact original bytes.
