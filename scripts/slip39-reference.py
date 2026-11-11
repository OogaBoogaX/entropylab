#!/usr/bin/env python3
"""Regenerate test/fixtures/slip39/reference-sets.json.

Usage: python3 -I scripts/slip39-reference.py <python-shamir-mnemonic checkout>

python-shamir-mnemonic is the SLIP-0039 reference implementation (MIT). The
checkout must be v0.3.0: every file this script imports is SHA-256 pinned
below, and any other content is refused before it is imported. It needs only
Python's standard library and never imports application code. No network is
performed.

The reference splits every set. Its random source (shamir.RANDOM_BYTES) is
replaced by a deterministic stream, so the fixture records, by construction,
every random value each split drew: the identifier, the shares drawn at
random at x = 0..T-3, and the digest share's random part R, at the group
level and in each group. test/slip39-reference.test.mjs checks that
src/js/slip39.js rebuilds exactly those values from the shares, combines each
set to its master secret, and reports the planted repeats and patterns.

Streams: block k of stream L is SHA-256(L || uint32_be(k)); draws take bytes
in order. Some sets replace single draws with plain patterns (all zero, one
byte repeated, a counter), reuse another set's stream, or return the same
buffer on every draw, to model a generator that restarts from the same
state or returns trivial output.
"""
import hashlib
import json
from pathlib import Path
import secrets
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "test/fixtures/slip39/reference-sets.json"
VERSION = "0.3.0"
COMMIT = "08bbb74bdcb58c918981836cb3ccf401e57ecfb4"
SOURCES = {
    "LICENSE": "332f92f7f90a1c957b473b902a5daf39ad5eb179d8828e0304b4c40faa0123c0",
    "shamir_mnemonic/__init__.py": "efc4925a7f1c88c9d65d9788f9539a0aa11a4d86decc8b9e8240898bddfcb648",
    "shamir_mnemonic/cipher.py": "193c0bc5d90a28fd2f139e4d17e5a6e072666765d72eb527198ec71fb128ffdc",
    "shamir_mnemonic/constants.py": "434696830041652cc08d6f837b763d7333aec149c1b2fd976aa2bd20350a147b",
    "shamir_mnemonic/rs1024.py": "7527b6ab5b0de8ef90697699f24c4bd615dbc77ec988e90590bfcf80146e8391",
    "shamir_mnemonic/shamir.py": "a7a3db954f0a3638f3e98574c2da2e8b8af1338ed3bc33aef937afbfffce465f",
    "shamir_mnemonic/share.py": "3ee6f46415ba34dd8c1bc5f92601b17151854a35425e098d1de857ca714205c5",
    "shamir_mnemonic/utils.py": "9bf6d2c71b11788ac1adabe156e71e43365f8c17f99cadf19aa8e78f5a066ee4",
    "shamir_mnemonic/wordlist.py": "f246d5c397155a377cb7344f6a3986e197210469cd575c83fbbfae2bcfe09975",
    # The same file as the specification's wordlist.txt.
    "shamir_mnemonic/wordlist.txt": "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3",
}

if len(sys.argv) != 2:
    sys.exit(__doc__)
REFERENCE = Path(sys.argv[1]).resolve()
for name, digest in SOURCES.items():
    actual = hashlib.sha256((REFERENCE / name).read_bytes()).hexdigest()
    if actual != digest:
        sys.exit(f"{name}: SHA-256 {actual} is not v{VERSION}'s {digest}")
sys.path.insert(0, str(REFERENCE))

import shamir_mnemonic  # noqa: E402
from shamir_mnemonic import shamir  # noqa: E402


class Stream:
    def __init__(self, label: str):
        self.label = label.encode()
        self.buffer = b""
        self.block = 0

    def take(self, n: int) -> bytes:
        while len(self.buffer) < n:
            self.buffer += hashlib.sha256(self.label + self.block.to_bytes(4, "big")).digest()
            self.block += 1
        out, self.buffer = self.buffer[:n], self.buffer[n:]
        return out


class Repeating:
    """Every draw returns the start of the same fixed buffer."""

    def __init__(self, label: str):
        self.source = hashlib.sha256(label.encode()).digest() * 4

    def take(self, n: int) -> bytes:
        return self.source[:n]


def secret(label: str, n: int) -> bytes:
    return hashlib.sha512(("entropylab slip39 fixture master secret " + label).encode()).digest()[:n]


def generate(spec: dict) -> dict:
    stream = spec["stream"]
    overrides = spec.get("overrides", {})
    master_secret = spec["masterSecret"]
    draws = []
    context = {"level": None, "group": None, "share": 0}
    calls = {"split": 0}
    original_split = shamir._split_secret

    def labelled_split(threshold, share_count, shared_secret):
        # split_ems calls _split_secret once for the group level, then once per group.
        call = calls["split"]
        calls["split"] += 1
        context.update(level="group" if call == 0 else "member", group=None if call == 0 else call - 1, share=0)
        return original_split(threshold, share_count, shared_secret)

    def random_bytes(n: int) -> bytes:
        if context["level"] is None:
            label = {"kind": "identifier"}
        elif n == len(master_secret):
            label = {"kind": "share", "level": context["level"], "x": context["share"]}
            context["share"] += 1
        else:
            label = {"kind": "digest-random", "level": context["level"], "x": 254}
        if context["group"] is not None:
            label["group"] = context["group"]
        key = "{}:{}:{}".format(label.get("level", "-"), label.get("group", "-"), label.get("x", "id"))
        value = stream.take(n)
        if key in overrides:
            value = bytes.fromhex(overrides[key])
            assert len(value) == n, key
        draws.append({**label, "hex": value.hex()})
        return value

    shamir.RANDOM_BYTES = random_bytes
    shamir._split_secret = labelled_split
    try:
        identifier = shamir._random_identifier()
        ems = shamir.EncryptedMasterSecret.from_master_secret(
            master_secret, spec["passphrase"].encode(), identifier, spec["extendable"], spec["iterationExponent"]
        )
        grouped = shamir.split_ems(spec["groupThreshold"], spec["groups"], ems)
    finally:
        shamir.RANDOM_BYTES = secrets.token_bytes
        shamir._split_secret = original_split
    mnemonics = [[share.mnemonic() for share in group] for group in grouped]
    # The reference's own round trip, on the first threshold subset of each group.
    pick = []
    for index, (threshold, _count) in enumerate(spec["groups"][: spec["groupThreshold"]]):
        pick += mnemonics[index][:threshold]
    assert shamir_mnemonic.combine_mnemonics(pick, spec["passphrase"].encode()) == master_secret
    return {
        "name": spec["name"],
        "masterSecret": master_secret.hex(),
        "passphrase": spec["passphrase"],
        "iterationExponent": spec["iterationExponent"],
        "extendable": spec["extendable"],
        "groupThreshold": spec["groupThreshold"],
        "groups": [list(group) for group in spec["groups"]],
        "identifier": identifier,
        "encryptedMasterSecret": ems.ciphertext.hex(),
        "draws": draws,
        "mnemonics": mnemonics,
    }


def zeros(n):
    return "00" * n


def repeated(byte, n):
    return "{:02x}".format(byte) * n


def counter(start, n):
    return bytes((start + i) & 0xFF for i in range(n)).hex()


def one_level(name, n, threshold, count, stream, **extra):
    return dict(name=name, masterSecret=secret(name, n), passphrase="", iterationExponent=1, extendable=True, groupThreshold=1, groups=[(threshold, count)], stream=stream, **extra)


def two_level(name, stream, **extra):
    return dict(name=name, masterSecret=secret(name, 16), passphrase="", iterationExponent=1, extendable=True, groupThreshold=2, groups=[(2, 3), (3, 4)], stream=stream, **extra)


SPECS = [
    # Combine coverage: lengths, thresholds, levels, flags, passphrases.
    dict(name="1-of-1, 128-bit", masterSecret=secret("a", 16), passphrase="", iterationExponent=0, extendable=True, groupThreshold=1, groups=[(1, 1)], stream=Stream("combine a")),
    dict(name="2-of-3, 128-bit, passphrase", masterSecret=secret("b", 16), passphrase="throwaway", iterationExponent=0, extendable=True, groupThreshold=1, groups=[(2, 3)], stream=Stream("combine b")),
    dict(name="3-of-5, 256-bit, e=1", masterSecret=secret("c", 32), passphrase="", iterationExponent=1, extendable=True, groupThreshold=1, groups=[(3, 5)], stream=Stream("combine c")),
    dict(name="5-of-8, 128-bit, not extendable", masterSecret=secret("d", 16), passphrase="", iterationExponent=0, extendable=False, groupThreshold=1, groups=[(5, 8)], stream=Stream("combine d")),
    dict(name="2 of 3 groups, 128-bit, not extendable", masterSecret=secret("e", 16), passphrase="Pass phrase 1", iterationExponent=0, extendable=False, groupThreshold=2, groups=[(2, 3), (3, 5), (1, 1)], stream=Stream("combine e")),
    dict(name="3 of 4 groups, 256-bit", masterSecret=secret("f", 32), passphrase="", iterationExponent=0, extendable=True, groupThreshold=3, groups=[(1, 1), (2, 2), (3, 4), (2, 5)], stream=Stream("combine f")),
    dict(name="2-of-2, 192-bit, e=2", masterSecret=secret("g", 24), passphrase="", iterationExponent=2, extendable=True, groupThreshold=1, groups=[(2, 2)], stream=Stream("combine g")),
    dict(name="4 of 5 groups, 160-bit", masterSecret=secret("h", 20), passphrase="", iterationExponent=0, extendable=True, groupThreshold=4, groups=[(2, 3), (1, 1), (4, 4), (2, 2), (3, 3)], stream=Stream("combine h")),
    # The randomness test: two throwaway wallets per comparison.
    one_level("run 1", 16, 3, 5, Stream("device run 1")),
    one_level("run 2", 16, 3, 5, Stream("device run 2")),
    # A generator that starts from the same state after a power cycle: a
    # different wallet, but every share-splitting draw repeats run 1's.
    one_level("run 1 restarted", 16, 3, 5, Stream("device run 1")),
    # The same restarted stream, read by a 2-of-3 split: its R is the start
    # of run 1's random share.
    one_level("run 1 restarted, 2-of-3", 16, 2, 3, Stream("device run 1")),
    one_level("one buffer every call", 16, 3, 5, Repeating("one buffer every call")),
    # Trivial output in single draws.
    one_level("zero digest random", 16, 2, 3, Stream("pattern zero"), overrides={"member:0:254": zeros(12)}),
    one_level("repeated byte share", 32, 3, 5, Stream("pattern repeated"), overrides={"member:0:0": repeated(0xA7, 32)}),
    one_level("counter digest random", 16, 3, 5, Stream("pattern counter"), overrides={"member:0:254": counter(0x10, 12)}),
    two_level("groups run 1", Stream("groups run 1")),
    two_level("groups run 2", Stream("groups run 2")),
]


def main():
    sets = [generate(spec) for spec in SPECS]
    # A third two-level wallet whose group-level R repeats run 1's.
    group_r = next(d["hex"] for d in sets[-2]["draws"] if d.get("level") == "group" and d["kind"] == "digest-random")
    sets.append(generate(two_level("groups run 3, reusing run 1's group-level R", Stream("groups run 3"), overrides={"group:-:254": group_r})))
    out = {
        "source": {"library": "python-shamir-mnemonic (the SLIP-0039 reference implementation)", "version": VERSION, "commit": COMMIT, "license": "MIT", "generator": "scripts/slip39-reference.py"},
        "randomSource": "Block k of stream L is SHA-256(L || uint32_be(k)), bytes drawn in order; 'one buffer every call' returns the start of SHA-256(L) x 4 on every draw; overrides replace single draws.",
        "sets": sets,
    }
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(sets)} sets")


main()
