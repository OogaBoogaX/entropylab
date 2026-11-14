#!/usr/bin/env python3
# Reads the Bitcoin block-header attestations of an OpenTimestamps proof by
# walking its structure, so an attestation counts only where the format puts
# one, never inside an op argument or a calendar URI that happens to contain
# the same bytes. Standard library only: ots-upgrade.yml runs it next to the
# push token on a proof the untrusted client produced.
#
#   python3 scripts/ots-attestations.py PROOF
#     prints how many Bitcoin attestations PROOF carries.
#   python3 scripts/ots-attestations.py --preserves COMMITTED UPGRADED
#     exits 0 only if every attestation of COMMITTED, pending calendar ones
#     included (its exact op path from the file hash, its type and its
#     payload), is still in UPGRADED: an upgrade may add attestations, never
#     drop or swap one, so a pending proof cannot be traded for one that
#     points at other calendars. `ots upgrade` keeps the pending entries
#     beside the Bitcoin ones (the repository's upgrades 5f2d963 -> 27362f2
#     and a113791 -> ea05539 pass). Checking that an attestation names a real
#     block needs Bitcoin headers, which CI does not fetch; a fabricated
#     extra branch cannot remove the real ones, and `ots verify` rejects it.
#
# Either mode exits 1 on anything that is not a well-formed v1 proof with a
# SHA-256 file hash (wrong header, unknown op, the same op twice at one node,
# truncation, trailing bytes, oversized fields, nesting past 256).
import sys

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108")
BITCOIN = bytes.fromhex("0588960d73d71901")
UNARY_OPS = {0x02, 0x03, 0x08, 0x67, 0xF2, 0xF3}  # sha1 ripemd160 sha256 keccak256 reverse hexlify
BINARY_OPS = {0xF0, 0xF1}  # append prepend, each with one argument


class Malformed(Exception):
    pass


def attestations(data):
    """Every attestation as (op path from the file hash, type tag, payload)."""
    if len(data) < len(MAGIC) + 32 or not data.startswith(MAGIC):
        raise Malformed("not an OpenTimestamps v1 proof with a SHA-256 file hash")
    pos = len(MAGIC) + 32
    path, found = [], []

    def byte():
        nonlocal pos
        if pos >= len(data):
            raise Malformed("truncated")
        pos += 1
        return data[pos - 1]

    def varuint():
        value, shift = 0, 0
        while True:
            b = byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise Malformed("varuint too long")

    def varbytes(limit):
        nonlocal pos
        length = varuint()
        if length > limit or pos + length > len(data):
            raise Malformed("field out of range")
        pos += length
        return data[pos - length:pos]

    def item(tag, depth, seen):
        if tag == 0x00:
            attestation = bytes(byte() for _ in range(8))
            payload = varbytes(8192)
            found.append((tuple(path), attestation, payload))
            return
        if tag in BINARY_OPS:
            op = (tag, varbytes(4096))
        elif tag in UNARY_OPS:
            op = (tag, b"")
        else:
            raise Malformed("unknown op 0x%02x" % tag)
        # The OTS client keeps a node's ops in a map, so it never writes the
        # same op twice at one node; such a proof is refused here too.
        if op in seen:
            raise Malformed("the same op twice at one node")
        seen.add(op)
        path.append(op)
        timestamp(depth + 1)
        path.pop()

    def timestamp(depth):
        if depth > 256:
            raise Malformed("nested too deeply")
        seen = set()
        tag = byte()
        while tag == 0xFF:
            item(byte(), depth, seen)
            tag = byte()
        item(tag, depth, seen)

    timestamp(0)
    if pos != len(data):
        raise Malformed("trailing bytes")
    return found


def read(name):
    with open(name, "rb") as proof:
        return attestations(proof.read())


def bitcoin(entries):
    return [entry for entry in entries if entry[1] == BITCOIN]


if __name__ == "__main__":
    try:
        if sys.argv[1] == "--preserves":
            committed, upgraded = read(sys.argv[2]), read(sys.argv[3])
            missing = [entry for entry in committed if entry not in upgraded]
            if missing:
                print("ots-attestations: the upgraded proof drops or changes %d of the committed proof's %d attestation(s)" % (len(missing), len(committed)), file=sys.stderr)
                sys.exit(1)
            print(len(bitcoin(upgraded)))
        else:
            print(len(bitcoin(read(sys.argv[1]))))
    except (Malformed, OSError, IndexError) as error:
        print("ots-attestations: %s" % error, file=sys.stderr)
        sys.exit(1)
