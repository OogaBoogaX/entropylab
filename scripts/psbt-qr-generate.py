#!/usr/bin/env python3
"""Offline, dev-only fixtures from pinned SeedSigner; never runs in npm test.

SEEDSIGNER_PATH defaults to /tmp/seedprobe. Run with a Python environment
containing SeedSigner's embit, urtypes and QR dependencies. Expected payloads
come from the reference serializer, never from EntropyLab's reader.
"""
import base64
import hashlib
import io
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import sys
import zlib

REVISION = "e0a80d4b33b8eb7fb1e9fd14a27b7cd11c7d2cd6"
ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get("SEEDSIGNER_PATH", "/tmp/seedprobe"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    revision = subprocess.check_output(["git", "-C", str(REFERENCE), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise SystemExit("SeedSigner revision does not match the pinned reference")
    subprocess.run(["git", "-C", str(REFERENCE), "diff", "--quiet", "HEAD"], check=True)
    sys.path.insert(0, str(REFERENCE / "src"))
    from embit import psbt
    from seedsigner.models.encode_qr import UrPsbtQrEncoder
    from seedsigner.models.settings import SettingsConstants
    from seedsigner.helpers.ur2.ur import UR
    from seedsigner.helpers.ur2.ur_encoder import UREncoder
    from seedsigner.helpers.ur2.ur_decoder import URDecoder
    from seedsigner.helpers.ur2.bytewords import decode_word
    from urtypes.crypto import PSBT as URPSBT

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "test/fixtures/psbt-qr"
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"reference": {"repository": "https://github.com/SeedSigner/SeedSigner", "revision": revision,
        "license": "MIT", "transport_license": "BSD-2-Clause-Patent", "specification": "BCR-2024-001",
        "generator": "scripts/psbt-qr-generate.py", "python": "3.12", "generated_date": "2026-11-01",
        "dependencies": {name: version(name) for name in ["embit", "urtypes", "qrcode", "Pillow"]}}, "fixtures": []}

    def valid_checksum(part):
        body = part.rsplit("/", 1)[1].lower()
        decoded = bytes(decode_word(body[i:i + 2], 2) for i in range(0, len(body), 2))
        return len(decoded) >= 4 and decoded[-4:] == zlib.crc32(decoded[:-4]).to_bytes(4, "big")

    for name in ["p2wpkh-1in-2out", "mixed-many-inputs", "p2tr-taproot"]:
        source_path = ROOT / f"test/fixtures/psbt/{name}.b64"
        original = base64.b64decode(source_path.read_text(), validate=False)
        parsed = psbt.PSBT.read_from(io.BytesIO(original), compress=psbt.CompressMode.KEEP_ALL)
        canonical = parsed.serialize()
        expected_tx = {"version": parsed.tx.version, "locktime": parsed.tx.locktime,
            "inputs": [{"txid": i.txid.hex(), "vout": i.vout, "sequence": i.sequence} for i in parsed.inputs],
            "outputs": [{"value": str(o.value), "scriptPubKey": o.script_pubkey.data.hex()} for o in parsed.outputs]}
        source = {"path": f"test/fixtures/psbt/{name}.b64", "bytes": len(original), "sha256": digest(original)}

        def save(kind, parts, status="complete", expected=canonical, density=None, note=None):
            filename = f"{name}-{kind}" + (f"-{density}" if density else "") + ".txt"
            data = ("\n".join(parts) + "\n").encode("ascii")
            (out / filename).write_bytes(data)
            entry = {"file": filename, "kind": kind, "density": density, "source": source,
                "bytes": len(data), "sha256": digest(data), "parts": len(parts), "direction": "reference-to-app",
                "expected": {"status": status}}
            if status == "complete":
                entry["expected"].update({"bytes": len(expected), "sha256": digest(expected), "transaction": expected_tx})
            if note:
                entry["note"] = note
            manifest["fixtures"].append(entry)

        save("base64", [base64.b64encode(original).decode()], expected=original)
        save("hex", [original.hex()], expected=original)
        save("single-ur", [UREncoder.encode(UR("crypto-psbt", URPSBT(canonical).to_cbor()))])
        for density, value in [("low", SettingsConstants.DENSITY__LOW), ("medium", SettingsConstants.DENSITY__MEDIUM), ("high", SettingsConstants.DENSITY__HIGH)]:
            encoder = UrPsbtQrEncoder(psbt=parsed, qr_density=value)
            count = encoder.seq_len()
            systematic = [encoder.next_part() for _ in range(count)]
            malformed = [p for p in systematic if not valid_checksum(p)]
            note = None
            if malformed:
                note = "Pinned SeedSigner emits a short Bytewords CRC on this stream; malformed frames must be refused, never repaired by the receiver."
            save("systematic", systematic, "bad-part" if malformed else "complete", density=density, note=note)
            for index, part in enumerate(malformed):
                save(f"invalid-reference-crc-{index}", [part], "bad-part", density=density, note=note)
            # Start after every systematic frame. Independently establish that
            # the emitted fountain-only stream completes in the reference.
            decoder = URDecoder()
            fountain = []
            for _ in range(16 * count + 100):
                part = encoder.next_part()
                if not valid_checksum(part):
                    continue  # deterministic transport loss, recorded below
                fountain.append(part)
                decoder.receive_part(part)
                if decoder.is_complete():
                    break
            if not decoder.is_success():
                raise RuntimeError(f"reference fountain did not complete: {name}/{density}")
            if URPSBT.from_cbor(decoder.result_message().cbor).data != canonical:
                raise RuntimeError("reference fountain recovered different bytes")
            save("fountain-only", fountain, density=density,
                note="Initial systematic frames skipped; malformed reference CRC frames deterministically dropped.")
            save("reversed", list(reversed(fountain)), density=density)
            if not malformed:
                save("dropped", systematic[:2] + systematic[3:], "partial", density=density)
                save("duplicated", [p for p in systematic for _ in range(2)], density=density)
            print(f"{name}/{density}: systematic={count}, invalid_crc={len(malformed)}, fountain_only={len(fountain)}")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"SeedSigner {revision}; wrote {len(manifest['fixtures'])} cases")


if __name__ == "__main__":
    main()
