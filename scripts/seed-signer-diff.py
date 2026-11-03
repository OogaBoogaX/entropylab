#!/usr/bin/env python3
"""Dev-only bidirectional SeedSigner check. No downloads or runtime dependency.

Run with a reference Python environment, e.g. /tmp/pyvenv/bin/python.
SEEDSIGNER_PATH must point to the pinned checkout (default /tmp/seedprobe).
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(os.environ.get("SEEDSIGNER_PATH", "/tmp/seedprobe"))


def node(script, data):
    result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT,
        input=json.dumps(data), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def main():
    # The generator verifies the reference revision before importing it.
    with tempfile.TemporaryDirectory(prefix="psbt-qr-diff-") as staging:
        subprocess.run([sys.executable, str(ROOT / "scripts/psbt-qr-generate.py"), staging], check=True)
        manifest = json.loads((Path(staging) / "manifest.json").read_text())
        cases = [{**entry, "text": (Path(staging) / entry["file"]).read_text()} for entry in manifest["fixtures"]]
        results = node(r'''
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createPsbtQrReader } from './src/js/psbt-qr-payload.js';
import { psbtInspectDoc } from './src/js/psbt-wasm.js';
const results = [];
for (const entry of JSON.parse(readFileSync(0, 'utf8'))) {
  const reader = createPsbtQrReader();
  let result, bytes;
  try {
    for (const part of entry.text.trim().split('\n')) {
      result = reader.receive(part);
      if (result.status === 'complete') bytes = result.bytes;
      else if (!['partial','done'].includes(result.status)) break;
    }
    if (entry.expected.status === 'complete') {
      if (!bytes || bytes.length !== entry.expected.bytes || createHash('sha256').update(bytes).digest('hex') !== entry.expected.sha256) throw Error(entry.file + ': byte mismatch');
      if (psbtInspectDoc(bytes).rustBitcoinError !== null) throw Error(entry.file + ': parser rejection');
    } else if (bytes || result.status !== entry.expected.status) throw Error(entry.file + ': rejection mismatch');
    results.push({file:entry.file,status:entry.expected.status});
  } finally { bytes?.fill(0); reader.reset(); }
}
console.log(JSON.stringify(results));
''', cases)
        print(f"reference -> app: {len(results)} exact-payload/rejection checks passed")

    sys.path.insert(0, str(REFERENCE / "src"))
    from seedsigner.models.decode_qr import DecodeQR
    fixtures = []
    for name in ["p2wpkh-1in-2out", "mixed-many-inputs", "p2tr-taproot"]:
        fixtures.append({"name": name, "base64": (ROOT / f"test/fixtures/psbt/{name}.b64").read_text().strip()})
    outputs = node(r'''
import { readFileSync } from 'node:fs';
import { psbtQrPlan } from './src/js/psbt-editor.js';
import { hodlUrEncodePsbt } from './src/js/psbt-ur.js';
console.log(JSON.stringify(JSON.parse(readFileSync(0,'utf8')).map(entry => {
  const bytes = Buffer.from(entry.base64,'base64');
  return {...entry, plan:psbtQrPlan(bytes), animated:hodlUrEncodePsbt(bytes)};
})));
''', fixtures)
    for entry in outputs:
        expected = base64.b64decode(entry["base64"])
        actual_plan = entry["plan"]
        paths = {"application-output": actual_plan.get("parts", [actual_plan.get("text")]),
            "animated-regression": entry["animated"]}
        for kind, parts in paths.items():
            decoder = DecodeQR()
            for part in parts:
                decoder.add_data(part)
            if not decoder.is_complete or decoder.get_data_psbt() != expected:
                raise RuntimeError(f"{entry['name']}/{kind}: independent decoder did not recover exact original bytes")
            print(f"app -> reference: {entry['name']}/{kind}, {len(parts)} parts, byte-exact")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
