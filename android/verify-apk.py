"""Inspect the built APK, not the source manifest or staging assets."""
import hashlib
from pathlib import Path
import subprocess
import sys
import zipfile

root = Path(__file__).resolve().parent
expected = (root / "ENTROPYLAB_HTML.sha256").read_text().split()[0]
with zipfile.ZipFile(sys.argv[1]) as apk:
    actual = hashlib.sha256(apk.read("assets/entropylab.html")).hexdigest()
if actual != expected:
    raise SystemExit(f"Packaged HTML digest {actual} differs from pin {expected}")
permissions = subprocess.check_output([sys.argv[2], "dump", "permissions", sys.argv[1]], text=True)
if "uses-permission:" in permissions or "uses-permission-sdk-" in permissions:
    raise SystemExit(f"APK requests permissions:\n{permissions}")
print(f"Packaged HTML OK {actual}; APK requests no permissions")
