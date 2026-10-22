"""Inspect the built APK, not the source manifest or staging assets."""
import hashlib
from pathlib import Path
import re
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

# The merged manifest is what Android enforces, so check it rather than the source XML.
manifest = subprocess.check_output([sys.argv[2], "dump", "xmltree", sys.argv[1], "AndroidManifest.xml"], text=True)
def attribute(name):
    found = re.findall(rf"android:{name}\(0x[0-9a-f]+\)=(.*)$", manifest, re.M)
    if len(found) != 1:
        raise SystemExit(f"Merged manifest has {len(found)} android:{name} attributes, expected 1")
    return found[0].strip()
for name in ("allowBackup", "fullBackupContent"):
    if attribute(name) != "(type 0x12)0x0":
        raise SystemExit(f"Merged manifest does not set android:{name}=false")
if not attribute("dataExtractionRules").startswith("@0x"):
    raise SystemExit("Merged manifest has no android:dataExtractionRules resource")
rules = subprocess.check_output([sys.argv[2], "dump", "xmltree", sys.argv[1], "res/xml/data_extraction_rules.xml"], text=True)
excluded, section = {"cloud-backup": set(), "device-transfer": set()}, None
for line in rules.splitlines():
    element = re.match(r"\s*E: (\S+)", line)
    if element and element.group(1) == "include":
        raise SystemExit("Data extraction rules include a domain")
    if element and element.group(1) in excluded:
        section = element.group(1)
    domain = re.search(r'domain="([^"]+)"', line)
    if domain and section:
        excluded[section].add(domain.group(1))
for section, domains in excluded.items():
    missing = {"root", "file", "database", "sharedpref", "external"} - domains
    if missing:
        raise SystemExit(f"Data extraction rules do not exclude {sorted(missing)} from {section}")
# ActivityInfo.CONFIG_* values for the six changes the live WebView must survive.
handled = {"keyboard": 0x10, "keyboardHidden": 0x20, "orientation": 0x80,
           "screenLayout": 0x100, "screenSize": 0x400, "smallestScreenSize": 0x800}
mask = int(attribute("configChanges").rsplit(")", 1)[-1], 16)
missing = [name for name, bit in handled.items() if not mask & bit]
if missing:
    raise SystemExit(f"Merged MainActivity configChanges {mask:#x} is missing {missing}")
print(f"Packaged HTML OK {actual}; APK requests no permissions; backup and device transfer off; configChanges {mask:#x}")
