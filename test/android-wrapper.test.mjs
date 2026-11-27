// Behaviour of the Android wrapper's build-side scripts, run as programs
// against stand-in tools: android/gradlew picks the JVM the README tells
// builders to select, and android/verify-apk.py judges an APK through a
// stand-in aapt that prints aapt's dump formats. No JDK or Android SDK is
// needed.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const fakeJava = (dir, label) => {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "java");
  writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' "${label}" "$@"\n`);
  chmodSync(path, 0o755);
};

// Gradle 8.11.1's own launcher runs $JAVA_HOME/bin/java when JAVA_HOME is set
// and java from PATH only otherwise; android/README.md and the CI workflow
// select JDK 21 through JAVA_HOME. An invalid JAVA_HOME must fail, never fall
// back to whatever java PATH holds.
test("android/gradlew runs JAVA_HOME's java when set, PATH's otherwise", { skip: process.platform === "win32" && "POSIX launcher" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-gradlew-"));
  try {
    fakeJava(join(dir, "jdk", "bin"), "jdk21");
    fakeJava(join(dir, "path"), "path-java");
    const PATH = `${join(dir, "path")}:/usr/bin:/bin`;
    const checkout = join(dir, "Entropy Lab checkout", "android");
    mkdirSync(checkout, { recursive: true });
    copyFileSync(join(root, "android/gradlew"), join(checkout, "gradlew"));
    const argv = ["-classpath", join(checkout, "gradle/wrapper/gradle-wrapper.jar"),
      "org.gradle.wrapper.GradleWrapperMain", ":app:assembleRelease"];
    const run = (env) => spawnSync("sh", [join(checkout, "gradlew"), ":app:assembleRelease"], { env: { PATH, ...env }, encoding: "utf8" });
    const withHome = run({ JAVA_HOME: join(dir, "jdk") });
    assert.equal(withHome.status, 0, withHome.stderr);
    assert.deepEqual(withHome.stdout.trimEnd().split("\n"), ["jdk21", ...argv]);
    const withoutHome = run({});
    assert.equal(withoutHome.status, 0, withoutHome.stderr);
    assert.deepEqual(withoutHome.stdout.trimEnd().split("\n"), ["path-java", ...argv]);
    const invalidHome = run({ JAVA_HOME: join(dir, "missing") });
    assert.notEqual(invalidHome.status, 0, "an invalid JAVA_HOME fell back to PATH's java");
    assert.doesNotMatch(invalidHome.stdout, /path-java/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const PYTHON = spawnSync("python3", ["--version"], { stdio: "pipe" }).status === 0;
const skipApk = process.platform === "win32" ? "POSIX stand-in aapt" : !PYTHON && "python3 is not installed";

// aapt dump xmltree of the merged manifest, as the CI workflow's build-tools
// 35.0.0 aapt prints it. configChanges 0xdb0 is the six changes MainActivity
// handles.
const manifestDump = (rulesRef, debuggable) => `N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    A: android:compileSdkVersion(0x01010572)=(type 0x10)0x24
    A: package="online.entropylab.android" (Raw: "online.entropylab.android")
    E: application (line=3)
${debuggable === undefined ? "" : `      A: android:debuggable(0x0101000f)=(type 0x12)${debuggable}\n`}      A: android:label(0x01010001)="EntropyLab" (Raw: "EntropyLab")
      A: android:allowBackup(0x01010280)=(type 0x12)0x0
      A: android:fullBackupContent(0x010104eb)=(type 0x12)0x0
      A: android:dataExtractionRules(0x0101064b)=${rulesRef}
      E: activity (line=10)
        A: android:name(0x01010003)="online.entropylab.android.MainActivity" (Raw: "online.entropylab.android.MainActivity")
        A: android:configChanges(0x0101001f)=(type 0x11)0xdb0
`;

// aapt dump resources: two xml resources, so a manifest can name the one
// verify-apk.py does not inspect.
const resourcesDump = `Package Groups (1)
Package Group 0 id=0x7f packageCount=1 name=online.entropylab.android
  Package 0 id=0x7f name=online.entropylab.android
    type 3 configCount=1 entryCount=2
      spec resource 0x7f040000 online.entropylab.android:xml/data_extraction_rules: flags=0x00000000
      spec resource 0x7f040001 online.entropylab.android:xml/backup_rules: flags=0x00000000
      config (default):
        resource 0x7f040000 online.entropylab.android:xml/data_extraction_rules: t=0x03 d=0x00000003 (s=0x0008 r=0x00)
        resource 0x7f040001 online.entropylab.android:xml/backup_rules: t=0x03 d=0x00000004 (s=0x0008 r=0x00)
`;

const DOMAINS = ["root", "file", "database", "sharedpref", "external"];
// aapt dump xmltree of res/xml/data_extraction_rules.xml; pathOf(section,
// domain) gives an exclusion's path attribute, or undefined for none.
const rulesDump = (pathOf = () => undefined) => {
  let line = 2;
  let out = `E: data-extraction-rules (line=${line++})\n`;
  for (const section of ["cloud-backup", "device-transfer"]) {
    out += `  E: ${section} (line=${line++})\n`;
    for (const domain of DOMAINS) {
      out += `    E: exclude (line=${line++})\n      A: domain="${domain}" (Raw: "${domain}")\n`;
      const path = pathOf(section, domain);
      if (path !== undefined) out += `      A: path="${path}" (Raw: "${path}")\n`;
    }
  }
  return out;
};

const STAND_IN_AAPT = `#!/bin/sh
dir=$(dirname "$0")
case "$1 $2 $4" in
  "dump permissions ") cat "$dir/permissions.txt" ;;
  "dump resources ") cat "$dir/resources.txt" ;;
  "dump xmltree AndroidManifest.xml") cat "$dir/manifest.txt" ;;
  "dump xmltree res/xml/data_extraction_rules.xml") cat "$dir/rules.txt" ;;
  *) echo "ERROR: no such file or command: $*" >&2; exit 1 ;;
esac
`;

// Runs android/verify-apk.py on an APK holding the pinned HTML, with the
// stand-in aapt answering from these dumps.
const verifyApk = ({ rulesRef = "@0x7f040000", rules = rulesDump(), debuggable } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-verify-apk-"));
  try {
    const apk = join(dir, "app-release-unsigned.apk");
    const zip = spawnSync("python3", ["-c", "import sys, zipfile\nwith zipfile.ZipFile(sys.argv[1], 'w') as z: z.write(sys.argv[2], 'assets/entropylab.html')", apk, join(root, "android/app/src/main/assets/entropylab.html")], { encoding: "utf8" });
    assert.equal(zip.status, 0, zip.stderr);
    writeFileSync(join(dir, "permissions.txt"), "package: online.entropylab.android\n");
    writeFileSync(join(dir, "resources.txt"), resourcesDump);
    writeFileSync(join(dir, "manifest.txt"), manifestDump(rulesRef, debuggable));
    writeFileSync(join(dir, "rules.txt"), rules);
    writeFileSync(join(dir, "aapt"), STAND_IN_AAPT);
    chmodSync(join(dir, "aapt"), 0o755);
    return spawnSync("python3", [join(root, "android/verify-apk.py"), apk, join(dir, "aapt")], { encoding: "utf8" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const accepted = (result) => {
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /backup and device transfer off/);
};
const refused = (result, reason) => {
  assert.notEqual(result.status, 0, `verify-apk.py accepted it: ${result.stdout}`);
  assert.match(result.stderr, reason);
};

// verify-apk.py reads one rules file, so it must be the one the merged
// manifest's android:dataExtractionRules names; a manifest naming any other
// resource (or none) is refused rather than judged by a file Android ignores.
test("verify-apk.py inspects only the rules resource the merged manifest names", { skip: skipApk }, () => {
  accepted(verifyApk());
  refused(verifyApk({ rulesRef: "@0x7f040001" }), /xml\/backup_rules/);
  refused(verifyApk({ rulesRef: "@0x7f0400ff" }), /dataExtractionRules/);
});

// An exclusion covers the whole domain only with no path (Android reads a
// missing path as the domain itself: FullBackup.extractCanonicalFile in
// AOSP) or path "."; any other path excludes only that file or folder, so
// the rest of the domain would still be backed up or transferred.
test("verify-apk.py counts only whole-domain exclusions as backup off", { skip: skipApk }, () => {
  accepted(verifyApk({ rules: rulesDump(() => undefined) }));
  accepted(verifyApk({ rules: rulesDump(() => ".") }));
  refused(verifyApk({ rules: rulesDump(() => "one-file") }), /do not exclude/);
  refused(verifyApk({ rules: rulesDump((section, domain) => (section === "device-transfer" && domain === "file" ? "one-file" : undefined)) }), /\['file'\] from device-transfer/);
});

test("verify-apk.py rejects a debuggable APK", { skip: skipApk }, () => {
  accepted(verifyApk());
  accepted(verifyApk({ debuggable: "0x0" }));
  refused(verifyApk({ debuggable: "0xffffffff" }), /debuggable/);
});
