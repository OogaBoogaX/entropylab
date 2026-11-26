// Behaviour of the Android wrapper's build-side scripts, run as programs
// against stand-in tools: android/gradlew picks the JVM the README tells
// builders to select. No JDK or Android SDK is needed.
// Run with `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const fakeJava = (dir, label) => {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "java");
  writeFileSync(path, `#!/bin/sh\necho "${label}" "$@"\n`);
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
    const run = (env) => spawnSync("sh", [join(root, "android/gradlew"), ":app:assembleDebug"], { env: { PATH, ...env }, encoding: "utf8" });
    const withHome = run({ JAVA_HOME: join(dir, "jdk") });
    assert.equal(withHome.status, 0, withHome.stderr);
    assert.match(withHome.stdout, /^jdk21 -classpath \S+\/gradle\/wrapper\/gradle-wrapper\.jar org\.gradle\.wrapper\.GradleWrapperMain :app:assembleDebug$/m);
    const withoutHome = run({});
    assert.equal(withoutHome.status, 0, withoutHome.stderr);
    assert.match(withoutHome.stdout, /^path-java -classpath \S+ org\.gradle\.wrapper\.GradleWrapperMain :app:assembleDebug$/m);
    const invalidHome = run({ JAVA_HOME: join(dir, "missing") });
    assert.notEqual(invalidHome.status, 0, "an invalid JAVA_HOME fell back to PATH's java");
    assert.doesNotMatch(invalidHome.stdout, /path-java/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
