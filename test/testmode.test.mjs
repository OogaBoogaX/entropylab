import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("testmode removes its temporary output when the build fails", () => {
  const root = mkdtempSync(join(tmpdir(), "testmode-fixture-"));
  try {
    const scripts = join(root, "scripts");
    const temporary = join(root, "tmp");
    mkdirSync(scripts);
    mkdirSync(temporary);
    copyFileSync(new URL("../scripts/testmode.mjs", import.meta.url), join(scripts, "testmode.mjs"));
    // Record that a partial output exists before simulating a failed build.
    writeFileSync(join(scripts, "build.mjs"), `
      import { writeFileSync } from "node:fs";
      import { join } from "node:path";
      const out = process.argv[process.argv.indexOf("--out") + 1];
      writeFileSync(join(out, "partial.html"), "partial build");
      console.error("fixture build failed");
      process.exit(1);
    `);
    const run = (args = []) => spawnSync(process.execPath, [join(scripts, "testmode.mjs"), ...args], {
      env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary },
      encoding: "utf8",
      timeout: 10000,
    });
    const help = run(["--help"]);
    assert.ifError(help.error);
    assert.equal(help.status, 0);
    assert.deepEqual(readdirSync(temporary), []);
    const failed = run();
    assert.ifError(failed.error);
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /fixture build failed/);
    assert.deepEqual(readdirSync(temporary), [], "failed builds must remove partial output and its directory");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
