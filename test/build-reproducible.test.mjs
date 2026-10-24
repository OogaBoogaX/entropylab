// The release claim "byte-for-byte reproducible from the sources" must hold
// mechanically, not aspirationally: scripts/reproduce.mjs builds the working
// tree twice from two differently shaped directory layouts and requires
// identical sha256 for entropylab.html and service-worker.js. This suite
// owns running that check as part of the default test run; the CI reproduce
// job additionally compares builds across environments (runner vs the
// pinned dev image). Run with `npm test` (part of the default suite).
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

test("the site build is byte-reproducible from two different source paths", { timeout: 120000 }, () => {
  execFileSync(process.execPath, [join(root, "scripts", "reproduce.mjs")], { stdio: "inherit" });
});
