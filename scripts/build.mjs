// EntropyLab build script (zero dependencies).
//
// Inlines the sources from src/ into a single self-contained index.html at
// the repository root so the file can be downloaded directly. The output is
// byte-for-byte reproducible from the sources and the version declared in
// package.json.
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const SRC = join(root, "src");

const read = (path) => readFileSync(join(SRC, path), "utf8");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

if (!/^\d+(?:\.\d+)*$/.test(version)) {
  throw new Error(`Invalid version in package.json: ${version}`);
}

const versionedFile = `entropylab-${version}.html`;
const generated = () =>
  ["index.html", "versions.json", ...readdirSync(root).filter((name) =>
    /^entropylab-\d+(?:\.\d+)*\.html$/.test(name)
  )];

if (process.argv.includes("--clean")) {
  for (const name of generated()) rmSync(join(root, name), { force: true });
  console.log("Removed generated files (index.html, versions.json, entropylab-*.html)");
  process.exit(0);
}

const template = read("index.html");
const css = read("css/styles.css");
const jsMain = read("js/vendor.js") + read("js/app.js");
const jsOnline = read("js/online.js");
const jsEnhanced = read("js/enhanced-inputs.js");
const jsRepeat = read("js/repeat-inputs.js");
const jsBryanMode = read("js/bryan-mode.js");

let html = template
  .replace("/*@@CSS@@*/", () => css)
  .replace("/*@@JS_MAIN@@*/", () => jsMain)
  .replace("/*@@JS_ONLINE@@*/", () => jsOnline)
  .replace("/*@@JS_ENHANCED@@*/", () => jsEnhanced)
  .replace("/*@@JS_REPEAT@@*/", () => jsRepeat)
  .replace("/*@@JS_BRYAN_MODE@@*/", () => jsBryanMode)
  .split("{{VERSION}}").join(version);

for (const leftover of html.match(/\/\*@@|{{VERSION}}/g) || []) {
  throw new Error(`Unreplaced build token in output: ${leftover}`);
}

// Remove stale generated files (e.g. versioned copies from older releases)
for (const name of generated()) rmSync(join(root, name), { force: true });

writeFileSync(join(root, "index.html"), html);
writeFileSync(join(root, versionedFile), html);
writeFileSync(
  join(root, "versions.json"),
  JSON.stringify({ versions: [{ version: `v${version}`, file: versionedFile }] }) + "\n",
);

console.log(`Built EntropyLab v${version}`);
console.log(`  index.html (${Buffer.byteLength(html, "utf8")} bytes)`);
console.log(`  ${versionedFile}`);
console.log(`  versions.json`);
