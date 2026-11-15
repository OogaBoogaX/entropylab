// A rock build carries an X.Y.Z-dev version and is published, unsigned, to
// preview.entropylab.online (#1406). Contract: a -dev build shows a banner
// that cannot be dismissed, in both copies of the shell (injected for first
// paint, bundled for the boot render), and asks search engines not to index
// the page; a release build carries neither. A dev-build marker the build
// cannot pair fails the build instead of shipping the banner in a release.
//
// Each case builds a throwaway copy of the sources with the version under
// test, so the suite holds whatever package.json says today. Run with
// `npm test` (part of the default suite).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { collectSources, normalize } from "../scripts/i18n-sources.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const COPIED = ["src", "scripts", "assets", "manifest.webmanifest", "package.json"];
const ROBOTS = '<meta name="robots" content="noindex, nofollow">';
const OPEN = "    <!-- dev-build -->\n";
const CLOSE = "    <!-- /dev-build -->\n";

// Builds a copy of the sources stamped with `version`, with the shell passed
// through `editShell` first. Returns the build's exit status, its log and the
// page it wrote (null when it wrote none).
const buildAs = (version, editShell = (shell) => shell) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-dev-build-"));
  try {
    for (const path of COPIED) cpSync(join(root, path), join(dir, path), { recursive: true });
    symlinkSync(join(root, "node_modules"), join(dir, "node_modules"), "junction");
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    writeFileSync(join(dir, "package.json"), `${JSON.stringify({ ...pkg, version }, null, 2)}\n`);
    const shellPath = join(dir, "src/shell.html");
    writeFileSync(shellPath, editShell(readFileSync(shellPath, "utf8")));
    const out = join(dir, "out");
    const result = spawnSync(process.execPath, [join(dir, "scripts/build.mjs"), "--out", out], { cwd: dir, encoding: "utf8" });
    const page = join(out, "entropylab.html");
    return { status: result.status, log: `${result.stdout}${result.stderr}`, html: existsSync(page) ? readFileSync(page, "utf8") : null };
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
};

// The outer markup of every <div> whose start tag carries id="<id>", closed by
// pairing its nested <div> tags.
const divsWithId = (html, id) => {
  const found = [];
  for (let at = html.indexOf(`id="${id}"`); at !== -1; at = html.indexOf(`id="${id}"`, at + 1)) {
    const start = html.lastIndexOf("<div", at);
    const tags = /<\/?div\b[^>]*>/g;
    tags.lastIndex = start;
    let depth = 0;
    for (let tag; (tag = tags.exec(html));) {
      depth += tag[0].startsWith("</") ? -1 : 1;
      if (depth === 0) break;
    }
    found.push(html.slice(start, tags.lastIndex));
  }
  return found;
};

test("the shell's dev-build block holds the banner, at the top of the page", () => {
  const shell = read("src/shell.html");
  assert.equal(shell.split(OPEN).length, 2, "one dev-build opening marker, alone on its line");
  assert.equal(shell.split(CLOSE).length, 2, "one dev-build closing marker, alone on its line");
  const block = shell.slice(shell.indexOf(OPEN) + OPEN.length, shell.indexOf(CLOSE));
  const [banner] = divsWithId(block, "dev-build-warning");
  assert.ok(banner, "the block holds #dev-build-warning");
  assert.equal(block.trim(), banner, "the block holds the banner and nothing else");
  assert.ok(shell.indexOf(OPEN) < shell.indexOf('id="site-intro"'), "the banner comes before the page's introduction");
});

test("a -dev build shows the banner in both shell copies and asks search engines not to index it", { timeout: 120000 }, async () => {
  const { status, log, html } = buildAs("1.1.0-dev");
  assert.equal(status, 0, log);
  assert.doesNotMatch(html, /<!-- \/?dev-build -->/, "the markers do not ship");
  const banners = divsWithId(html, "dev-build-warning");
  assert.equal(banners.length, 2, "first paint and the boot render both carry the banner");
  assert.equal(banners[0], banners[1], "the two copies agree");
  const [banner] = banners;
  assert.doesNotMatch(banner.match(/^<div\b[^>]*>/)[0], /\shidden\b/, "the banner is not hidden");
  assert.match(banner, /\srole="alert"/, "the banner is announced as an alert");
  // Nothing can close it: no control inside it, and no script reads or
  // writes it, so neither a click nor a stored dismissal can hide it.
  assert.doesNotMatch(banner, /<(button|a|input)\b/, "the banner carries no control");
  for (const name of readdirSync(join(root, "src/js")).filter((file) => file.endsWith(".js"))) {
    assert.doesNotMatch(read(`src/js/${name}`), /dev-build-warning/, `src/js/${name} must not touch the banner`);
  }
  assert.doesNotMatch(read("src/index.html"), /dev-build-warning/, "the head script must not touch the banner");
  // Safety wording, pinned by short stable phrases only.
  assert.match(banner, /unsigned/);
  assert.match(banner, /real funds/);
  // Its text reaches the translation catalog the way the beta banner's does.
  const rich = banner.match(/<div\b[^>]*\sdata-i18n-rich[^>]*>([\s\S]*?)<\/div>/);
  assert.ok(rich, "the banner text is a rich translation block");
  assert.ok((await collectSources(root)).has(normalize(rich[1])), "the catalog sweep misses the banner text");
  // Exactly one robots tag, in the head.
  assert.equal(html.split(ROBOTS).length, 2, "one noindex robots meta");
  assert.ok(html.indexOf(ROBOTS) < html.indexOf("</head>"), "the robots meta sits in the head");
});

test("a release build carries no banner and no robots meta", { timeout: 120000 }, () => {
  const { status, log, html } = buildAs("1.1.0");
  assert.equal(status, 0, log);
  assert.doesNotMatch(html, /dev-build/, "no banner and no marker reach a release");
  assert.doesNotMatch(html, /<meta name="robots"/, "a release can be indexed");
});

test("a dev-build marker the build cannot pair fails the build", { timeout: 120000 }, () => {
  for (const [label, edit] of [
    ["a marker followed by markup on its line", (shell) => shell.replace(OPEN, OPEN.trimEnd())],
    ["a marker after markup on its line", (shell) => shell.replace(CLOSE, `    <p></p>${CLOSE.trimStart()}`)],
    ["a missing closing marker", (shell) => shell.replace(CLOSE, "")],
    ["a misspelled marker", (shell) => shell.replace(OPEN, "    <!--dev-build-->\n")],
    ["a second block", (shell) => shell.replace(CLOSE, `${CLOSE}${OPEN}${CLOSE}`)],
  ]) {
    const { status, log, html } = buildAs("1.1.0", edit);
    assert.notEqual(status, 0, `${label}: the release build must fail`);
    assert.match(log, /Expected one dev-build block in each shell copy/, label);
    assert.equal(html, null, `${label}: no page is written`);
  }
});
