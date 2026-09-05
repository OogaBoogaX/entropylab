// Jade anti-exfil (secp256k1-zkp sign-to-contract) helpers used by PSBT nonce checks.
// Run with: npm run test:antiexfil
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
const shell = readFileSync(join(root, "..", "src/shell.html"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let i = app.indexOf("{", start); i < app.length; i++) {
    if (app[i] === "{") depth++;
    else if (app[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const hodlHex = {
  encode: (bytes) => Buffer.from(bytes).toString("hex"),
  decode: (hex) => Uint8Array.from(Buffer.from(hex, "hex")),
};
const hodlSha256 = (bytes) => Uint8Array.from(createHash("sha256").update(Buffer.from(bytes)).digest());

const hodlTaggedSha256 = new Function(
  "hodlSha256",
  `${loadSlice("hodlTaggedSha256")}; return hodlTaggedSha256;`,
)(hodlSha256);
const hodlParseAntiExfil = new Function(
  "hodlHex",
  `${loadSlice("hodlParseAntiExfil")}; return hodlParseAntiExfil;`,
)(hodlHex);

test("PSBT copy mentions Jade anti-exfil transcript checks", () => {
  assert.match(shell, /Optional Jade anti-exfil transcripts/);
  assert.match(shell, /id="psbt-ax-transcript"/);
  assert.match(app, /hodlAntiExfilCommitOk\(\s*parts\.r\s*,\s*opening\s*,\s*transcript\.host\s*\)/);
  assert.match(app, /s2c\/ecdsa\/point/);
  assert.match(app, /hodlT\("Matches Jade anti-exfil \(sign-to-contract\)\. Host entropy mixed into the nonce\. Not a leak\."\)/);
  assert.match(app, /RFC 6979 comparison currently covers/);
  assert.match(app, /QR \/ sign_psbt Jade does not run it yet/);
});

test("empty transcript is inspect-only (no anti-exfil check)", () => {
  assert.equal(hodlParseAntiExfil(""), null);
  assert.equal(hodlParseAntiExfil("   "), null);
  assert.equal(hodlParseAntiExfil(null), null);
});

test("parses host nonce and compressed opening as separate hex", () => {
  const host = "11".repeat(32);
  const opening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
  const parsed = hodlParseAntiExfil(`host ${host}\nopening ${opening}`);
  assert.equal(parsed.host.length, 32);
  assert.equal(Buffer.from(parsed.host).toString("hex"), host);
  assert.equal(parsed.openings.length, 1);
  assert.equal(Buffer.from(parsed.openings[0]).toString("hex"), opening);
});

test("parses concatenated 32-byte host || 33-byte opening", () => {
  const host = "11".repeat(32);
  const opening = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
  const parsed = hodlParseAntiExfil(host + opening);
  assert.equal(Buffer.from(parsed.host).toString("hex"), host);
  assert.equal(Buffer.from(parsed.openings[0]).toString("hex"), opening);
});

test("rejects uncompressed opening and incomplete transcripts", () => {
  const host = "11".repeat(32);
  assert.throws(
    () => hodlParseAntiExfil(host),
    /both the host nonce/,
  );
  assert.throws(
    () => hodlParseAntiExfil("04" + "aa".repeat(32)),
    /compressed secp256k1 point/,
  );
  assert.throws(
    () => hodlParseAntiExfil("aa".repeat(40)),
    /32-byte host nonce/,
  );
});

test("tagged s2c/ecdsa/point hash matches secp256k1-zkp over opening||rho", () => {
  const host = hodlHex.decode("11".repeat(32));
  const opening = hodlHex.decode("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
  const tweak = hodlTaggedSha256("s2c/ecdsa/point", opening, host);
  assert.equal(
    Buffer.from(tweak).toString("hex"),
    "52be4b29692b2aa0d852edd9a5451e8ca2e6759b41c4bf0dc290f99cf145bea2",
  );
});

test("anti-exfil commit check is try/caught so a bad opening cannot wipe the PSBT report", () => {
  assert.match(app, /else\s+try\s*\{\s*if\s*\(\s*hodlAntiExfilCommitOk\(\s*parts\.r\s*,\s*opening\s*,\s*transcript\.host\s*\)\s*\)/);
  assert.match(
    app,
    /catch\s*\(\s*exception\s*\)\s*\{\s*message\s*=\s*hodlT\(\s*"Could not verify Jade anti-exfil: \{error\}"\s*,\s*\{\s*error:\s*exception\.message\s*\|\|\s*String\s*\(\s*exception\s*\)\s*\}\s*\)\s*;\s*className\s*=\s*"psbt-warn"\s*;?\s*\}/,
  );
});

test("malformed anti-exfil transcript is try/caught so parse errors cannot wipe the PSBT report", () => {
  const render = loadSlice("hodlRenderPsbt");
  assert.match(
    render,
    /try\s*\{\s*transcript\s*=\s*hodlParseAntiExfil\(document\.getElementById\("psbt-ax-transcript"\)\?\.value\s*\|\|\s*""\)\s*;?\s*\}\s*catch\s*\(\s*exception\s*\)\s*\{\s*transcriptError\s*=\s*exception\.message\s*\|\|\s*String\(\s*exception\s*\)\s*;?\s*\}/,
  );
  assert.match(
    render,
    /if\s*\(\s*transcriptError\s*\)\s*html\.push\("<p class='psbt-warn'><strong>Jade anti-exfil transcript not used:<\/strong> "\s*\+\s*hodlEscapeHtml\(\s*transcriptError\s*\)\s*\+\s*"<\/p>"\)/,
  );
});

test("compressed 02\/03 openings parse even when x is off-curve (validity is the commit check's job)", () => {
  const host = "11".repeat(32);
  const opening = "02" + "00".repeat(31) + "01";
  const parsed = hodlParseAntiExfil(`host ${host}\nopening ${opening}`);
  assert.equal(parsed.openings.length, 1);
  assert.equal(Buffer.from(parsed.openings[0]).toString("hex"), opening);
});
