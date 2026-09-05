// Brain-wallet passphrase normalization and SHA-256 compatibility.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");
function hodlT(key, vars) {
  let text = key; // English-as-key
  if (vars) text = text.replace(/\{(\w+)\}/g, (_, n) => (vars[n] == null ? `{${n}}` : String(vars[n])));
  return text;
}
function hodlError(key, vars) {
  const err = new Error(hodlT(key, vars));
  err.hodlSpec = vars == null ? { key } : { key, vars };
  return err;
}

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let depth = 0;
  let end = -1;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}") {
      depth--;
      if (depth === 0) {
        end = index + 1;
        break;
      }
    }
  }
  assert.ok(end > start, name);
  return app.slice(start, end);
}

const hodlSha256 = (input) => new Uint8Array(createHash("sha256").update(input).digest());
const helpers = new Function(
  "hodlSha256",
  "TextEncoder",
  "hodlError",
  `${loadSlice("hodlBrainWalletPassphrase")};${loadSlice("hodlBrainWalletPrivateKey")};return { hodlBrainWalletPassphrase, hodlBrainWalletPrivateKey };`,
)(hodlSha256, TextEncoder, hodlError);

test("brain-wallet recovery hashes exact text by default", () => {
  const passphrase = " recovery phrase \t\n";
  const expected = createHash("sha256").update(passphrase, "utf8").digest("hex");
  assert.equal(Buffer.from(helpers.hodlBrainWalletPrivateKey(passphrase)).toString("hex"), expected);
  assert.equal(helpers.hodlBrainWalletPassphrase(passphrase), passphrase);
});

test("opt-in trimming removes boundary whitespace before hashing", () => {
  const passphrase = " \trecovery phrase\n ";
  const expected = createHash("sha256").update("recovery phrase", "utf8").digest("hex");
  assert.equal(Buffer.from(helpers.hodlBrainWalletPrivateKey(passphrase, true)).toString("hex"), expected);
  assert.equal(helpers.hodlBrainWalletPassphrase(passphrase, true), "recovery phrase");
});

test("exact mode accepts whitespace while trim mode rejects an empty result", () => {
  assert.equal(helpers.hodlBrainWalletPassphrase(" \t\n"), " \t\n");
  assert.throws(() => helpers.hodlBrainWalletPassphrase(" \t\n", true), /leaves an empty brain-wallet recovery passphrase/);
  assert.throws(() => helpers.hodlBrainWalletPassphrase(""), /Enter the brain-wallet recovery passphrase/);
});

const lab = new Function(
  "hodlSha256",
  "hodlHex",
  "hodlNote",
  `${loadSlice("hodlBrainLabEntropy")};return { hodlBrainLabEntropy };`,
)(hodlSha256, { encode: (bytes) => Buffer.from(bytes).toString("hex") }, (key, vars) => hodlT(key, vars));

test("brain-wallet lab hashes exact UTF-8 text as 256-bit BIP39 entropy", () => {
  const text = " recovery phrase \t\n";
  const expected = createHash("sha256").update(text, "utf8").digest("hex");
  const result = lab.hodlBrainLabEntropy(text);
  assert.equal(result.ok, true);
  assert.equal(result.hex, expected);
  assert.equal(result.bits, 256);
  assert.equal(result.sourceBits, 256);
  assert.equal(result.method, "brain-lab");
  assert.equal(result.bytes.length, 32);
  assert.match(result.notes.join(" "), /24 words/);
  assert.match(result.warnings.join(" "), /entropy of this text, not the 24-word count/);
  assert.match(result.warnings.join(" "), /unsalted and fast/);
  assert.match(result.warnings.join(" "), /not a BIP39 passphrase/);
  assert.match(result.warnings.join(" "), /not a Bitcoin Core hdseed/);
  assert.match(result.warnings.join(" "), /not mean it is the same wallet/);
});

test("brain-wallet lab rejects empty text and keeps private-key hashing separate", () => {
  assert.equal(lab.hodlBrainLabEntropy("").ok, false);
  const text = "correct horse battery staple";
  const labHex = lab.hodlBrainLabEntropy(text).hex;
  const scalarHex = Buffer.from(helpers.hodlBrainWalletPrivateKey(text)).toString("hex");
  assert.equal(labHex, scalarHex);
  assert.match(app, /kind === "brain" && hodlBrainWalletOutput\(\) === "hd"/);
  assert.match(app, /function hodlBrainWalletPrivateKey\(/);
  assert.match(app, /function hodlBrainLabEntropy\(/);
});

test("the brain-wallet HD output has no silent fingerprint or mnemonic preview path", () => {
  // It lives under Private key > Brain wallet rather than in its own mode, so the
  // two uses of the same digest are chosen explicitly instead of by tab.
  assert.match(app, /hodlKeyModes = \["dice", "cards", "hex", "seed", "key"\]/);
  assert.doesNotMatch(app, /"brain-lab" \? "Brain wallet/);
  assert.doesNotMatch(app, /Brain wallet — lab/);
  assert.doesNotMatch(app, /id="brain-lab-details"/);
  assert.match(app, /id="brain-warning"/);
  assert.match(app, /name="bo" value="scalar"/);
  assert.match(app, /name="bo" value="hd"/);
  // The private-key mode never previews a fingerprint or mnemonic, which now
  // covers the HD brain output too.
  assert.match(app, /if \(hodlKeyMode === "key"\) \{\s*preview\.hidden = true;/);
  assert.match(app, /hodlTText\("([\w .-]*\{derive\}[\w .-]*)", \{ derive: hodlTText\("Derive Key"\) \}\)/);
  assert.match(app, /24 words appear only after \{derive\}/);
  assert.match(app, /hodlError\("Acknowledge the lab warning before deriving/);
  // Each output is acknowledged on its own, so one does not unlock the other.
  assert.match(app, /hodlBrainLabAck = \{ scalar: false, hd: false \}/);
  assert.match(app, /hodlBrainLabAck\[output\] = ack\.checked/);
  assert.doesNotMatch(loadSlice("hodlBrainLabEntropy"), /localStorage/);
});

test("a derived brain wallet does not outlive its acknowledgement or its output choice", () => {
  // Unticking "I understand" has to retract what it authorised. Without this the
  // warning can be revoked while the derived private key stays on screen and
  // stays revealable, which is the opposite of what the checkbox promises.
  // Switching output is the same failure wearing a different hat: the two
  // outputs build different wallets from the same text, so a result left over
  // from the other one is a wrong address waiting to be copied.
  const ack = app.slice(app.indexOf('let ack = document.getElementById("brain-lab-ack");'));
  const handler = ack.slice(0, ack.indexOf("};") + 2);
  assert.match(handler, /hodlBrainLabAck\[output\] = ack\.checked;\s*if \(!ack\.checked\) hodlRetractBrainWalletResults\(output\);\s*hodlInvalidateLiveKeyResult\(\);/);

  const radios = app.slice(app.indexOf(`document.querySelectorAll('input[name="bo"]')`));
  const bound = radios.slice(0, radios.indexOf("}));") + 4);
  assert.match(bound, /state\.brainWalletOutput = hodlBrainWalletOutput\(\);\s*hodlInvalidateLiveKeyResult\(\);/);

  // The retraction has to clear the rendered result and the reveal flag, not
  // merely hide the input.
  const invalidate = loadSlice("hodlInvalidateLiveKeyResult");
  assert.match(invalidate, /state\.result = null/);
  assert.match(invalidate, /state\.reveal = false/);
  assert.match(invalidate, /hodlWalletResult = null/);
  assert.match(invalidate, /hodlRevealPrivate = false/);
  assert.match(invalidate, /hodlOutEl\.innerHTML = ""/);

  // A revoked acknowledgement has to reach committed key tabs too: they
  // re-render their stored result without asking again, so every brain-derived
  // result carries a marker and revoking sweeps it from every slot.
  const derive = loadSlice("hodlCalculateKey");
  assert.match(derive, /if \(kind === "brain"\) hodlWalletResult\.brainWalletOutput = hodlBrainWalletOutput\(\);/);
  const retract = loadSlice("hodlRetractBrainWalletResults");
  assert.match(retract, /for \(let state of hodlKeys\)/);
  assert.match(retract, /state\?\.result\?\.brainWalletOutput !== output/);
  assert.match(retract, /state\.result = null/);
  assert.match(retract, /state\.reveal = false/);
});
