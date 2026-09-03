// Lifecycle clearing must discard application state, not only visible fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");
const start = app.indexOf("function hodlInitSecretFieldAutoClear()");
const end = app.indexOf("\nfunction hodlBoot()", start);
const lifecycle = app.slice(start, end);

test("page lifecycle clearing replaces every cached key and clears PSBT private state", () => {
  assert.match(lifecycle, /hodlPsbtWipeMem\(\)/);
  assert.match(lifecycle, /hodlBip85WipeMem\(\)/);
  assert.match(lifecycle, /hodlSpWipeMem\(\)/);
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(lifecycle, /hodlKeys\s*=\s*hodlKeys\.map\(\(state\)\s*=>\s*\{/);
  assert.match(lifecycle, /privateKeys\[kind\]\s*=\s*""/);
  assert.match(lifecycle, /if \(id !== "privateKeys"\) fields\[id\] = ""/);
  assert.match(lifecycle, /state\.result\s*=\s*null/);
  assert.match(lifecycle, /return state\.isLab \? hodlNewLabState\(\) : hodlNewKeyState\(state\.name, state\.id, state\.number\)/);
  assert.match(lifecycle, /hodlWalletResult\s*=\s*null[\s\S]*hodlRevealPrivate\s*=\s*false[\s\S]*hodlPickedLastWord\s*=\s*""[\s\S]*hodlDiceCoinPositions\s*=\s*\[\]/);
  assert.match(lifecycle, /addEventListener\("pagehide", clearSecretFields\)/);
  assert.match(lifecycle, /event\.persisted\) clearSecretFields\(\)/);
});

test("PSBT key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("psbt-key"\)/);
  assert.match(lifecycle, /getElementById\("psbt-pass"\)/);
  assert.match(lifecycle, /psbtKey\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtPass\.value\s*=\s*""/);
});

test("PSBT text and anti-exfil transcript fields are explicitly cleared", () => {
  // #psbt-text can carry xprvs in proprietary fields; #psbt-ax-transcript
  // holds the anti-exfil host nonce.
  assert.match(lifecycle, /getElementById\("psbt-text"\)/);
  assert.match(lifecycle, /getElementById\("psbt-ax-transcript"\)/);
  assert.match(lifecycle, /psbtText\.value\s*=\s*""/);
  assert.match(lifecycle, /psbtAxTranscript\.value\s*=\s*""/);
});

test("BIP-85 parent and derived-child fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("bip85-key"\)/);
  assert.match(lifecycle, /bip85Key\.value\s*=\s*""/);
  assert.match(lifecycle, /bip85Out\.innerHTML\s*=\s*""/);
});

test("Entropy Journal password, entries, and encrypted session are explicitly cleared", () => {
  // The lifecycle's hodlJournalWipeMem clears both the session notepad and the
  // encrypted notebook (keys, document, and every notebook field).
  assert.match(lifecycle, /hodlJournalWipeMem\(\)/);
  assert.match(app, /function hodlJournalWipeMem\(\) \{[\s\S]*?hodlJournalWipeNotebook\(\)[\s\S]*?hodlJournalClearFields\(\)/);
  assert.match(app, /journal-create-password/);
  assert.match(app, /journal-input/);
  assert.match(app, /journal-phrase/);
  assert.match(app, /journal-entry-notes/);
});

test("Silent Payments session key and passphrase fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-key"\)/);
  assert.match(lifecycle, /getElementById\("sp-pass"\)/);
  assert.match(lifecycle, /spKey\.value\s*=\s*""/);
  assert.match(lifecycle, /spPass\.value\s*=\s*""/);
});

test("Silent Payments private-bearing inputs and revealed output are cleared", () => {
  // #sp-send-vins carries per-input private keys; #sp-out renders revealed
  // scan/spend private material. Both must go when the page lifecycle clears.
  assert.match(lifecycle, /getElementById\("sp-send-vins"\)/);
  assert.match(lifecycle, /spVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-out"\)/);
  assert.match(lifecycle, /spOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /spError\.textContent\s*=\s*""/);
  assert.match(lifecycle, /spSession\.textContent\s*=\s*hodlFormatNote\(hodlSpNote\)/);
});

test("Silent Payments recipient, verify, and label fields are explicitly cleared", () => {
  assert.match(lifecycle, /getElementById\("sp-recipients"\)/);
  assert.match(lifecycle, /spRecipients\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-vins"\)/);
  assert.match(lifecycle, /spVerifyVins\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-verify-outputs"\)/);
  assert.match(lifecycle, /spVerifyOutputs\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("sp-label"\)/);
  assert.match(lifecycle, /spLabel\.value\s*=\s*""/);
});

test("highlight mirrors, copy-button phrases, the last-word cache, and the PSBT editor are cleared", () => {
  // The .dice-input-highlight <pre> behind each input holds a second live
  // copy of the typed secret; copy buttons keep the phrase in data-phrase;
  // hodlLastWordCache retains partial mnemonics; the editor holds the loaded
  // PSBT (which can carry xprvs in proprietary fields).
  assert.match(lifecycle, /querySelectorAll\("\.dice-input-highlight"\)/);
  assert.match(lifecycle, /highlight\.textContent\s*=\s*""/);
  assert.match(lifecycle, /querySelectorAll\("\[data-phrase\]"\)/);
  assert.match(lifecycle, /removeAttribute\("data-phrase"\)/);
  assert.match(lifecycle, /hodlLastWordCache\.clear\(\)/);
  assert.match(lifecycle, /getElementById\("psbted-wipe"\)/);
  assert.match(lifecycle, /psbtEditorWipe\.click\(\)/);
});

test("Vanity grinder salt, matches, and running workers are cleared", () => {
  // The imported/typed salt prefixes every candidate passphrase, and a found
  // passphrase is private key material — both go on pagehide/bfcache, and the
  // worker pool is cancelled so nothing keeps grinding (or holding the salt
  // in a worker's WASM heap) after the page hides.
  assert.match(lifecycle, /hodlVanityCancel\(\)/);
  assert.match(lifecycle, /hodlVanityMatches\s*=\s*\[\]/);
  assert.match(lifecycle, /hodlVanityFound\s*=\s*0/);
  assert.match(lifecycle, /hodlVanityReveal\s*=\s*false/);
  assert.match(lifecycle, /hodlVanitySource\s*=\s*""/);
  assert.match(lifecycle, /hodlVanityRun\s*=\s*null/);
  assert.match(lifecycle, /getElementById\("vanity-pass"\)/);
  assert.match(lifecycle, /vanityPass\.value\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-out"\)/);
  assert.match(lifecycle, /vanityOut\.innerHTML\s*=\s*""/);
  assert.match(lifecycle, /getElementById\("vanity-error"\)/);
  assert.match(lifecycle, /vanityError\.textContent\s*=\s*""/);
});
