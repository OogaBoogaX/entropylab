// "Check a descriptor for key reuse" (issue #164): the verdict markup and the
// controls' wiring, which ship in every build.
// Run with: node --test test/descriptor-reuse-ui.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { mnemonicToSeedSync } from "../src/js/bip39.js";
import { HDKey } from "../src/js/hdkey.js";
import { descriptorChecksum } from "../src/js/core-importdescriptors.js";
import { DESCRIPTOR_REUSE_SHOWN, descriptorReuseHtml, initDescriptorReuseCheck } from "../src/js/descriptor-reuse-ui.js";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

const master = HDKey.fromMasterSeed(mnemonicToSeedSync("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
const X = master.derive("m/84'/0'/0'").publicExtendedKey;
const Y = master.derive("m/84'/0'/1'").publicExtendedKey;

const CLEAN = "No duplicate derived keys detected in the first 20 addresses of each branch.";
const REUSE = "Potential key reuse: this descriptor derives the same public key in more than one place";

const fakeElement = () => ({
  value: "",
  textContent: "",
  innerHTML: "",
  listeners: {},
  addEventListener(type, handler) { this.listeners[type] = handler; },
});
const setup = () => {
  const elements = Object.fromEntries(["descriptor-reuse-text", "descriptor-reuse-go", "descriptor-reuse-out", "descriptor-reuse-error"].map((id) => [id, fakeElement()]));
  initDescriptorReuseCheck({ getElementById: (id) => elements[id] ?? null });
  const check = (descriptor) => {
    elements["descriptor-reuse-text"].value = descriptor;
    elements["descriptor-reuse-go"].listeners.click();
    return { out: elements["descriptor-reuse-out"].innerHTML, error: elements["descriptor-reuse-error"].textContent };
  };
  return { elements, check };
};

test("a clean descriptor gets the agreed green note", () => {
  const { check } = setup();
  const body = `wsh(multi(2,${X}/<0;1>/*,${Y}/<0;1>/*))`;
  const { out, error } = check(`${body}#${descriptorChecksum(body)}`);
  assert.equal(error, "");
  assert.equal(out, `<p class="edge-note is-public" data-reuse-verdict="clean">${CLEAN}</p>`);
});

test("a repeated key gets the agreed red note with the first collisions and their paths", () => {
  const { check } = setup();
  const { out, error } = check(`wsh(multi(2,${X}/0/*,${X}/0/*))`);
  assert.equal(error, "");
  assert.match(out, /^<div class="edge-note is-private" data-reuse-verdict="reuse">/);
  assert.ok(out.includes(`<strong>${REUSE}</strong>`));
  const items = [...out.matchAll(/<li data-reuse-collision>([^<]*)<\/li>/g)].map((match) => match[1]);
  assert.equal(items.length, DESCRIPTOR_REUSE_SHOWN, "only the first collisions are listed");
  assert.equal(items[0], `Key 1 at ${X.slice(0, 4)}…/0/0 and key 2 at ${X.slice(0, 4)}…/0/0`);
  assert.match(out, /<p>…and 15 more\.<\/p>/, "the rest are counted");
});

test("a few collisions are all listed, with no count line", () => {
  const html = descriptorReuseHtml({ collisionCount: 2, collisions: [
    { first: { slot: 0, path: "xpub…/0/1" }, second: { slot: 2, path: "xpub…/1/1" } },
    { first: { slot: 1, path: "xpub…/0/4" }, second: { slot: 2, path: "xpub…/1/4" } },
  ] });
  assert.equal((html.match(/<li data-reuse-collision>/g) ?? []).length, 2);
  assert.ok(html.includes("Key 1 at xpub…/0/1 and key 3 at xpub…/1/1"));
  assert.doesNotMatch(html, /more\./);
});

test("paths are escaped as text", () => {
  const html = descriptorReuseHtml({ collisionCount: 1, collisions: [{ first: { slot: 0, path: "<img src=x>" }, second: { slot: 1, path: "a&b" } }] });
  assert.ok(html.includes("&lt;img src=x&gt;") && html.includes("a&amp;b"));
  assert.doesNotMatch(html, /<img/);
});

test("a refusal shows in the error line without echoing the input, and an edit retires the verdict", () => {
  const { elements, check } = setup();
  const body = `wpkh(${X}/<0;1>/*)`;
  let { out, error } = check(`${body}#aaaaaaaa`);
  assert.equal(out, "");
  assert.match(error, /^checksum:/);
  const xprv = master.derive("m/84'/0'/0'").privateExtendedKey;
  ({ out, error } = check(`wpkh(${xprv}/0/*)`));
  assert.equal(out, "");
  assert.ok(error && !error.includes(xprv), "a private key is refused and never repeated");
  ({ out } = check(body));
  assert.ok(out);
  elements["descriptor-reuse-text"].listeners.input();
  assert.equal(elements["descriptor-reuse-out"].innerHTML, "");
  assert.equal(elements["descriptor-reuse-error"].textContent, "");
});

test("the section ships in every build and is wired without a preview gate", () => {
  const shell = read("src/shell.html");
  assert.ok(shell.includes("<summary>Check a descriptor for key reuse</summary>"));
  const release = applyPreviewBlocks(shell, false);
  for (const id of ["descriptor-reuse-options", "descriptor-reuse-text", "descriptor-reuse-go", "descriptor-reuse-error", "descriptor-reuse-out"]) {
    assert.match(release, new RegExp(`id="${id}"`), `a release build keeps #${id}`);
  }
  // Inside the PSBT Inspector's card, after its actions.
  const card = release.slice(release.indexOf('id="psbt-card"'), release.indexOf('id="psbted-card"'));
  assert.ok(card.indexOf('id="psbt-wipe"') < card.indexOf('id="descriptor-reuse-options"'));
  const app = read("src/js/app.js");
  const callAt = app.indexOf("initDescriptorReuseCheck(document, { onChange: hodlSyncPsbtControls })");
  assert.ok(callAt > 0, "the check is wired");
  assert.doesNotMatch(app.slice(Math.max(0, callAt - 200), callAt), /__ENTROPYLAB_PREVIEW__/, "the wiring is ungated");
  // Second line of defence: a stray call with no markup wires nothing and
  // touches nothing.
  const asked = [];
  assert.doesNotThrow(() => initDescriptorReuseCheck({ getElementById: (id) => { asked.push(id); return null; } }, { onChange: () => assert.fail("onChange ran") }));
  assert.deepEqual(asked, ["descriptor-reuse-text", "descriptor-reuse-go", "descriptor-reuse-out", "descriptor-reuse-error"]);
});

test("every edit and check tells the page, so Clear Inspectors can enable", () => {
  const elements = Object.fromEntries(["descriptor-reuse-text", "descriptor-reuse-go", "descriptor-reuse-out", "descriptor-reuse-error"].map((id) => [id, fakeElement()]));
  let calls = 0;
  initDescriptorReuseCheck({ getElementById: (id) => elements[id] ?? null }, { onChange: () => { calls++; } });
  elements["descriptor-reuse-text"].value = `wpkh(${X}/<0;1>/*)`;
  elements["descriptor-reuse-text"].listeners.input();
  elements["descriptor-reuse-go"].listeners.click();
  elements["descriptor-reuse-text"].value = "wpkh(bad)#aaaaaaaa";
  elements["descriptor-reuse-go"].listeners.click();
  assert.equal(calls, 3);
  const app = read("src/js/app.js");
  const sync = app.slice(app.indexOf("function hodlSyncPsbtControls("), app.indexOf("\nfunction ", app.indexOf("function hodlSyncPsbtControls(") + 1));
  assert.match(sync, /anything \|\|= Boolean\(value\("descriptor-reuse-text"\) \|\| document\.getElementById\("descriptor-reuse-out"\)\?\.childElementCount\);\s*enable\("psbt-wipe", anything\);/);
});

test("Clear Inspectors and the session-end sweep clear the pasted descriptor and its verdict", () => {
  const app = read("src/js/app.js");
  const end = app.slice(app.indexOf("function hodlEndPsbtSession("), app.indexOf("\nfunction ", app.indexOf("function hodlEndPsbtSession(") + 1));
  assert.match(end, /"descriptor-reuse-text"/);
  assert.match(end, /"descriptor-reuse-out", "descriptor-reuse-error"/);
  const sweep = app.slice(app.indexOf("function hodlInitSecretFieldAutoClear("), app.indexOf("\nfunction ", app.indexOf("function hodlInitSecretFieldAutoClear(") + 1));
  assert.match(sweep, /"nonce-text", "descriptor-reuse-text"\]/);
  assert.match(sweep, /for \(let id of \["descriptor-reuse-out", "descriptor-reuse-error"\]\)/);
});

test("the module never talks to the network", () => {
  assert.doesNotMatch(read("src/js/descriptor-reuse-ui.js"), /\bfetch\b|XMLHttpRequest|WebSocket|sendBeacon/);
});
