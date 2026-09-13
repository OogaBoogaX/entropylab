import { test } from "node:test";
import assert from "node:assert/strict";
import { runInNewContext } from "node:vm";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  KEY_VAULT_FORMAT,
  KEY_VAULT_MAX_KEYS,
  KEY_VAULT_VERSION,
  keyVaultIdentity,
  parseKeyVault,
  serializeKeyVault,
} from "../src/js/keymanager.js";
import { createDocument, openExport, sealExport } from "../src/js/journal.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const password = "correct horse battery staple";

function stationHarness(keys, pending, ignored = []) {
  const source = read("src/js/app.js");
  const slice = (name, next) => source.slice(source.indexOf(`function ${name}(`), source.indexOf(`function ${next}(`));
  const calls = [];
  const context = {
    hodlKeys: keys, hodlKeyManagerPending: pending, hodlKeyManagerIgnored: ignored,
    hodlActiveKey: 0, keyVaultIdentity,
    hodlJournalLog: (...args) => calls.push(args),
    hodlRenderKeyTabs: () => calls.push(["tabs"]),
    hodlKeyManagerRender: () => calls.push(["manager"]),
    hodlShowWorkspace: (id) => calls.push(["workspace", id]),
  };
  runInNewContext(slice("hodlKeyManagerStates", "hodlKeyManagerEntry") +
    slice("hodlKeyManagerUseAllInStation", "hodlKeyManagerIgnore"), context);
  return { context, calls };
}

test("Add all transfers pending keys once, preserving existing and ignored keys", () => {
  const existing = key(), first = key({ result: { masterFingerprint: "11111111" } }),
    second = key({ result: { masterFingerprint: "22222222" } }), ignored = key({ name: "Ignored" });
  const lab = { isLab: true, fields: { seed: "unfinished input" } };
  const keys = [lab, existing], pending = [first, second], ignoredKeys = [ignored];
  const before = JSON.stringify([first, second, lab, ignored]);
  const { context, calls } = stationHarness(keys, pending, ignoredKeys);
  context.hodlKeyManagerUseAllInStation();
  assert.deepEqual(keys, [lab, existing, first, second]);
  assert.equal(pending.length, 0);
  assert.equal(context.hodlActiveKey, 2);
  assert.equal(JSON.stringify([first, second, lab, ignored]), before);
  assert.deepEqual(ignoredKeys, [ignored]);
  assert.deepEqual(calls, [
    ["key-manager-use", "11111111", "journal"], ["key-manager-use", "22222222", "journal"],
    ["tabs"], ["manager"], ["workspace", "calc"],
  ]);
  context.hodlKeyManagerUseAllInStation();
  assert.equal(keys.length, 4);
  assert.equal(calls.length, 5, "repeated activation does nothing");
});

test("Add all ignores duplicate identities and does nothing without pending keys", () => {
  const existing = key(), duplicate = key({ name: "Duplicate" });
  const { context, calls } = stationHarness([existing], [duplicate]);
  context.hodlKeyManagerUseAllInStation();
  assert.equal(context.hodlKeys.length, 1);
  assert.equal(context.hodlActiveKey, 0);
  assert.deepEqual(calls, []);
  const empty = stationHarness([], []);
  empty.context.hodlKeyManagerUseAllInStation();
  assert.deepEqual(empty.calls, []);
});

test("Add all is disabled initially and refreshed from available managed keys", () => {
  assert.match(read("src/shell.html"), /id="journal-keymanager-add-all" type="button" disabled>Add all to Key Station/);
  const source = read("src/js/app.js");
  assert.match(source, /addAll\.disabled = !states\.some\(\(state\) => !state\.needsDerivation && !hodlKeys\.includes\(state\)\)/);
  assert.match(source, /addAll\.onclick = hodlKeyManagerUseAllInStation/);
});

function key(overrides = {}) {
  return {
    id: 7,
    number: 2,
    name: "Cold storage",
    createdAt: "2026-09-03T12:00:00.000Z",
    fields: { derivationPath: "m/84'/0'/0'/0/0", seed: "user supplied words" },
    result: { masterFingerprint: "deadbeef", rootXpub: "xpub-example", rootXprv: "xprv-example" },
    reveal: true,
    error: "stale error",
    ...overrides,
  };
}

test("Key Manager payloads round-trip and clear transient UI state", () => {
  const text = serializeKeyVault([key()], [key({ id: 8, name: "Ignored", result: { masterFingerprint: "a1b2c3d4" } })]);
  const raw = JSON.parse(text);
  assert.equal(raw.format, KEY_VAULT_FORMAT);
  assert.equal(raw.version, KEY_VAULT_VERSION);
  assert.equal(raw.keys[0].reveal, false);
  assert.equal(raw.keys[0].error, "");
  assert.equal(raw.keys[0].errorSpec, undefined);
  assert.equal(raw.ignoredKeys[0].name, "Ignored");
  assert.deepEqual(parseKeyVault(text), { keys: raw.keys, ignoredKeys: raw.ignoredKeys });
  assert.equal(raw.keys[0].result, null);
  assert.equal(raw.keys[0].needsDerivation, true);
  assert.equal(keyVaultIdentity(raw.keys[0]), "", "file claims cannot supply a trusted identity");
});

test("Key Manager payload validation rejects malformed or oversized files", () => {
  assert.throws(() => parseKeyVault("not json"), /not valid Key Manager JSON/);
  assert.throws(() => parseKeyVault('{"format":"other","version":1,"keys":[]}'), /not a supported/);
  assert.throws(() => serializeKeyVault([{ name: "missing state" }]), /invalid key/);
  assert.throws(() => serializeKeyVault(Array.from({ length: KEY_VAULT_MAX_KEYS + 1 }, () => key())), /too many keys/);
  assert.throws(() => serializeKeyVault([key({ isLab: true })]), /invalid key/);
});

test(".elkeys reuse deterministic Journal encryption and the Journal password", async () => {
  const journal = await createDocument(password, password);
  const content = serializeKeyVault([key()]);
  const first = await sealExport("key-manager", content, journal.keys);
  const second = await sealExport("key-manager", content, journal.keys);
  assert.deepEqual(second, first);
  const opened = await openExport(JSON.stringify(first), journal.keys);
  assert.equal(opened.kind, "key-manager");
  assert.equal(parseKeyVault(opened.content).keys[0].fields.seed, "user supplied words");
  assert.equal(parseKeyVault(opened.content).keys[0].result, null);
});

test("Key Manager has no entropy, network, or browser-storage primitive", () => {
  const source = read("src/js/keymanager.js").replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(source, /Math\.random|crypto\.getRandomValues|fetch\b|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB/);
});

test("the Journal integration keeps imported keys pending until explicit use", () => {
  const source = read("src/js/app.js");
  assert.match(source, /hodlKeyManagerPending\.push\(state\)/);
  assert.match(source, /function hodlKeyManagerUseInStation\(state\)[\s\S]*hodlKeyManagerPending\.splice\(pending, 1\);[\s\S]*hodlKeys\.push\(state\)/);
  assert.match(source, /function hodlDeleteActiveKey\(\)[\s\S]*hodlJournalUnlocked\(\)[\s\S]*hodlKeyManagerDetachFromStation\(state\)/);
  assert.match(source, /hodlJournalSealExport\("key-manager", content, hodlJournalKeys\)/);
  assert.match(source, /let text = await file\.text\(\);\s*if \(generation !== hodlJournalGeneration\) return;\s*let opened = await hodlJournalOpenExport\(text, hodlJournalKeys\)/);
});
