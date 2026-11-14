import { test } from "node:test";
import assert from "node:assert/strict";
import { KEY_VAULT_MAX_KEYS, parseKeyVault, serializeKeyVault } from "../src/js/keymanager.js";
import { mergeLogHistory, wipeDocument } from "../src/js/journal.js";
import { loadAppFunctions } from "./app-slice-harness.mjs";

// Security contract: accepted inventory changes remain exportable under the
// format's existing limits; a rejected change preserves all recovery inputs.
async function harness() {
  const statuses = [], decisions = { preview: async () => "derive", journalOpen: true };
  const variables = ["hodlKeys", "hodlKeyManagerPending", "hodlKeyManagerIgnored", "hodlKeyManagerIds", "hodlKeyManagerActiveId", "hodlActiveKey", "hodlNextKeyId"];
  const api = await loadAppFunctions([
    "hodlNewKeyState", "hodlNewLabState", "hodlKeyManagerStates", "hodlKeyManagerEntry",
    "hodlKeyManagerImportFile", "hodlKeyManagerIgnore", "hodlKeyManagerRestoreIgnored", "hodlKeyManagerDetachFromStation", "hodlCommitDerivedKey", ...variables,
  ], {
    settable: variables,
    stubs: {
      hodlTText: (text, values = {}) => text.replace(/\{(\w+)\}/g, (_, key) => String(values[key] ?? "")),
      hodlDefaultCoinType: () => 0, hodlNetworkDefault: "mainnet", hodlDefaultKeyName: number => `Key ${number}`,
      hodlJournalUnlocked: () => decisions.journalOpen, hodlJournalGeneration: 0, hodlJournalKeys: {}, hodlJournalMaxFileLength: 4 * 1024 * 1024,
      hodlActiveDerivation: null, hodlJournalKeyDerivation: null, document: { getElementById: () => null },
      hodlJournalOpenExport: async content => ({ kind: "key-manager", content }),
      hodlKeyManagerDecision: options => decisions.preview(options), hodlKeyManagerDeriveInputs: async () => {},
      hodlKeyManagerStatus: (message, error) => statuses.push({ message, error }), hodlJournalLog() {},
      hodlKeyManagerRender() {}, hodlRenderKeyTabs() {}, hodlRestoreKey() {}, hodlDisposeDroppedWallets() {},
      hodlReleaseKeyConsumers() {}, hodlWipeUnsharedWalletRows() {}, hodlCaptureKey() {}, hodlElement: () => ({ children: [] }),
      hodlPassphraseText: value => ArrayBuffer.isView(value) ? new TextDecoder().decode(value) : String(value ?? ""),
      hodlVanityApplying: false,
    },
  });
  api.hodlKeys.push(api.hodlNewLabState());
  api.__set.hodlActiveKey(0);
  const input = (name = "Saved inputs", derived = false) => {
    const state = api.hodlNewKeyState(name);
    state.fields.seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    state.fields.pass = new Uint8Array([19, 23]);
    state.needsDerivation = !derived;
    if (derived) state.result = { masterIdentity: `wallet-${state.id}`, network: "mainnet" };
    return state;
  };
  const add = (count, collection, derived = false) => {
    for (let i = 0; i < count; i++) collection.push(input(`Saved ${i}`, derived));
  };
  const portable = name => ({ name, fields: { seed: "saved recovery input", pass: "saved passphrase" } });
  const file = (keys, ignored = []) => {
    const text = serializeKeyVault(keys, ignored);
    return { size: text.length, text: async () => text };
  };
  const backup = () => parseKeyVault(serializeKeyVault(api.hodlKeyManagerStates().map(api.hodlKeyManagerEntry), api.hodlKeyManagerIgnored.map(api.hodlKeyManagerEntry)));
  const inventory = () => JSON.stringify([api.hodlKeys, api.hodlKeyManagerPending, api.hodlKeyManagerIgnored, [...api.hodlKeyManagerIds], api.hodlKeyManagerActiveId, api.hodlActiveKey, api.hodlNextKeyId]);
  return { api, statuses, decisions, input, add, portable, file, backup, inventory };
}

test("an individually valid import cannot overflow existing station inputs", async () => {
  const h = await harness(), { api } = h;
  h.add(1, api.hodlKeys, true);
  const before = h.inventory();
  await api.hodlKeyManagerImportFile(h.file(Array.from({ length: KEY_VAULT_MAX_KEYS }, () => h.portable("Imported"))));
  assert.equal(api.hodlKeyManagerPending.length, 0, "the import exceeded the format's combined active-input limit");
  assert.equal(h.inventory(), before);
  assert.equal(h.statuses.at(-1).error, true);
  assert.equal(h.backup().keys.length, 1);
});

test("successive valid imports accept the boundary and atomically reject the next input", async () => {
  const h = await harness(), { api } = h;
  await api.hodlKeyManagerImportFile(h.file(Array.from({ length: 60 }, () => h.portable("First"))));
  await api.hodlKeyManagerImportFile(h.file(Array.from({ length: 40 }, () => h.portable("Second"))));
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
  const before = h.inventory();
  await api.hodlKeyManagerImportFile(h.file([h.portable("Overflow")]));
  assert.equal(api.hodlKeyManagerPending.length, KEY_VAULT_MAX_KEYS);
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

test("an import overflowing the archive installs neither active nor archived inputs", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeyManagerIgnored);
  const before = h.inventory();
  await api.hodlKeyManagerImportFile(h.file([h.portable("Active")], [h.portable("Archived")]));
  assert.equal(api.hodlKeyManagerPending.length, 0, "a rejected file partially installed its active inputs");
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS);
});

test("import capacity is checked again after its asynchronous preview", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeyManagerPending);
  let before;
  h.decisions.preview = async () => {
    api.hodlKeyManagerPending.push(h.input("Arrived during preview"));
    before = h.inventory();
    return "derive";
  };
  await api.hodlKeyManagerImportFile(h.file([h.portable("Late import")]), true);
  assert.equal(api.hodlKeyManagerPending.length, KEY_VAULT_MAX_KEYS);
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

test("a full archive refuses an archive action without removing or wiping its source", async () => {
  const h = await harness(), { api } = h, source = h.input();
  api.hodlKeyManagerPending.push(source);
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeyManagerIgnored);
  const before = h.inventory();
  api.hodlKeyManagerIgnore(source);
  assert.equal(api.hodlKeyManagerPending[0], source);
  assert.equal(h.inventory(), before);
  assert.equal(h.statuses.at(-1).error, true);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS);
});

test("a full active inventory refuses restore without losing the archived source", async () => {
  const h = await harness(), { api } = h, source = h.input();
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeys, true);
  api.hodlKeyManagerIgnored.push(source);
  const before = h.inventory();
  api.hodlKeyManagerRestoreIgnored(source);
  assert.equal(api.hodlKeyManagerIgnored[0], source);
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

test("archive and restore can move the last available slot in each direction", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeyManagerPending);
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeyManagerIgnored);
  const source = api.hodlKeyManagerPending[0], original = api.hodlKeyManagerEntry(source);
  api.hodlKeyManagerIgnore(source);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS - 1);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS);
  const archived = api.hodlKeyManagerIgnored.at(-1);
  assert.deepEqual(archived.fields, original.fields);
  api.hodlKeyManagerRestoreIgnored(archived);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS - 1);
  assert.equal(api.hodlKeyManagerPending.at(-1).fields.seed, original.fields.seed);
  assert.deepEqual([...api.hodlKeyManagerPending.at(-1).fields.pass], [19, 23]);
});

test("exact reuse refuses a full archive before consuming imported recovery inputs", async () => {
  const h = await harness(), { api } = h, existing = h.input("Existing", true), source = h.input("Imported");
  api.hodlKeys.push(existing);
  api.hodlKeyManagerPending.push(source);
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeyManagerIgnored);
  const lab = api.hodlKeys[0];
  lab.importedKeyId = source.id;
  lab.fields = structuredClone(source.fields);
  lab.result = { ...existing.result };
  const before = h.inventory();
  assert.throws(() => api.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: existing.result }), { name: "Error" });
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().keys.length, 2);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS);
});

test("exact reuse can fill the final archive slot while preserving the existing key", async () => {
  const h = await harness(), { api } = h, existing = h.input("Existing", true), source = h.input("Imported");
  api.hodlKeys.push(existing);
  api.hodlKeyManagerPending.push(source);
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeyManagerIgnored);
  const lab = api.hodlKeys[0], result = existing.result;
  lab.importedKeyId = source.id;
  lab.fields = structuredClone(source.fields);
  lab.result = { ...result };
  api.hodlCommitDerivedKey("derive", { kind: "reuse", state: existing, previousResult: result });
  assert.equal(api.hodlKeys[api.hodlActiveKey], existing);
  assert.equal(existing.result, result);
  assert.equal(api.hodlKeyManagerPending.length, 0);
  assert.equal(h.backup().ignoredKeys.length, KEY_VAULT_MAX_KEYS);
  assert.equal(api.hodlKeyManagerIgnored.at(-1).fields.seed, lab.fields.seed);
});

test("a new station key cannot overflow backups or consume its unfinished source", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeys, true);
  const lab = api.hodlKeys[0];
  lab.fields.seed = "unfinished recovery input";
  lab.result = { masterIdentity: "new-wallet", network: "mainnet" };
  const before = h.inventory();
  assert.throws(() => api.hodlCommitDerivedKey(), { name: "Error" });
  assert.equal(h.inventory(), before);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

test("deriving a pending input or updating a key at capacity does not count it twice", async () => {
  const h = await harness(), { api } = h, source = h.input("Imported");
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeys, true);
  api.hodlKeyManagerPending.push(source);
  const lab = api.hodlKeys[0];
  lab.importedKeyId = source.id;
  lab.fields = structuredClone(source.fields);
  lab.result = { masterIdentity: "new-wallet", network: "mainnet" };
  api.hodlCommitDerivedKey("derive", { kind: "append" });
  const added = api.hodlKeys[api.hodlActiveKey];
  assert.equal(added.name, "Imported");
  assert.equal(api.hodlKeyManagerPending.length, 0);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
  const edit = api.hodlKeys[0];
  edit.editSourceId = added.id;
  edit.fields = structuredClone(added.fields);
  edit.result = { masterIdentity: "updated-wallet", network: "mainnet" };
  api.__set.hodlActiveKey(0);
  api.hodlCommitDerivedKey("update");
  assert.equal(api.hodlKeys[api.hodlActiveKey].id, added.id);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

async function unlockHarness(stationCount, restoredCount, { legacy = false } = {}) {
  const entry = { input: "incoming raw input", phrase: "incoming recovery phrase" };
  const keys = Array.from({ length: restoredCount }, () => ({ fields: { seed: "incoming key input" } }));
  const opened = { keys: { passwordProtected: true }, doc: { entries: [entry], ...(legacy ? {} : { backup: { keyManager: { keys, ignoredKeys: [] } } }) } };
  const previous = { entries: [{ phrase: "previous journal contents" }] };
  const station = Array.from({ length: stationCount }, (_, index) => ({ id: index + 1, fields: { seed: "live station input" }, result: { masterIdentity: `live-${index}` } }));
  // These old pending inputs are replaced on a successful open; only the
  // live station must be counted alongside the incoming backup.
  const pending = Array.from({ length: KEY_VAULT_MAX_KEYS }, (_, index) => ({ id: stationCount + index + 1, fields: { seed: "old journal input" } }));
  const events = [], errors = [];
  const fields = new Map(["journal-open-password", "journal-file", "journal-open-ready", "journal-unlock"].map(id => [id, { value: "", focus() {} }]));
  let api;
  api = await loadAppFunctions(["hodlJournalUnlock", "hodlJournalDoc", "hodlJournalKeys", "hodlJournalFileText", "hodlJournalUnlockBusy"], {
    settable: ["hodlJournalDoc", "hodlJournalKeys", "hodlJournalFileText", "hodlJournalUnlockBusy"],
    stubs: {
      document: { getElementById: id => fields.get(id) ?? null },
      hodlKeys: [{ id: 0, isLab: true, result: { masterIdentity: "parked draft" } }, ...station],
      hodlKeyManagerPending: pending, hodlKeyManagerIgnored: [],
      hodlActiveDerivation: null, hodlJournalKeyDerivation: null, hodlCaptureKey() {},
      hodlJournalMergeLogHistory: mergeLogHistory,
      hodlJournalOpenDocument: async () => opened,
      hodlJournalDiscardOpened: value => wipeDocument(value.doc),
      hodlJournalSetGateBusy: value => api.__set.hodlJournalUnlockBusy(value),
      hodlJournalError: value => errors.push(value), hodlTText: value => value,
      hodlKeyManagerReset: () => events.push("reset"), hodlJournalWipeNotebook: () => events.push("wipe"),
      hodlJournalRestoreBackup: value => events.push(value),
      hodlJournalHideEditor() {}, hodlJournalShowWork() {}, hodlShowJournalTool() {}, hodlJournalLog() {},
      wipeJournal() {}, hodlJournal: { log: [], logDiscarded: 0 },
    },
  });
  api.__set.hodlJournalDoc(previous);
  api.__set.hodlJournalKeys({ previous: true });
  api.__set.hodlJournalFileText("selected complete backup");
  return { api, opened, previous, station, pending, entry, keys, events, errors };
}

test("opening a complete backup refuses combined overflow before clearing current data", async () => {
  const h = await unlockHarness(KEY_VAULT_MAX_KEYS, 1), before = JSON.stringify([h.previous, h.station, h.pending]);
  const incoming = h.keys[0];
  await h.api.hodlJournalUnlock();
  assert.deepEqual(h.events, [], "opening an over-capacity backup destroyed or installed data");
  assert.equal(h.api.hodlJournalDoc, h.previous);
  assert.equal(JSON.stringify([h.previous, h.station, h.pending]), before);
  assert.equal(h.entry.phrase, "", "the rejected opened document retained its recovery phrase");
  assert.equal(incoming.fields.seed, "", "the rejected opened backup retained its key inputs");
  assert.equal(h.opened.doc.backup, null);
  assert.ok(h.errors.at(-1));
});

test("opening a complete backup counts only retained station keys and accepts the boundary", async () => {
  const h = await unlockHarness(KEY_VAULT_MAX_KEYS - 1, 1), backup = h.opened.doc.backup;
  await h.api.hodlJournalUnlock();
  assert.deepEqual(h.events, ["reset", "wipe", backup]);
  assert.equal(h.api.hodlJournalDoc, h.opened.doc);
  assert.equal(h.entry.phrase, "incoming recovery phrase");
  assert.equal(h.keys[0].fields.seed, "incoming key input");
});

test("a legacy journal without backed-up key inputs still opens at station capacity", async () => {
  const h = await unlockHarness(KEY_VAULT_MAX_KEYS, 0, { legacy: true });
  await h.api.hodlJournalUnlock();
  assert.deepEqual(h.events, ["reset", "wipe"]);
  assert.equal(h.api.hodlJournalDoc, h.opened.doc);
  assert.equal(h.entry.phrase, "incoming recovery phrase");
});


test("without Journal, a new station key is not limited by the backup format", async () => {
  const h = await harness(), { api } = h;
  h.decisions.journalOpen = false;
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeys, true);
  const lab = api.hodlKeys[0];
  lab.fields.seed = "unfinished recovery input";
  lab.result = { masterIdentity: "new-wallet", network: "mainnet" };
  assert.doesNotThrow(() => api.hodlCommitDerivedKey());
  assert.equal(api.hodlKeys.filter(state => !state.isLab).length, KEY_VAULT_MAX_KEYS + 1);
  assert.equal(api.hodlKeys[api.hodlActiveKey].fields.seed, "unfinished recovery input");
});

test("meaningful resultless station inputs remain in the Journal inventory", async () => {
  const h = await harness(), { api } = h;
  const input = h.input("Result withdrawn"); delete input.needsDerivation;
  const empty = api.hodlNewKeyState("Empty tab"); empty.fields.addressRange = "20";
  api.hodlKeys.push(input, empty);
  assert.deepEqual(api.hodlKeyManagerStates(), [input]);
  assert.equal(h.backup().keys[0].fields.seed, input.fields.seed);
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeys, true);
  const lab = api.hodlKeys[0]; lab.result = { masterIdentity: "one-too-many", network: "mainnet" };
  const before = h.inventory();
  assert.throws(() => api.hodlCommitDerivedKey());
  assert.equal(h.inventory(), before);
});

test("detaching a resultless input at capacity keeps it unverified and exportable", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS - 1, api.hodlKeys, true);
  const input = h.input("Result withdrawn"); delete input.needsDerivation;
  api.hodlKeys.push(input); api.__set.hodlActiveKey(api.hodlKeys.indexOf(input));
  api.hodlKeyManagerDetachFromStation(input);
  assert.equal(api.hodlKeyManagerPending[0], input);
  assert.equal(input.needsDerivation, true);
  assert.equal(h.backup().keys.length, KEY_VAULT_MAX_KEYS);
});

test("detaching cannot move or drop recovery inputs from an over-capacity inventory", async () => {
  const h = await harness(), { api } = h;
  h.add(KEY_VAULT_MAX_KEYS, api.hodlKeys, true);
  const input = h.input("Result withdrawn"); delete input.needsDerivation;
  api.hodlKeys.push(input); api.__set.hodlActiveKey(api.hodlKeys.indexOf(input));
  const before = h.inventory();
  api.hodlKeyManagerDetachFromStation(input);
  assert.equal(h.inventory(), before);
  assert.equal(h.statuses.at(-1).error, true);
});


test("removing an empty station tab does not create an empty pending input", async () => {
  const h = await harness(), { api } = h;
  const empty = api.hodlNewKeyState("Empty tab");
  api.hodlKeys.push(empty); api.__set.hodlActiveKey(api.hodlKeys.indexOf(empty));
  api.hodlKeyManagerDetachFromStation(empty);
  assert.equal(api.hodlKeys.includes(empty), false);
  assert.equal(api.hodlKeyManagerPending.length, 0);
  assert.equal(h.backup().keys.length, 0);
});
