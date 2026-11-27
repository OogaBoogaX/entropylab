// End Session wipes every secret field even when one wipe step throws
// (red-team part13 #3). The tail of clearSecretFields is guarded by station.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");

const loadInit = (stubs) => {
  const start = app.indexOf("function hodlInitSecretFieldAutoClear(");
  assert.ok(start >= 0, "hodlInitSecretFieldAutoClear is missing");
  let depth = 0;
  for (let index = app.indexOf("{", start); index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) {
      const source = app.slice(start, index + 1);
      const names = Object.keys(stubs);
      const values = names.map((name) => stubs[name]);
      return new Function(...names, `${source}; return hodlInitSecretFieldAutoClear;`)(...values);
    }
  }
  throw new Error("hodlInitSecretFieldAutoClear has no end");
};

const noop = () => {};
const makeElement = (id) => ({ id, value: "secret", innerHTML: "secret", textContent: "secret", dataset: {}, style: { removeProperty: noop }, click: noop });

const makeStubs = (element, overrides = {}) => {
  const stubs = {
    addEventListener: (type, handler) => { if (type === "pagehide") stubs.clear = handler; },
    document: { getElementById: element, querySelector: () => null, querySelectorAll: () => [] },
    hodlKeyManagerCancelDerivation: noop,
    hodlInvalidateDerivation: noop,
    hodlLowEntropyConfirm: null,
    hodlFingerprintCollisionConfirm: null,
    hodlJournalKeyImportConfirm: null,
    hodlPsbtWipeMem: noop,
    hodlBip85WipeMem: noop,
    hodlSpWipeMem: noop,
    hodlBip47WipeMem: noop,
    hodlLnWipeMem: noop,
    hodlWalletResult: null,
    hodlKeys: [],
    hodlKeyManagerPending: [],
    hodlCommittedResults: new Map(),
    hodlWipeWalletKeys: noop,
    hodlJournalWipeMem: noop,
    hodlNewLabState: () => ({}),
    hodlNewKeyState: () => ({}),
    hodlNewMsigLabState: () => ({}),
    hodlNewMsigState: () => ({}),
    hodlMsigs: [],
    hodlRestoreMsig: noop,
    hodlClearPassphraseField: noop,
    hodlClearStationPassphrase: noop,
    hodlPsbtRetireAuditUploads: noop,
    hodlPsbtRetireInspectorUploads: noop,
    hodlPsbtClearSignerAudit: noop,
    hodlPsbtRetireRbfUploads: noop,
    hodlSyncPsbtControls: noop,
    hodlBip85Note: "",
    hodlRenderBip85Tabs: noop,
    hodlSyncBip85View: noop,
    hodlSpVerifyMatches: null,
    hodlSpSendLast: null,
    hodlPaintSpSession: noop,
    hodlSpNote: "",
    hodlVanityCancel: noop,
    hodlVanityGrinder: null,
    hodlVanityMatches: [],
    hodlVanityFound: 0,
    hodlVanityReveal: false,
    hodlVanityRun: null,
    hodlVanitySource: "",
    hodlVanityApplying: false,
    hodlSetVanityError: noop,
    hodlNote: (text) => text,
    hodlVanitySetStatus: noop,
    hodlVanitySyncSource: noop,
    hodlVanitySyncControls: noop,
    hodlRefreshMsigSessionPickers: noop,
    hodlRefreshStationKeyPickers: noop,
    hodlLastWordCache: new Map(),
    hodlSetWorkspaceError: noop,
    hodlKeyScan: null,
    hodlSeedPicker: null,
    hodlSecureDicePad: null,
    hodlDestroyPsbtScans: noop,
    hodlSeedScan: null,
    hodlSeedScanOpenAfterMount: false,
    hodlKeyScanOpenAfterMount: false,
    hodlDestroyTextScans: noop,
    hodlKeyScanModule: null,
    hodlPsbtScanModule: null,
    hodlTextScanModule: null,
    hodlBindKeyScan: noop,
    hodlBindSeedScan: noop,
    hodlBindPsbtScans: noop,
    hodlBindTextScans: noop,
    hodlSecureEntryConfirm: null,
    hodlSecureEntryEnd: noop,
    hodlSetMode: noop,
    hodlKeyMode: "key",
    hodlReleaseSecureKeyField: noop,
    hodlSyncWorkspaceCounts: noop,
  };
  return Object.assign(stubs, overrides);
};

test("a throw in one End Session wipe step does not skip the later fields", () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const stubs = makeStubs(element, { hodlRestoreMsig: () => { throw new Error("boom"); } });
  const init = loadInit(stubs);
  init();
  assert.ok(stubs.clear, "clearSecretFields was not registered");
  assert.doesNotThrow(() => stubs.clear());
  assert.equal(element("sp-key").value, "");
  assert.equal(element("ln-seed").value, "");
  assert.equal(element("psbt-text").value, "");
});

test("a throw clearing the PSBT passphrase does not skip the pasted PSBT wipe", () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const stubs = makeStubs(element, {
    hodlClearStationPassphrase: (id) => { if (id === "psbt-pass") throw new Error("boom"); },
  });
  const init = loadInit(stubs);
  init();
  assert.ok(stubs.clear, "clearSecretFields was not registered");
  assert.doesNotThrow(() => stubs.clear());
  assert.equal(element("psbt-text").value, "");
});

test("a throw painting the SP session does not skip the SP recipient wipe", () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const stubs = makeStubs(element, {
    hodlPaintSpSession: () => { throw new Error("boom"); },
  });
  const init = loadInit(stubs);
  init();
  assert.ok(stubs.clear, "clearSecretFields was not registered");
  assert.doesNotThrow(() => stubs.clear());
  assert.equal(element("sp-recipients").value, "");
});

test("a throw cancelling the vanity grinder does not skip the vanity output wipe", () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const stubs = makeStubs(element, {
    hodlVanityCancel: () => { throw new Error("boom"); },
  });
  const init = loadInit(stubs);
  init();
  assert.ok(stubs.clear, "clearSecretFields was not registered");
  assert.doesNotThrow(() => stubs.clear());
  assert.equal(element("vanity-out").innerHTML, "");
});

test("a throw refreshing the multisig pickers does not skip the output and last-word wipes", () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement(id));
    return elements.get(id);
  };
  const stubs = makeStubs(element, {
    hodlRefreshMsigSessionPickers: () => { throw new Error("boom"); },
  });
  const init = loadInit(stubs);
  init();
  assert.ok(stubs.clear, "clearSecretFields was not registered");
  const out = element("out");
  out.innerHTML = "secret";
  stubs.hodlLastWordCache.set("k", "secret");
  assert.doesNotThrow(() => stubs.clear());
  assert.equal(out.innerHTML, "");
  assert.equal(stubs.hodlLastWordCache.size, 0);
});
