import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadAppFunctions } from "./app-slice-harness.mjs";
import { createSecureSession, sessionGet } from "../src/js/secure-entry.js";

const app = readFileSync(new URL("../src/js/app.js", import.meta.url), "utf8");

const functionBody = (name) => {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} is missing`);
  const open = app.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < app.length; i += 1) {
    if (app[i] === "{") depth += 1;
    else if (app[i] === "}") {
      depth -= 1;
      if (depth === 0) return app.slice(start, i + 1);
    }
  }
  throw new Error(`${name} has no end`);
};

test("the masked key template renders the scan host", () => {
  const at = app.indexOf('<input id="secure-key"');
  assert.ok(at >= 0, "the masked key field is missing");
  const branch = app.slice(at, app.indexOf("hodlRenderPassphraseKeyboard();", at));
  assert.match(branch, /\$\{hodlKeyScanHostMarkup\(\)\}/);
  assert.match(branch, /hodlBindKeyScan\(\)/);
});

test("hodlBindKeyScan mounts a key panel with the bytes handler", () => {
  const body = functionBody("hodlBindKeyScan");
  assert.match(body, /accept: "wif"/);
  assert.match(body, /onKey: hodlKeyScanLoad/);
  assert.match(body, /replacesKey: hodlKeyScanReplaces/);
  assert.match(body, /beforeOpen: hodlKeyScanBeforeOpen/);
  const take = body.indexOf("let openNow = hodlKeyScanOpenAfterMount;");
  const clear = body.indexOf("hodlKeyScanOpenAfterMount = false;", take);
  assert.ok(take >= 0 && take < clear && clear < body.indexOf("if (!module || hodlKeyScan"), "the flag is cleared before the bail");
  assert.match(body, /if \(openNow && document\.visibilityState !== "hidden"\) try \{ hodlKeyScan\.open\(\); \} catch \{\}/);
});

test("End Session clears the key scan open request", () => {
  const wipeStart = app.indexOf("let clearSecretFields = () => {");
  assert.ok(wipeStart >= 0, "clearSecretFields is missing");
  const wipe = app.slice(wipeStart, app.indexOf("\n  };", wipeStart));
  assert.match(wipe, /hodlKeyScanOpenAfterMount = false/);
});

const loadKeyScan = async (overrides = {}) => {
  const session = createSecureSession();
  const state = { id: 1, fields: { keyKind: "hex-key", privateKeys: { wif: "old-wif", "hex-key": "old-hex", minikey: "old-mini", brain: "old-brain" } } };
  const modes = [];
  const previews = [];
  const doc = {
    getElementById: (id) => (id === "secure-key" ? {} : null),
    querySelector: (selector) => (selector === 'input[name="kk"]:checked' ? { value: "wif" } : null),
  };
  const mod = await loadAppFunctions(
    ["hodlKeyScanLoad", "hodlSecureKeyEntry", "hodlSecureKeyOf"],
    {
      stubs: {
        hodlSecureKeyActive: () => true,
        hodlKeyMode: "key",
        hodlKeys: [state],
        hodlActiveKey: 0,
        hodlSecureSession: session,
        document: doc,
        hodlPrivateKeyValues: (fields) => fields.privateKeys,
        hodlInvalidateLiveKeyResult: () => {},
        hodlSetMode: (mode) => modes.push(mode),
        hodlQueueMasterFingerprintPreview: (delay) => previews.push(delay),
        ...overrides.stubs,
      },
    },
  );
  return { mod, session, state, modes, previews, doc };
};

test("hodlKeyScanLoad puts the WIF's code points in the key's vault", async () => {
  const { mod, session, state, modes, previews } = await loadKeyScan();
  const wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
  const bytes = Uint8Array.from(wif, (character) => character.charCodeAt(0));
  mod.hodlKeyScanLoad(bytes);
  const owner = mod.hodlSecureKeyOf(state);
  const entry = sessionGet(session, owner, "key");
  assert.ok(entry, "the key entry was not created");
  assert.equal(entry.vault.text(), wif);
  assert.equal(state.fields.keyKind, "wif");
  for (const format of ["wif", "hex-key", "minikey", "brain"]) assert.equal(state.fields.privateKeys[format], "", format);
  assert.deepEqual(modes, ["key"]);
  assert.deepEqual(previews, [0]);
  bytes.fill(0);
});

test("hodlKeyScanLoad throws, changing nothing, when it cannot load", async () => {
  const wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
  const bytes = () => Uint8Array.from(wif, (character) => character.charCodeAt(0));
  const off = await loadKeyScan({ stubs: { hodlSecureKeyActive: () => false } });
  assert.throws(() => off.mod.hodlKeyScanLoad(bytes()));
  assert.equal(off.state.fields.keyKind, "hex-key");
  assert.equal(off.session.entries.size, 0);

  const absent = await loadKeyScan({ stubs: { document: { getElementById: () => null, querySelector: () => ({ value: "wif" }) } } });
  assert.throws(() => absent.mod.hodlKeyScanLoad(bytes()));
  assert.equal(absent.state.fields.keyKind, "hex-key");
  assert.equal(absent.session.entries.size, 0);

  const ascii = await loadKeyScan();
  assert.throws(() => ascii.mod.hodlKeyScanLoad(Uint8Array.from([0x35, 0x80])));
  assert.equal(ascii.state.fields.keyKind, "hex-key");
  assert.equal(ascii.session.entries.size, 0);
});
