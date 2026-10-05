// Field registry: every text-entry field in the shell is classified, and
// every secret-bearing one has a clearing path the tests can point at.
//
// The completeness sweep is the rule: add a field to src/shell.html without
// listing it in SECRET_FIELDS (with a clearing path) or PUBLIC_FIELDS (with
// a reason) and this suite fails. The clearing-path rows then pin WHERE the
// clear lives, so a refactor that drops one row's wiring fails here even
// when the targeted behavioral test was not watching that field.
// Run with `npm test` (part of the default and CI suites).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (file) => readFileSync(join(root, file), "utf8");
const app = read("src/js/app.js");
const shell = read("src/shell.html");
const expandable = read("src/js/expandable.js");
const psbtEditor = read("src/js/psbt-editor.js");

// A named top-level function body in app.js, for "this id is cleared in
// this function" probes.
const fnBody = (name) => {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} not found`);
  const realStart = app.slice(Math.max(0, start - 6), start) === "async " ? start - 6 : start;
  const next = app.indexOf("\nfunction ", start + 1);
  const asyncNext = app.indexOf("\nasync function ", start + 1);
  const end = Math.min(...[next, asyncNext].filter((value) => value >= 0));
  return app.slice(realStart, end);
};

const lifecycle = fnBody("hodlInitSecretFieldAutoClear");
const journalFields = fnBody("hodlJournalClearFields");
const journalWipe = fnBody("hodlJournalWipeMem");
const journalLock = fnBody("hodlJournalLock");
const msigRestore = fnBody("hodlRestoreMsig");

// One slice of source around a marker, for "the change handler that reads
// this file input resets it right there" probes.
const around = (source, marker, span = 500) => {
  const at = source.indexOf(marker);
  assert.ok(at >= 0, `marker not found: ${marker}`);
  return source.slice(at, at + span);
};

// id → probe. Every probe is a regex run against the named source; the row
// says in one sentence why the field is security-critical.
const CLEARING_PATHS = [
  {
    ids: ["dice", "hex", "bin", "base4", "base8", "base32", "base64", "seed", "seed-numbers", "key", "pass", "cards", "direct-cards"],
    why: "Key Station: raw entropy transcripts, seed words, passphrases, private keys",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`), `#${id} missing from the lifecycle field sweep`),
  },
  {
    ids: ["psbt-key", "psbt-pass", "psbt-text", "psbt-ax-transcript", "nonce-key", "nonce-pass", "nonce-text"],
    why: "PSBT/Nonce stations: session keys, pasted PSBTs (xprvs in proprietary fields), anti-exfil transcript",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`) && fnBody("hodlEndPsbtSession").includes(`"${id}"`), `#${id} missing from the PSBT lifecycle/session-end sweeps`),
  },
  {
    ids: ["bip85-key"],
    why: "BIP-85 parent root key (auto-filled from the session pick)",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`), `#${id} missing from the lifecycle sweep`),
  },
  {
    ids: ["sp-key", "sp-pass", "sp-recipients", "sp-send-vins", "sp-verify-vins", "sp-verify-outputs", "sp-label", "sp-payname"],
    why: "Silent Payments: session key/passphrase and per-input derivation detail",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`), `#${id} missing from the lifecycle sweep`),
  },
  {
    ids: ["ln-seed", "ln-pass"],
    why: "Lightning: aezeed cipher seed and passphrase",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`), `#${id} missing from the lifecycle sweep`),
  },
  {
    ids: ["codex32-shares"],
    why: "Codex32 MS1 shares and secrets typed by the user",
    probe: (id) => assert.ok(lifecycle.includes(`"${id}"`), `#${id} missing from the lifecycle sweep`),
  },
  {
    ids: ["journal-create-password", "journal-create-confirm", "journal-open-password", "journal-input", "journal-phrase", "journal-label", "journal-entry-notes", "journal-search", "journal-file"],
    why: "Journal: passwords, raw entropy input, seed phrases, entry text",
    probe: (id) => assert.ok(journalFields.includes(`"${id}"`), `#${id} missing from the journal field clear`),
  },
  {
    ids: ["journal-state-text", "journal-state-private"],
    why: "Session snapshot: with the private box ticked it holds the whole session's recovery texts",
    probe: (id) => {
      assert.ok(journalWipe.includes(`"${id}"`), `#${id} must be dropped by the journal Clear`);
      if (id === "journal-state-text") assert.match(journalLock, /stateText\.value = ""/, "Lock must empty the snapshot");
      else assert.match(journalLock, /privateBox\.checked = false/, "Lock must untick the private box");
    },
  },
  {
    ids: ["journal-notes-text", "journal-log-out"],
    why: "Session notepad and session log — free text; Lock drops them with the password (#522)",
    probe: (id) => {
      assert.ok(journalWipe.includes(`"${id}"`), `#${id} missing from the journal full wipe`);
      assert.match(journalLock, /wipeJournal\(hodlJournal\)/, "Lock must wipe the journal's in-memory session text");
      assert.match(journalLock, new RegExp(`getElementById\\("${id}"\\)`), `#${id} missing from the journal Lock`);
    },
  },
  {
    ids: ["msig-descriptor"],
    why: "MultiSig descriptor (watch-only, but a session's form does not survive page hide)",
    probe: (id) => assert.ok(msigRestore.includes(`"${id}"`) && /hodlMsigs\s*=\s*hodlMsigs\.map/.test(lifecycle), `#${id} must be re-rendered from a reset state on lifecycle`),
  },
  {
    ids: ["msig-x-0", "msig-x-1", "msig-x-2"],
    why: "MultiSig cosigner key fields (rebuilt from the tab state on restore)",
    probe: () => {
      assert.match(lifecycle, /hodlMsigs\s*=\s*hodlMsigs\.map/, "lifecycle must reset every multisig tab's state");
      assert.match(msigRestore, /hodlFillKeys\(state\.fields\.xpubs \|\| \[\], state\.fields\.specs\)/, "restore must rebuild the cosigner rows from that state");
    },
  },
  {
    ids: ["psbted-text"],
    why: "PSBT editor's working document (base64/hex; may embed an xprv)",
    probe: () => assert.match(psbtEditor, /\$\("psbted-wipe"\)\.onclick[\s\S]*?text\.value = ""[\s\S]*?\$\("psbted-compare-go"\)/, "the editor wipe must empty #psbted-text"),
  },
  {
    ids: ["psbted-compare-text"],
    why: "PSBT editor's comparison paste",
    probe: () => {
      assert.match(psbtEditor, /\$\("psbted-wipe"\)\.onclick[\s\S]*?compareText\.value = ""/, "the editor wipe must empty #psbted-compare-text");
      assert.match(psbtEditor, /\$\("psbted-compare-clear"\)\.addEventListener\("click"[\s\S]*?compareText\.value = ""/, "the compare clear must empty it too");
    },
  },
  {
    ids: ["exp-text"],
    why: "Expand overlay's full-value editor (a PSBT pair value can be a whole previous transaction)",
    probe: () => {
      assert.match(expandable, /const release = \(\) => \{[\s\S]*?text\.value = ""/, "the overlay release must empty #exp-text");
      assert.match(expandable, /const close = \(\) => \{[\s\S]*?release\(\)/, "close must release");
      assert.match(expandable, /addEventListener\("pagehide", teardown\)/, "pagehide must release");
    },
  },
  {
    // File inputs hold no content once consumed, but the reset is what lets
    // "pick the same file again" work AND keeps the fake path off screen.
    ids: ["psbt-file", "nonce-file", "psbt-nonce-history-file", "journal-notes-file", "journal-keymanager-file"],
    why: "file pickers for PSBT / nonce / journal / vault uploads (reset on consume)",
    probe: (id) => assert.match(around(app, `getElementById("${id}")`), /value = ""/, `#${id} must be reset on consume`),
  },
  {
    ids: ["psbted-file"],
    why: "the PSBT editor's file picker (reset on consume)",
    probe: () => assert.match(around(psbtEditor, `$("psbted-file")`), /file\.value = ""/, "#psbted-file must be reset on consume"),
  },
];

const SECRET_FIELDS = CLEARING_PATHS.flatMap((row) => row.ids);

test("every registry id has its clearing path wired", () => {
  for (const row of CLEARING_PATHS) for (const id of row.ids) row.probe(id);
});

// Settings and public helpers. Keep a one-sentence reason per field so the
// next field is classified consciously, not by default.
const PUBLIC_FIELDS = {
  "account": "derivation account index",
  "account-harden": "hardening toggle",
  "address-range": "address window setting",
  "address-start": "address window setting",
  "address-start-harden": "hardening toggle",
  "bip85-bytes": "BIP-85 length setting",
  "bip85-index": "BIP-85 index setting",
  "bip85-pwdlen": "BIP-85 length setting",
  "branch-range": "address window setting",
  "branch-start": "address window setting",
  "branch-start-harden": "hardening toggle",
  "derivation-path": "public derivation path text",
  "journal-log-encrypt": "download-encryption checkbox",
  "journal-notes-encrypt": "download-encryption checkbox",
  "journal-state-encrypt": "download-encryption checkbox",
  "msig-account": "derivation setting",
  "msig-account-harden": "derivation setting",
  "msig-address-range": "derivation setting",
  "msig-address-start": "derivation setting",
  "msig-address-start-harden": "derivation setting",
  "msig-branch-range": "derivation setting",
  "msig-branch-start": "derivation setting",
  "msig-branch-start-harden": "derivation setting",
  "msig-legacy-bip87": "script-policy checkbox",
  "msig-m": "quorum size",
  "msig-m-number": "quorum size",
  "msig-n": "quorum size",
  "msig-n-number": "quorum size",
  "msig-network": "network setting",
  "msig-network-harden": "hardening toggle",
  "msig-purpose": "purpose setting",
  "msig-purpose-harden": "hardening toggle",
  "msig-reuse-session-keys": "session-key checkbox",
  "network": "network setting",
  "network-harden": "hardening toggle",
  "psbted-insane": "editor policy checkbox",
  "purpose": "purpose setting",
  "purpose-harden": "hardening toggle",
  "sp-account": "derivation setting",
  "sp-verify-labels": "label index settings",
  "vanity-account-count": "grind range setting",
  "vanity-account-start": "grind range setting",
  "vanity-count": "grind range setting",
  "vanity-first": "stop-on-first checkbox",
  "vanity-length": "grind range setting",
  "vanity-prefix": "the desired address prefix — public output text, not key material",
  "vanity-start": "grind range setting",
  "vanity-workers": "worker-count setting",
  "codex32-index": "target share index character, not key material",
};

test("the registry covers every known secret-bearing field", () => {
  for (const id of ["dice", "pass", "seed", "key", "bip85-key", "sp-key", "psbt-key", "nonce-key", "ln-seed", "journal-input", "journal-phrase", "journal-state-text", "psbted-text", "msig-descriptor", "exp-text"]) {
    assert.ok(SECRET_FIELDS.includes(id), `#${id} is secret but missing from the registry`);
  }
});

test("every shell field is classified as secret (cleared) or public (settings)", () => {
  const fields = [...shell.matchAll(/<(input|textarea)\b[^>]*>/g)].map(([tag]) => tag.match(/\sid="([^"]*)"/)?.[1]).filter(Boolean);
  const known = new Set([...SECRET_FIELDS, ...Object.keys(PUBLIC_FIELDS)]);
  assert.ok(fields.length > 0, "the sweep read no fields — the shell changed shape");
  for (const id of fields) {
    assert.ok(known.has(id), `#${id} is unclassified: add it to SECRET_FIELDS (with a clearing path) or PUBLIC_FIELDS (with a reason)`);
  }
  // No stale entries either: a removed field must not linger in the lists.
  // (The completeness sweep reads input/textarea tags; a registry id may be
  // another element, like the pre the session log renders into.)
  const inShell = (id) => shell.includes(`id="${id}"`);
  for (const id of known) {
    assert.ok(inShell(id) || ["hex", "bin", "base4", "base8", "base32", "base64", "seed", "seed-numbers", "key", "cards", "direct-cards", "exp-text"].includes(id),
      `#${id} is classified but no longer in the shell`);
  }
});
