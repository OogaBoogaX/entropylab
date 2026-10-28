// Secure entry: the session-wide switch that holds secrets in zeroable typed
// buffers instead of text fields.
//
// A text field's value is text the page cannot erase (see passphrase-vault.js
// for the residue audit). Here a seed is word indices, a private key is bytes
// in a PassphraseVault, dice are faces and cards are values, each in a typed
// array that can be zeroed. The module has no DOM and no app imports beyond
// the vault: P1b wires it into the Key Station.
//
// Contract: every constructor and setter validates its arguments and refuses
// bad input with a coded SecureEntryError; every buffer is zeroed when it is
// replaced, cleared, deleted or the session ends; a wiped entry refuses
// further mutation; and a turn-on/turn-off plan is dry-run in full before
// anything is committed, so a blocked plan changes nothing and never echoes
// secret text.

import { PassphraseVault } from "./passphrase-vault.js";

export class SecureEntryError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = "SecureEntryError";
    this.code = code;
  }
}

const fail = (code, message) => { throw new SecureEntryError(code, message); };

const SEED_LENGTHS = new Set([12, 15, 18, 21, 24]);
const MAX_WORD_INDEX = 2048;
const MAX_CAPACITY = 400;

const isInteger = (value) => typeof value === "number" && Number.isInteger(value);

// The module writes rev, count, wiped and owner on an entry; refuse one where
// those writes would throw a raw TypeError halfway through an edit or install.
const assertWritable = (entry) => {
  if (!Object.isExtensible(entry)) fail("BAD_ENTRY", "A secure entry must be extensible.");
  for (const field of ["rev", "count", "wiped"]) {
    const descriptor = Object.getOwnPropertyDescriptor(entry, field);
    if (descriptor && descriptor.writable !== true) fail("BAD_ENTRY", "A secure entry's fields must be writable.");
  }
  const owner = Object.getOwnPropertyDescriptor(entry, "owner");
  if (owner && owner.configurable !== true) fail("BAD_ENTRY", "A secure entry's owner must be configurable.");
};

const assertLive = (entry, kind) => {
  if (!entry || typeof entry !== "object" || entry.kind !== kind) fail("BAD_ENTRY", `Not a ${kind} entry.`);
  if (entry.wiped) fail("WIPED", "This secure entry has been wiped.");
  assertWritable(entry);
};

const isPlainObject = (value) => {
  if (!value || typeof value !== "object") return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

// One canonical key id: a non-negative safe integer or a non-empty string,
// always carried as a string so 1 and "1" name the same key.
const normalizeKeyId = (keyId) => {
  if (typeof keyId === "number" && Number.isSafeInteger(keyId) && keyId >= 0) return String(keyId);
  if (typeof keyId === "string" && keyId.length > 0) return keyId;
  return fail("BAD_KEY", "A key id must be a non-negative integer or a non-empty string.");
};

const bumpRev = (entry) => { entry.rev = (isInteger(entry.rev) ? entry.rev : 0) + 1; };

// An edit to an installed entry moves the owning session's generation, so a
// guard or plan captured before the edit is stale.
const bumpOwner = (entry) => {
  if (entry.owner && typeof entry.owner === "object" && isInteger(entry.owner.generation)) entry.owner.generation += 1;
};

// P1b calls this when the key vault mutates internally, so a turn-off plan
// taken before the edit is refused instead of serializing stale bytes.
export const touchEntry = (entry) => {
  if (!entry || typeof entry !== "object") fail("BAD_ENTRY", "Not a secure entry.");
  assertWritable(entry);
  bumpRev(entry);
  bumpOwner(entry);
};

// The one shared shape check: a session, a plan and a commit all refuse an
// entry whose kind, buffers or counts do not match the method it claims.
const assertEntry = (entry, method) => {
  if (!entry || typeof entry !== "object" || entry.kind !== method) fail("BAD_ENTRY", `Not a ${method} entry.`);
  if (entry.wiped === true) fail("BAD_ENTRY", "This secure entry has been wiped.");
  assertWritable(entry);
  switch (method) {
    case "seed":
      if (!(entry.indices instanceof Uint16Array)) fail("BAD_ENTRY", "A seed entry needs Uint16 word indices.");
      if (!SEED_LENGTHS.has(entry.length)) fail("BAD_ENTRY", "A seed entry needs 12, 15, 18, 21 or 24 words.");
      if (entry.indices.length !== entry.length) fail("BAD_ENTRY", "The seed buffer does not match its length.");
      if (!isInteger(entry.count) || entry.count < 0 || entry.count > entry.length) fail("BAD_ENTRY", "The seed count is outside the buffer.");
      for (let i = 0; i < entry.count; i += 1) {
        if (entry.indices[i] >= MAX_WORD_INDEX) fail("BAD_ENTRY", "A seed word index is outside 0..2047.");
      }
      break;
    case "rolls":
      if (!(entry.rolls instanceof Uint8Array)) fail("BAD_ENTRY", "A rolls entry needs a Uint8 face buffer.");
      if (!isInteger(entry.count) || entry.count < 0 || entry.count > entry.rolls.length) fail("BAD_ENTRY", "The rolls count is outside the buffer.");
      for (let i = 0; i < entry.count; i += 1) {
        if (entry.rolls[i] < 1 || entry.rolls[i] > 6) fail("BAD_ENTRY", "A die face is 1..6.");
      }
      break;
    case "cards":
      if (!(entry.cards instanceof Uint8Array)) fail("BAD_ENTRY", "A cards entry needs a Uint8 card buffer.");
      if (!isInteger(entry.count) || entry.count < 0 || entry.count > entry.cards.length) fail("BAD_ENTRY", "The cards count is outside the buffer.");
      for (let i = 0; i < entry.count; i += 1) {
        if (entry.cards[i] > 51) fail("BAD_ENTRY", "A card value is 0..51.");
      }
      break;
    case "key":
      if (!(entry.vault instanceof PassphraseVault)) fail("BAD_ENTRY", "A key entry needs a PassphraseVault.");
      break;
    default:
      fail("BAD_ENTRY", "Not a secure entry.");
  }
};

// The four entry kinds the module can hold. The boolean is the UI gate that
// P1b reads through isSupported(); it is false for every kind in this round,
// so the Key Station does not yet offer secure entry. Planning recognises the
// kinds themselves: a method not listed here (a "hex" number base, say) is
// never plannable.
export const SUPPORTED_METHODS = Object.freeze({ seed: false, key: false, rolls: false, cards: false });

export const isSupported = (method) => typeof method === "string"
  && Object.prototype.hasOwnProperty.call(SUPPORTED_METHODS, method)
  && SUPPORTED_METHODS[method] === true;

const isKnownMethod = (method) => typeof method === "string"
  && Object.prototype.hasOwnProperty.call(SUPPORTED_METHODS, method);

export const seedEntry = (length) => {
  if (!SEED_LENGTHS.has(length)) fail("BAD_LENGTH", "A seed entry needs 12, 15, 18, 21 or 24 words.");
  return { kind: "seed", length, indices: new Uint16Array(length), count: 0, wiped: false, rev: 0 };
};

export const seedSet = (entry, position, index) => {
  assertLive(entry, "seed");
  if (!isInteger(position) || position < 0 || position >= entry.length) fail("BAD_POSITION", "The word position is outside the seed.");
  if (!isInteger(index) || index < 0 || index >= MAX_WORD_INDEX) fail("BAD_INDEX", "A BIP39 word index is 0..2047.");
  if (position > entry.count) fail("BAD_POSITION", "Words fill in order; this position is past the end.");
  entry.indices[position] = index;
  if (position === entry.count) entry.count += 1;
  bumpRev(entry);
  bumpOwner(entry);
};

export const seedUndo = (entry) => {
  assertLive(entry, "seed");
  if (entry.count === 0) fail("EMPTY", "There is no word to undo.");
  entry.count -= 1;
  entry.indices[entry.count] = 0;
  bumpRev(entry);
  bumpOwner(entry);
};

export const seedIndices = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "seed") fail("BAD_ENTRY", "Not a seed entry.");
  return entry.indices.slice(0, entry.count);
};

export const keyEntry = () => ({ kind: "key", vault: new PassphraseVault(), wiped: false, rev: 0 });

export const rollsEntry = (method, capacity) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A rolls entry needs a method tag.");
  if (!isInteger(capacity) || capacity < 1 || capacity > MAX_CAPACITY) fail("BAD_CAPACITY", "Capacity is 1..400.");
  return { kind: "rolls", method, rolls: new Uint8Array(capacity), count: 0, wiped: false, rev: 0 };
};

export const rollsPush = (entry, face) => {
  assertLive(entry, "rolls");
  if (!isInteger(face) || face < 1 || face > 6) fail("BAD_FACE", "A die face is 1..6.");
  if (entry.count === entry.rolls.length) fail("FULL", "The rolls buffer is full.");
  entry.rolls[entry.count] = face;
  entry.count += 1;
  bumpRev(entry);
  bumpOwner(entry);
};

export const rollsUndo = (entry) => {
  assertLive(entry, "rolls");
  if (entry.count === 0) fail("EMPTY", "There is no roll to undo.");
  entry.count -= 1;
  entry.rolls[entry.count] = 0;
  bumpRev(entry);
  bumpOwner(entry);
};

export const rollAt = (entry, i) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "rolls") fail("BAD_ENTRY", "Not a rolls entry.");
  if (!isInteger(i) || i < 0 || i >= entry.count) fail("BAD_POSITION", "No roll at that position.");
  return entry.rolls[i];
};

export const rollsCopy = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "rolls") fail("BAD_ENTRY", "Not a rolls entry.");
  return entry.rolls.slice(0, entry.count);
};

export const cardsEntry = (method, capacity) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A cards entry needs a method tag.");
  if (!isInteger(capacity) || capacity < 1 || capacity > MAX_CAPACITY) fail("BAD_CAPACITY", "Capacity is 1..400.");
  return { kind: "cards", method, cards: new Uint8Array(capacity), count: 0, wiped: false, rev: 0 };
};

export const cardsPush = (entry, value) => {
  assertLive(entry, "cards");
  if (!isInteger(value) || value < 0 || value > 51) fail("BAD_VALUE", "A card value is 0..51.");
  if (entry.count === entry.cards.length) fail("FULL", "The cards buffer is full.");
  entry.cards[entry.count] = value;
  entry.count += 1;
  bumpRev(entry);
  bumpOwner(entry);
};

export const cardsUndo = (entry) => {
  assertLive(entry, "cards");
  if (entry.count === 0) fail("EMPTY", "There is no card to undo.");
  entry.count -= 1;
  entry.cards[entry.count] = 0;
  bumpRev(entry);
  bumpOwner(entry);
};

export const cardAt = (entry, i) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "cards") fail("BAD_ENTRY", "Not a cards entry.");
  if (!isInteger(i) || i < 0 || i >= entry.count) fail("BAD_POSITION", "No card at that position.");
  return entry.cards[i];
};

export const cardsCopy = (entry) => {
  if (!entry || typeof entry !== "object" || entry.kind !== "cards") fail("BAD_ENTRY", "Not a cards entry.");
  return entry.cards.slice(0, entry.count);
};

// Zero every typed array an entry holds and clear its vault, without checking
// the entry's shape.
const zeroBuffers = (entry) => {
  for (const field of ["indices", "rolls", "cards"]) {
    const buffer = entry[field];
    if (buffer && typeof buffer.fill === "function") buffer.fill(0);
  }
  if (entry.vault && typeof entry.vault.clear === "function") entry.vault.clear();
};

export const wipeEntry = (entry) => {
  if (!entry || typeof entry !== "object") fail("BAD_ENTRY", "Not a secure entry.");
  // A wiped entry's buffers stay reachable (a key entry's vault can be refilled
  // through entry.vault), so a repeat wipe clears them again, and invalidates
  // guards as a first wipe does: one taken after the refill must not survive.
  if (entry.wiped) {
    zeroBuffers(entry);
    bumpOwner(entry);
    return;
  }
  switch (entry.kind) {
    case "seed":
      if (!(entry.indices instanceof Uint16Array)) fail("BAD_ENTRY", "The seed entry has no word buffer.");
      entry.indices.fill(0);
      break;
    case "key":
      if (!entry.vault || typeof entry.vault.clear !== "function") fail("BAD_ENTRY", "The key entry has no vault.");
      entry.vault.clear();
      break;
    case "rolls":
      if (!(entry.rolls instanceof Uint8Array)) fail("BAD_ENTRY", "The rolls entry has no face buffer.");
      entry.rolls.fill(0);
      break;
    case "cards":
      if (!(entry.cards instanceof Uint8Array)) fail("BAD_ENTRY", "The cards entry has no card buffer.");
      entry.cards.fill(0);
      break;
    default: fail("BAD_ENTRY", "Not a secure entry.");
  }
  // A direct wipe must invalidate any guard captured before it, so the owning
  // session's generation moves even when the wipe did not go through the map,
  // and before the refusal below: the buffers are zeroed either way.
  bumpOwner(entry);
  // The buffers are zeroed above even for a frozen entry (typed-array contents
  // stay writable); a frozen entry's own fields cannot be updated, so report
  // it as a coded refusal rather than a raw TypeError.
  try {
    if ("count" in entry) entry.count = 0;
    entry.wiped = true;
  } catch {
    fail("BAD_ENTRY", "This entry cannot be marked wiped.");
  }
  if (entry.wiped !== true) fail("BAD_ENTRY", "This entry cannot be marked wiped.");
};

// Best-effort wipe: if wipeEntry throws on a malformed entry, still zero every
// typed array it holds and clear any vault, so nothing survives the cleanup.
const scrub = (entry) => {
  try {
    wipeEntry(entry);
    return true;
  } catch {
    try {
      if (entry && typeof entry === "object") {
        zeroBuffers(entry);
        if ("count" in entry) entry.count = 0;
        entry.wiped = true;
      }
    } catch { /* nothing more can be done */ }
    return false;
  }
};

const entryId = (keyId, method) => `${normalizeKeyId(keyId)}:${method}`;

const metaOf = (session) => {
  if (!session.meta) Object.defineProperty(session, "meta", { value: new Map(), enumerable: false, writable: true, configurable: true });
  return session.meta;
};

// Plans not yet committed or discarded. A turn-on plan's staged entries and a
// turn-off plan's serialized texts hold secrets outside session.entries, so
// End Session and a key delete must still reach them.
const PLAN_SESSION = Symbol("secure-entry plan session");
const pendingOf = (session) => {
  if (!session.pending) Object.defineProperty(session, "pending", { value: new Set(), enumerable: false, writable: true, configurable: true });
  return session.pending;
};

// True when the entry is live in some session. A staged entry that ended up
// installed (a converter that handed one object to two plans) belongs to
// that session now, and only its own wipe may zero it.
const isInstalled = (entry) => Boolean(entry && typeof entry === "object" && entry.owner && installedId(entry.owner, entry) !== null);

// Empties one plan. A turn-on plan wipes the staged entries it still owns; a
// turn-off plan points at the live entries, so it only drops its texts
// (strings cannot be zeroed, but no reference to them is left). True when
// every wipe went through.
const dropPlan = (plan) => {
  let clean = true;
  if (Array.isArray(plan.staged)) {
    for (const item of plan.staged) {
      if (!item || typeof item !== "object") continue;
      if (plan.kind === "on") {
        if (item.entry && !isInstalled(item.entry) && !scrub(item.entry)) clean = false;
      } else if (typeof item.text === "string") {
        try { item.text = ""; } catch { /* the plan below still lets go of it */ }
      }
    }
  }
  plan.staged = [];
  return clean;
};

// Empties every pending plan. Callers move the generation in the same step,
// so these plans are stale and can never commit. True when every wipe went
// through.
const wipePending = (session) => {
  let clean = true;
  const pending = pendingOf(session);
  for (const plan of pending) if (!dropPlan(plan)) clean = false;
  pending.clear();
  return clean;
};

// True when a pending turn-on plan of this session already stages the entry.
const stagedInPending = (session, entry) => {
  for (const plan of pendingOf(session)) {
    if (plan.kind === "on" && Array.isArray(plan.staged) && plan.staged.some((item) => item && item.entry === entry)) return true;
  }
  return false;
};

const splitId = (id) => {
  const at = id.lastIndexOf(":");
  return at < 0 ? { keyId: id, method: "" } : { keyId: id.slice(0, at), method: id.slice(at + 1) };
};

// The id an entry is installed under in a session, or null when it is not
// installed there. One entry lives in one place: a second install under a
// different id is refused rather than silently aliased.
const installedId = (session, entry) => {
  if (!session || typeof session !== "object" || !(session.entries instanceof Map)) return null;
  for (const [id, other] of session.entries) if (other === entry) return id;
  return null;
};

// True when the entry is installed in a different session: staging or
// committing it here would make sessionSet refuse mid-install.
const installedElsewhere = (session, entry) =>
  Boolean(entry && typeof entry === "object" && entry.owner && entry.owner !== session && installedId(entry.owner, entry) !== null);

export const createSecureSession = () => {
  const session = { on: false, generation: 0, entries: new Map() };
  Object.defineProperty(session, "meta", { value: new Map(), enumerable: false, writable: true, configurable: true });
  Object.defineProperty(session, "pending", { value: new Set(), enumerable: false, writable: true, configurable: true });
  return session;
};

export const sessionGet = (session, keyId, method) => session.entries.get(entryId(keyId, method)) ?? null;

export const sessionSet = (session, keyId, method, entry) => {
  if (typeof method !== "string" || method.length === 0) fail("BAD_METHOD", "A session method must be a non-empty string.");
  const canonical = normalizeKeyId(keyId);
  assertEntry(entry, method);
  const id = `${canonical}:${method}`;
  const ownerId = installedId(entry.owner, entry);
  if (ownerId !== null && (entry.owner !== session || ownerId !== id)) fail("BAD_ENTRY", "This entry is already installed under another id.");
  const hereId = installedId(session, entry);
  if (hereId !== null && hereId !== id) fail("BAD_ENTRY", "This entry is already installed under another id.");
  Object.defineProperty(entry, "owner", { value: session, writable: true, configurable: true });
  // Install first, then wipe the entry it replaces: a wipe that cannot finish
  // must not leave the key pointing at a half-wiped entry, or stop a
  // commitTurnOn install loop part way.
  const previous = session.entries.get(id);
  session.entries.set(id, entry);
  metaOf(session).set(id, { keyId: canonical, method });
  session.generation += 1;
  if (previous && previous !== entry) scrub(previous);
};

export const sessionDeleteKey = (session, keyId) => {
  const wanted = normalizeKeyId(keyId);
  const meta = metaOf(session);
  const doomed = [];
  for (const [id, entry] of session.entries) {
    const info = meta.get(id) ?? splitId(id);
    if (info.keyId !== wanted) continue;
    doomed.push([id, entry]);
  }
  let failed = false;
  for (const [id, entry] of doomed) {
    if (!scrub(entry)) failed = true;
    session.entries.delete(id);
    meta.delete(id);
  }
  // Moves even when nothing was installed: a pending turn-on plan may hold
  // this key's staged secrets, and committing it would bring them back. Every
  // pending plan is stale from here on, so its staged secrets are wiped now.
  if (!wipePending(session)) failed = true;
  session.generation += 1;
  if (failed) fail("WIPE_PARTIAL", "Some secure entries could not be wiped cleanly.");
};

export const sessionWipe = (session) => {
  let failed = false;
  for (const entry of session.entries.values()) {
    if (!scrub(entry)) failed = true;
  }
  if (!wipePending(session)) failed = true;
  session.entries.clear();
  metaOf(session).clear();
  session.on = false;
  session.generation += 1;
  if (failed) fail("WIPE_PARTIAL", "Some secure entries could not be wiped cleanly.");
};

export const sessionGuard = (session) => {
  const generation = session.generation;
  return { generation, current: () => session.generation === generation };
};

// A converter must return a fresh entry it does not keep: the plan owns the
// entry and wipes it on discard.
export const planTurnOn = (session, keys, converters) => {
  if (!Array.isArray(keys)) fail("BAD_INPUT", "keys must be an array.");
  const staged = [], blockers = [];
  const seen = new Set();
  const stagedEntries = new Set();
  try {
    for (const key of keys) {
      const keyId = normalizeKeyId(key?.keyId);
      const methods = key?.methods;
      if (!isPlainObject(methods)) fail("BAD_INPUT", "A key's methods must be a plain object.");
      for (const method of Object.keys(methods)) {
        const text = methods[method];
        if (text === undefined || text === null || text === "") continue;
        const id = `${keyId}:${method}`;
        if (seen.has(id)) { blockers.push({ keyId, method, reason: "duplicate" }); continue; }
        seen.add(id);
        if (!isKnownMethod(method)) { blockers.push({ keyId, method, reason: "unsupported" }); continue; }
        const convert = converters && Object.prototype.hasOwnProperty.call(converters, method) ? converters[method] : undefined;
        if (typeof convert !== "function") { blockers.push({ keyId, method, reason: "no-converter" }); continue; }
        let entry;
        try { entry = convert(text); }
        catch { blockers.push({ keyId, method, reason: "invalid" }); continue; }
        if (stagedEntries.has(entry) || stagedInPending(session, entry) || installedId(session, entry) !== null || installedElsewhere(session, entry)) {
          blockers.push({ keyId, method, reason: "invalid" });
          continue;
        }
        try { assertEntry(entry, method); }
        catch {
          scrub(entry);
          blockers.push({ keyId, method, reason: "invalid" });
          continue;
        }
        stagedEntries.add(entry);
        staged.push({ keyId, method, entry });
      }
    }
  } catch (error) {
    // A malformed key id or methods object is a programming error, not a
    // blocker: refuse the whole plan and wipe whatever was already staged.
    for (const item of staged) scrub(item.entry);
    throw error;
  }
  const plan = { kind: "on", ok: blockers.length === 0, staged, blockers, generation: session.generation };
  Object.defineProperty(plan, PLAN_SESSION, { value: session, enumerable: false, configurable: true });
  if (staged.length > 0) pendingOf(session).add(plan);
  return plan;
};

export const commitTurnOn = (session, plan) => {
  if (!plan || plan.kind !== "on" || plan.ok !== true || !Array.isArray(plan.staged)) fail("PLAN_BLOCKED", "The plan has blockers; nothing was changed.");
  if (plan.generation !== session.generation) fail("PLAN_STALE", "The plan is stale; nothing was changed.");
  // Validate every item and every key id up front, so the install loop below
  // cannot throw and the commit is all-or-nothing.
  const seenEntries = new Set();
  const seenIds = new Set();
  for (const item of plan.staged) {
    if (!item || typeof item !== "object") fail("PLAN_BLOCKED", "The plan is not valid; nothing was changed.");
    assertEntry(item.entry, item.method);
    const canonical = normalizeKeyId(item.keyId);
    const id = `${canonical}:${item.method}`;
    if (seenEntries.has(item.entry) || seenIds.has(id) || installedId(session, item.entry) !== null || installedElsewhere(session, item.entry)) {
      fail("PLAN_BLOCKED", "The plan is not valid; nothing was changed.");
    }
    seenEntries.add(item.entry);
    seenIds.add(id);
  }
  // A plan commits only into the session it was made for: two fresh sessions
  // share generation 0, so the generation alone cannot tell them apart.
  if (plan[PLAN_SESSION] !== session) fail("PLAN_STALE", "The plan is stale; nothing was changed.");
  for (const { keyId, method, entry } of plan.staged) sessionSet(session, keyId, method, entry);
  plan.staged = [];
  pendingOf(session).delete(plan);
  session.on = true;
  session.generation += 1;
};

export const discardPlan = (plan) => {
  if (!plan || !Array.isArray(plan.staged)) return;
  // Only a turn-on plan owns its staged entries. A turn-off plan points at the
  // live entries, so discarding it must never wipe them; it drops its texts.
  dropPlan(plan);
  if (plan[PLAN_SESSION]) pendingOf(plan[PLAN_SESSION]).delete(plan);
  // A discarded plan cannot be committed: an empty turn-on would otherwise
  // switch secure entry on with the user's text already wiped.
  plan.ok = false;
};

export const planTurnOff = (session, serializers) => {
  const meta = metaOf(session);
  const ready = [], staged = [], blockers = [];
  // Check every entry before serializing any: a blocked plan can be neither
  // committed nor wiped, so it must not carry secret text.
  for (const [id, entry] of session.entries) {
    const info = meta.get(id) ?? splitId(id);
    const { keyId, method } = info;
    try { assertEntry(entry, method); }
    catch { blockers.push({ keyId, method, reason: "invalid" }); continue; }
    const serialize = serializers && Object.prototype.hasOwnProperty.call(serializers, method) ? serializers[method] : undefined;
    if (typeof serialize !== "function") { blockers.push({ keyId, method, reason: "no-serializer" }); continue; }
    ready.push({ keyId, method, entry, serialize });
  }
  if (blockers.length === 0) {
    for (const { keyId, method, entry, serialize } of ready) {
      let text;
      try { text = serialize(entry); }
      catch { blockers.push({ keyId, method, reason: "invalid" }); continue; }
      if (typeof text !== "string") { blockers.push({ keyId, method, reason: "invalid" }); continue; }
      const item = { keyId, method, text };
      Object.defineProperty(item, "entry", { value: entry, enumerable: false });
      Object.defineProperty(item, "rev", { value: entry.rev, enumerable: false });
      staged.push(item);
    }
    // A serializer that fails part way blocks the plan too: drop the texts
    // already made rather than return them with it.
    if (blockers.length > 0) staged.length = 0;
  }
  const plan = { kind: "off", ok: blockers.length === 0, staged, blockers, generation: session.generation };
  Object.defineProperty(plan, PLAN_SESSION, { value: session, enumerable: false, configurable: true });
  // The texts are the secrets in the clear: End Session and a key delete must
  // drop them even if the plan is never committed or discarded.
  if (staged.length > 0) pendingOf(session).add(plan);
  return plan;
};

export const commitTurnOff = (session, plan, mode) => {
  if (mode === "convert") {
    if (!plan || plan.kind !== "off" || plan.ok !== true || !Array.isArray(plan.staged)) fail("PLAN_BLOCKED", "The plan has blockers; nothing was changed.");
    if (plan.generation !== session.generation) fail("PLAN_STALE", "The plan is stale; nothing was changed.");
    // Each staged item must name a distinct entry: with the size check below,
    // that makes the plan cover every installed entry exactly once.
    const seenEntries = new Set();
    for (const item of plan.staged) {
      if (!item || typeof item !== "object" || !item.entry) fail("PLAN_STALE", "The plan is stale; nothing was changed.");
      if (item.entry.rev !== item.rev) fail("PLAN_STALE", "The plan is stale; nothing was changed.");
      if (seenEntries.has(item.entry)) fail("PLAN_BLOCKED", "The plan is not valid; nothing was changed.");
      seenEntries.add(item.entry);
    }
    if (plan.staged.length !== session.entries.size) fail("PLAN_BLOCKED", "The plan is stale; nothing was changed.");
    for (const item of plan.staged) {
      if (sessionGet(session, item.keyId, item.method) !== item.entry) fail("PLAN_BLOCKED", "The plan is stale; nothing was changed.");
    }
    // Each text keeps its key and method, so the caller puts it back in the right field.
    const texts = plan.staged.map(({ keyId, method, text }) => ({ keyId, method, text }));
    plan.staged = [];
    pendingOf(session).delete(plan);
    try {
      sessionWipe(session);
    } catch (error) {
      // The cleanup still ran; hand the caller the texts so the fields can be
      // restored even though some buffers could not be wiped.
      try {
        Object.defineProperty(error, "texts", { value: texts, enumerable: false, configurable: true, writable: true });
      } catch { /* the error still propagates */ }
      throw error;
    }
    return texts;
  }
  if (mode === "clear") {
    // A pending turn-on plan owns secrets that are not in the session yet:
    // wipe them too. A turn-off plan only points at the live entries.
    discardPlan(plan);
    sessionWipe(session);
    return [];
  }
  fail("BAD_MODE", "Unknown turn-off mode.");
};
