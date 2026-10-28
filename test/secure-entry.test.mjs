// Secure entry (src/js/secure-entry.js): the session-wide switch that holds
// secrets in zeroable typed buffers instead of text fields.
//
// Contract: every entry kind validates its arguments and refuses bad input
// with a coded SecureEntryError; every buffer is zeroed when it is replaced,
// cleared, deleted or the session ends; a wiped entry refuses further
// mutation; and a turn-on/turn-off plan is dry-run in full before anything is
// committed, so a blocked plan changes nothing and never echoes secret text.
//
// Expected values: the P1a design (BIP39 word counts 12/15/18/21/24, word
// indices 0..2047, die faces 1..6, card values 0..51, capacities 1..400) and
// the BIP39 word-count rule. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SecureEntryError,
  SUPPORTED_METHODS,
  isSupported,
  seedEntry,
  seedSet,
  seedUndo,
  seedIndices,
  keyEntry,
  rollsEntry,
  rollsPush,
  rollsUndo,
  rollAt,
  rollsCopy,
  cardsEntry,
  cardsPush,
  cardsUndo,
  cardAt,
  cardsCopy,
  wipeEntry,
  touchEntry,
  createSecureSession,
  sessionGet,
  sessionSet,
  sessionDeleteKey,
  sessionWipe,
  sessionGuard,
  planTurnOn,
  commitTurnOn,
  discardPlan,
  planTurnOff,
  commitTurnOff,
} from "../src/js/secure-entry.js";

const code = (expected) => (error) => error instanceof SecureEntryError && error.code === expected;

test("seed entries accept only the five BIP39 word counts", () => {
  for (const length of [12, 15, 18, 21, 24]) {
    const entry = seedEntry(length);
    assert.equal(entry.kind, "seed");
    assert.equal(entry.length, length);
    assert.equal(entry.count, 0);
    assert.ok(entry.indices instanceof Uint16Array);
    assert.equal(entry.indices.length, length);
    assert.ok(entry.indices.every((value) => value === 0));
  }
  for (const length of [0, 1, 11, 13, 23, 25, 27, -12, 12.5, "12", null, undefined, NaN]) {
    assert.throws(() => seedEntry(length), code("BAD_LENGTH"));
  }
});

test("seedSet refuses positions and indices outside the contract", () => {
  const entry = seedEntry(12);
  assert.throws(() => seedSet(entry, -1, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 12, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 1.5, 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, "0", 0), code("BAD_POSITION"));
  assert.throws(() => seedSet(entry, 0, -1), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, 2048), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, 1.5), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 0, "1"), code("BAD_INDEX"));
  assert.throws(() => seedSet(entry, 2, 5), code("BAD_POSITION"));
  assert.equal(entry.count, 0);
});

test("seed words fill in order and a middle word is replaced without shifting the rest", () => {
  const entry = seedEntry(12);
  const words = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
  words.forEach((index, position) => seedSet(entry, position, index));
  assert.equal(entry.count, 12);
  assert.deepEqual([...seedIndices(entry)], words);
  seedSet(entry, 5, 2047);
  assert.equal(entry.count, 12);
  const expected = words.slice();
  expected[5] = 2047;
  assert.deepEqual([...seedIndices(entry)], expected);
});

test("seedUndo zeroes the last slot and decrements the count", () => {
  const entry = seedEntry(12);
  seedSet(entry, 0, 7);
  seedSet(entry, 1, 8);
  seedUndo(entry);
  assert.equal(entry.count, 1);
  assert.equal(entry.indices[1], 0);
  assert.deepEqual([...seedIndices(entry)], [7]);
  seedUndo(entry);
  assert.equal(entry.count, 0);
  assert.equal(entry.indices[0], 0);
  assert.throws(() => seedUndo(entry), code("EMPTY"));
});

test("seedIndices returns a copy the caller owns", () => {
  const entry = seedEntry(12);
  seedSet(entry, 0, 1);
  seedSet(entry, 1, 2);
  const copy = seedIndices(entry);
  assert.ok(copy instanceof Uint16Array);
  assert.notEqual(copy.buffer, entry.indices.buffer);
  copy[0] = 999;
  assert.equal(entry.indices[0], 1);
  assert.deepEqual([...seedIndices(entry)], [1, 2]);
});

test("rolls validate their method, capacity and faces", () => {
  for (const capacity of [1, 6, 400]) {
    const entry = rollsEntry("base10", capacity);
    assert.equal(entry.kind, "rolls");
    assert.equal(entry.method, "base10");
    assert.equal(entry.count, 0);
    assert.ok(entry.rolls instanceof Uint8Array);
    assert.equal(entry.rolls.length, capacity);
  }
  for (const capacity of [0, 401, -1, 1.5, "6", null, undefined]) {
    assert.throws(() => rollsEntry("base10", capacity), code("BAD_CAPACITY"));
  }
  for (const method of ["", null, undefined, 3, {}]) {
    assert.throws(() => rollsEntry(method, 6), code("BAD_METHOD"));
  }
  const entry = rollsEntry("coleman", 6);
  for (const face of [0, 7, -1, 1.5, "3", null]) {
    assert.throws(() => rollsPush(entry, face), code("BAD_FACE"));
  }
  assert.equal(entry.count, 0);
});

test("rolls push, undo zeroes, FULL at capacity, and copies do not alias", () => {
  const entry = rollsEntry("base10", 3);
  rollsPush(entry, 1);
  rollsPush(entry, 6);
  assert.equal(entry.count, 2);
  assert.equal(rollAt(entry, 0), 1);
  assert.equal(rollAt(entry, 1), 6);
  assert.throws(() => rollAt(entry, 2), code("BAD_POSITION"));
  assert.throws(() => rollAt(entry, -1), code("BAD_POSITION"));
  const copy = rollsCopy(entry);
  assert.ok(copy instanceof Uint8Array);
  assert.notEqual(copy.buffer, entry.rolls.buffer);
  assert.deepEqual([...copy], [1, 6]);
  copy[0] = 9;
  assert.equal(entry.rolls[0], 1);
  rollsPush(entry, 3);
  assert.throws(() => rollsPush(entry, 4), code("FULL"));
  rollsUndo(entry);
  assert.equal(entry.count, 2);
  assert.equal(entry.rolls[2], 0);
  rollsUndo(entry);
  rollsUndo(entry);
  assert.throws(() => rollsUndo(entry), code("EMPTY"));
});

test("cards validate values 0..51 and behave like rolls", () => {
  const entry = cardsEntry("shuffle", 2);
  assert.equal(entry.kind, "cards");
  assert.equal(entry.method, "shuffle");
  assert.ok(entry.cards instanceof Uint8Array);
  for (const value of [-1, 52, 1.5, "0", null]) {
    assert.throws(() => cardsPush(entry, value), code("BAD_VALUE"));
  }
  cardsPush(entry, 0);
  cardsPush(entry, 51);
  assert.equal(cardAt(entry, 0), 0);
  assert.equal(cardAt(entry, 1), 51);
  assert.throws(() => cardAt(entry, 2), code("BAD_POSITION"));
  const copy = cardsCopy(entry);
  assert.notEqual(copy.buffer, entry.cards.buffer);
  assert.deepEqual([...copy], [0, 51]);
  assert.throws(() => cardsPush(entry, 5), code("FULL"));
  cardsUndo(entry);
  assert.equal(entry.count, 1);
  assert.equal(entry.cards[1], 0);
  for (const capacity of [0, 401, 2.5]) {
    assert.throws(() => cardsEntry("shuffle", capacity), code("BAD_CAPACITY"));
  }
});

test("wipeEntry zeroes every buffer and refuses later mutation", () => {
  const seed = seedEntry(12);
  seedSet(seed, 0, 42);
  const seedBuffer = seed.indices;
  wipeEntry(seed);
  assert.ok(seedBuffer.every((value) => value === 0));
  assert.equal(seed.count, 0);
  assert.equal(seed.wiped, true);
  assert.throws(() => seedSet(seed, 0, 1), code("WIPED"));
  assert.throws(() => seedUndo(seed), code("WIPED"));
  wipeEntry(seed);

  const rolls = rollsEntry("base10", 4);
  rollsPush(rolls, 5);
  const rollsBuffer = rolls.rolls;
  wipeEntry(rolls);
  assert.ok(rollsBuffer.every((value) => value === 0));
  assert.throws(() => rollsPush(rolls, 1), code("WIPED"));
  assert.throws(() => rollsUndo(rolls), code("WIPED"));

  const cards = cardsEntry("shuffle", 4);
  cardsPush(cards, 7);
  const cardsBuffer = cards.cards;
  wipeEntry(cards);
  assert.ok(cardsBuffer.every((value) => value === 0));
  assert.throws(() => cardsPush(cards, 1), code("WIPED"));
  assert.throws(() => cardsUndo(cards), code("WIPED"));

  const key = keyEntry();
  key.vault.setText("hunter2");
  assert.equal(key.vault.length, 7);
  wipeEntry(key);
  assert.equal(key.vault.length, 0);
  assert.equal(key.wiped, true);

  // The vault is still reachable after the wipe; a refill is cleared by the
  // next wipe instead of surviving behind the wiped flag.
  key.vault.setText("refilled");
  wipeEntry(key);
  assert.equal(key.vault.length, 0, "a repeat wipe clears a refilled vault");
  seed.indices[0] = 9;
  wipeEntry(seed);
  assert.equal(seed.indices[0], 0, "a repeat wipe zeroes the word buffer again");
});

test("wipeEntry refuses something that is not an entry", () => {
  assert.throws(() => wipeEntry(null), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "nope" }), code("BAD_ENTRY"));
});

test("the session keys entries by key and method, and replacing wipes the old one", () => {
  const session = createSecureSession();
  assert.equal(session.on, false);
  assert.equal(session.generation, 0);
  assert.ok(session.entries instanceof Map);
  assert.equal(session.entries.size, 0);
  assert.equal(sessionGet(session, 3, "seed"), null);

  const first = seedEntry(12);
  seedSet(first, 0, 3);
  const firstBuffer = first.indices;
  const before = session.generation;
  sessionSet(session, 3, "seed", first);
  assert.equal(sessionGet(session, 3, "seed"), first);
  assert.ok(session.generation > before);

  const second = seedEntry(12);
  sessionSet(session, 3, "seed", second);
  assert.ok(firstBuffer.every((value) => value === 0));
  assert.equal(first.wiped, true);
  assert.equal(sessionGet(session, 3, "seed"), second);
  assert.equal(session.entries.size, 1);
});

test("sessionDeleteKey wipes only that key's entries", () => {
  const session = createSecureSession();
  const a = seedEntry(12);
  const b = rollsEntry("base10", 4);
  const c = seedEntry(12);
  sessionSet(session, 1, "seed", a);
  sessionSet(session, 1, "rolls", b);
  sessionSet(session, 2, "seed", c);
  const aBuffer = a.indices, bBuffer = b.rolls;
  const before = session.generation;
  sessionDeleteKey(session, 1);
  assert.ok(aBuffer.every((value) => value === 0));
  assert.ok(bBuffer.every((value) => value === 0));
  assert.equal(a.wiped, true);
  assert.equal(b.wiped, true);
  assert.equal(c.wiped, false);
  assert.equal(sessionGet(session, 1, "seed"), null);
  assert.equal(sessionGet(session, 1, "rolls"), null);
  assert.equal(sessionGet(session, 2, "seed"), c);
  assert.ok(session.generation > before);
});

test("sessionWipe wipes everything and turns the switch off", () => {
  const session = createSecureSession();
  const a = seedEntry(12);
  const b = keyEntry();
  b.vault.setText("secret");
  sessionSet(session, 1, "seed", a);
  sessionSet(session, 2, "key", b);
  session.on = true;
  const aBuffer = a.indices;
  const before = session.generation;
  sessionWipe(session);
  assert.ok(aBuffer.every((value) => value === 0));
  assert.equal(b.vault.length, 0);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  assert.ok(session.generation > before);
});

test("the guard goes stale after any wipe", () => {
  const session = createSecureSession();
  const guard = sessionGuard(session);
  assert.equal(guard.generation, session.generation);
  assert.equal(guard.current(), true);
  sessionWipe(session);
  assert.equal(guard.current(), false);
});

test("the guard goes stale after a key is deleted", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  sessionDeleteKey(session, 1);
  assert.equal(guard.current(), false);
});

test("the guard goes stale when an entry is replaced", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  sessionSet(session, 1, "seed", seedEntry(12));
  assert.equal(guard.current(), false);
});

test("planTurnOn stages every supported conversion without touching the session", () => {
  const session = createSecureSession();
  const keys = [{ keyId: 1, methods: { seed: "abandon ability" } }];
  const converters = {
    seed: (text) => {
      const entry = seedEntry(12);
      seedSet(entry, 0, text.length);
      return entry;
    },
  };
  const plan = planTurnOn(session, keys, converters);
  assert.equal(plan.ok, true);
  assert.equal(plan.blockers.length, 0);
  assert.equal(plan.staged.length, 1);
  assert.equal(plan.staged[0].keyId, "1");
  assert.equal(plan.staged[0].method, "seed");
  assert.equal(plan.staged[0].entry.kind, "seed");
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  discardPlan(plan);
});

test("an unsupported method blocks the plan and never echoes the text", () => {
  const session = createSecureSession();
  const sentinel = "SENTINEL-DO-NOT-ECHO-9f3a";
  const plan = planTurnOn(session, [{ keyId: 7, methods: { hex: sentinel } }], {});
  assert.equal(plan.ok, false);
  assert.equal(plan.staged.length, 0);
  assert.deepEqual(plan.blockers, [{ keyId: "7", method: "hex", reason: "unsupported" }]);
  assert.equal(JSON.stringify(plan.blockers).includes(sentinel), false);
  assert.equal(JSON.stringify(plan).includes(sentinel), false);
});

test("a converter that throws is an invalid blocker, not a crash", () => {
  const session = createSecureSession();
  const sentinel = "SENTINEL-INVALID-4b2c";
  const plan = planTurnOn(session, [{ keyId: 2, methods: { seed: sentinel } }], {
    seed: () => { throw new Error("bad words"); },
  });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "2", method: "seed", reason: "invalid" }]);
  assert.equal(JSON.stringify(plan.blockers).includes(sentinel), false);
});

test("a known method with no converter is a no-converter blocker", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {});
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "1", method: "seed", reason: "no-converter" }]);
});

test("planTurnOn ignores empty text and never stages it", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "", hex: "" } }], {});
  assert.equal(plan.ok, true);
  assert.equal(plan.staged.length, 0);
  assert.equal(plan.blockers.length, 0);
});

test("planTurnOn stages one entry per key and method", () => {
  const session = createSecureSession();
  const keys = [
    { keyId: 1, methods: { seed: "a", rolls: "b" } },
    { keyId: 2, methods: { seed: "c" } },
  ];
  const converters = {
    seed: () => seedEntry(12),
    rolls: () => rollsEntry("base10", 6),
  };
  const plan = planTurnOn(session, keys, converters);
  assert.equal(plan.ok, true);
  assert.equal(plan.staged.length, 3);
  assert.deepEqual(plan.staged.map((item) => `${item.keyId}:${item.method}`), ["1:seed", "1:rolls", "2:seed"]);
  discardPlan(plan);
});

test("commitTurnOn refuses a blocked plan and changes nothing", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { hex: "deadbeef" } }], {});
  assert.equal(plan.ok, false);
  const before = session.generation;
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  assert.equal(session.generation, before);
});

test("commitTurnOn refuses a malformed plan", () => {
  const session = createSecureSession();
  assert.throws(() => commitTurnOn(session, { ok: true, staged: null }), code("PLAN_BLOCKED"));
  assert.throws(() => commitTurnOn(session, null), code("PLAN_BLOCKED"));
});

test("commitTurnOn installs every staged entry and turns the switch on", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); return entry; },
  });
  const before = session.generation;
  commitTurnOn(session, plan);
  assert.equal(session.on, true);
  assert.ok(session.generation > before);
  const installed = sessionGet(session, 1, "seed");
  assert.ok(installed);
  assert.equal(installed.kind, "seed");
  assert.deepEqual([...seedIndices(installed)], [5]);
});

test("commitTurnOn installs every staged entry across keys", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [
    { keyId: 1, methods: { seed: "a" } },
    { keyId: 2, methods: { rolls: "b" } },
  ], {
    seed: () => seedEntry(12),
    rolls: () => rollsEntry("base10", 6),
  });
  commitTurnOn(session, plan);
  assert.equal(session.entries.size, 2);
  assert.equal(sessionGet(session, 1, "seed").kind, "seed");
  assert.equal(sessionGet(session, 2, "rolls").kind, "rolls");
});

test("discardPlan wipes every staged entry", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); return entry; },
  });
  assert.equal(plan.ok, true);
  const staged = plan.staged[0].entry;
  const buffer = staged.indices;
  discardPlan(plan);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(staged.wiped, true);
  assert.equal(plan.staged.length, 0);
});

test("commitTurnOff in convert mode returns the texts and wipes the entries", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const buffer = entry.indices;
  const plan = planTurnOff(session, { seed: (e) => `words:${seedIndices(e).length}` });
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.staged, [{ keyId: "1", method: "seed", text: "words:1" }]);
  const texts = commitTurnOff(session, plan, "convert");
  assert.deepEqual(texts, [{ keyId: "1", method: "seed", text: "words:1" }]);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(entry.wiped, true);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

test("planTurnOff blocks when a serializer is missing", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, {});
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "1", method: "seed", reason: "no-serializer" }]);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 1);
});

test("planTurnOff serializes every entry", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  sessionSet(session, 2, "rolls", rollsEntry("base10", 6));
  const plan = planTurnOff(session, {
    seed: () => "seed-text",
    rolls: () => "rolls-text",
  });
  assert.equal(plan.ok, true);
  assert.deepEqual(plan.staged, [
    { keyId: "1", method: "seed", text: "seed-text" },
    { keyId: "2", method: "rolls", text: "rolls-text" },
  ]);
});

test("commitTurnOff in clear mode wipes everything and returns no texts", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const buffer = entry.indices;
  const texts = commitTurnOff(session, null, "clear");
  assert.deepEqual(texts, []);
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

test("commitTurnOff refuses an unknown mode", () => {
  const session = createSecureSession();
  assert.throws(() => commitTurnOff(session, null, "sideways"), code("BAD_MODE"));
});

test("commitTurnOff refuses a stale plan", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionSet(session, 1, "seed", seedEntry(12));
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
  assert.equal(session.entries.size, 1);
});

test("commitTurnOff refuses a plan whose entry was deleted", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionDeleteKey(session, 1);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
});

test("commitTurnOff refuses a plan that misses an entry", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionSet(session, 2, "seed", seedEntry(12));
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
  assert.equal(session.entries.size, 2);
});

test("a key entry can be planned and committed", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { key: "xprv..." } }], {
    key: () => keyEntry(),
  });
  assert.equal(plan.ok, true);
  commitTurnOn(session, plan);
  const installed = sessionGet(session, 1, "key");
  assert.equal(installed.kind, "key");
  assert.equal(installed.vault.length, 0);
});

test("SUPPORTED_METHODS is frozen and every value is false in this round", () => {
  assert.ok(Object.isFrozen(SUPPORTED_METHODS));
  assert.deepEqual(Object.keys(SUPPORTED_METHODS).sort(), ["cards", "key", "rolls", "seed"]);
  for (const value of Object.values(SUPPORTED_METHODS)) assert.equal(value, false);
  for (const method of ["seed", "key", "rolls", "cards", "hex", "base10", "toString", "", null, undefined]) {
    assert.equal(isSupported(method), false);
  }
});

test("SecureEntryError carries a code and a message without the input", () => {
  const error = new SecureEntryError("BAD_INDEX", "A BIP39 word index is 0..2047.");
  assert.ok(error instanceof Error);
  assert.equal(error.name, "SecureEntryError");
  assert.equal(error.code, "BAD_INDEX");
  assert.equal(error.message, "A BIP39 word index is 0..2047.");
});

test("discarding a turn-off plan leaves the live entries intact", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  seedSet(entry, 1, 6);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const buffer = entry.indices;
  const plan = planTurnOff(session, { seed: () => "words" });
  assert.equal(plan.kind, "off");
  assert.equal(plan.ok, true);
  discardPlan(plan);
  assert.equal(plan.staged.length, 0);
  assert.equal(entry.wiped, false);
  assert.equal(entry.count, 2);
  assert.deepEqual([...buffer], [5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  assert.equal(sessionGet(session, 1, "seed"), entry);
  assert.equal(session.entries.size, 1);
  assert.equal(session.on, true);
});

test("a turn-on plan goes stale when the session generation moves", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], { seed: () => seedEntry(12) });
  assert.equal(plan.kind, "on");
  assert.equal(plan.ok, true);
  sessionSet(session, 2, "seed", seedEntry(12));
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_STALE"));
  assert.equal(session.entries.size, 1);
  assert.equal(session.on, false);
  discardPlan(plan);
});

test("a turn-off plan goes stale when the session generation moves", () => {
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  session.on = true;
  const plan = planTurnOff(session, { seed: () => "text" });
  sessionSet(session, 2, "seed", seedEntry(12));
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
  assert.equal(session.entries.size, 2);
  assert.equal(session.on, true);
});

test("a turn-off plan goes stale when an entry's rev moves", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const plan = planTurnOff(session, { seed: () => "text" });
  seedSet(entry, 0, 5);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
  assert.equal(session.entries.size, 1);
  assert.equal(session.on, true);
  assert.equal(entry.wiped, false);
});

test("touchEntry makes a turn-off plan stale", () => {
  const session = createSecureSession();
  const entry = keyEntry();
  sessionSet(session, 1, "key", entry);
  session.on = true;
  const plan = planTurnOff(session, { key: () => "xprv" });
  touchEntry(entry);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
  assert.equal(session.entries.size, 1);
  assert.equal(session.on, true);
});

test("a direct wipeEntry invalidates the guard", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  wipeEntry(entry);
  assert.equal(guard.current(), false);
});

test("key ids are canonical: 1 and \"1\" name the same key", () => {
  const session = createSecureSession();
  const first = seedEntry(12);
  sessionSet(session, 1, "seed", first);
  assert.equal(sessionGet(session, "1", "seed"), first);
  assert.equal(sessionGet(session, 1, "seed"), first);
  const second = seedEntry(12);
  sessionSet(session, "1", "seed", second);
  assert.equal(session.entries.size, 1);
  assert.equal(first.wiped, true);
  assert.equal(sessionGet(session, 1, "seed"), second);
  sessionDeleteKey(session, "1");
  assert.equal(sessionGet(session, 1, "seed"), null);
  assert.equal(second.wiped, true);
  assert.equal(session.entries.size, 0);
});

test("a bad key id is refused with BAD_KEY", () => {
  const session = createSecureSession();
  for (const bad of [Symbol("k"), {}, [], "", -1, 1.5, NaN, null, undefined, true]) {
    assert.throws(() => sessionGet(session, bad, "seed"), code("BAD_KEY"));
    assert.throws(() => sessionSet(session, bad, "seed", seedEntry(12)), code("BAD_KEY"));
    assert.throws(() => sessionDeleteKey(session, bad), code("BAD_KEY"));
  }
  assert.equal(session.entries.size, 0);
});

test("planTurnOn refuses a bad key id and wipes what it staged", () => {
  const session = createSecureSession();
  const staged = [];
  const converters = {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); staged.push(entry); return entry; },
  };
  assert.throws(
    () => planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }, { keyId: Symbol("bad"), methods: { seed: "b" } }], converters),
    code("BAD_KEY"),
  );
  assert.equal(staged.length, 1);
  assert.equal(staged[0].wiped, true);
  assert.ok(staged[0].indices.every((value) => value === 0));
  assert.equal(session.entries.size, 0);
});

test("sessionSet refuses an entry that does not match its method", () => {
  const session = createSecureSession();
  const existing = seedEntry(12);
  sessionSet(session, 1, "seed", existing);
  assert.throws(() => sessionSet(session, 1, "seed", rollsEntry("base10", 6)), code("BAD_ENTRY"));
  assert.throws(() => sessionSet(session, 1, "seed", { kind: "seed", length: 12, indices: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], count: 0, wiped: false }), code("BAD_ENTRY"));
  assert.throws(() => sessionSet(session, 1, "seed", { kind: "seed", length: 12, indices: new Uint8Array(12), count: 0, wiped: false }), code("BAD_ENTRY"));
  const wiped = seedEntry(12);
  wipeEntry(wiped);
  assert.throws(() => sessionSet(session, 1, "seed", wiped), code("BAD_ENTRY"));
  assert.equal(existing.wiped, false);
  assert.equal(sessionGet(session, 1, "seed"), existing);
  assert.equal(session.entries.size, 1);
});

test("commitTurnOn refuses an invalid staged item before installing anything", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }], { seed: () => seedEntry(12) });
  assert.equal(plan.ok, true);
  plan.staged.push({ keyId: "2", method: "seed", entry: { kind: "seed", length: 12, indices: [0], count: 0, wiped: false } });
  assert.throws(() => commitTurnOn(session, plan), code("BAD_ENTRY"));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  discardPlan(plan);
});

test("sessionWipe wipes every entry even when one wipe throws", () => {
  const session = createSecureSession();
  const broken = { kind: "seed", length: 12, count: 0, wiped: false };
  session.entries.set("0:seed", broken);
  session.meta.set("0:seed", { keyId: "0", method: "seed" });
  const valid = seedEntry(12);
  seedSet(valid, 0, 7);
  sessionSet(session, 1, "seed", valid);
  session.on = true;
  const buffer = valid.indices;
  assert.throws(() => sessionWipe(session), code("WIPE_PARTIAL"));
  assert.ok(buffer.every((value) => value === 0));
  assert.equal(valid.wiped, true);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

test("planTurnOn refuses malformed keys and methods", () => {
  const session = createSecureSession();
  assert.throws(() => planTurnOn(session, null, {}), code("BAD_INPUT"));
  assert.throws(() => planTurnOn(session, "keys", {}), code("BAD_INPUT"));
  assert.throws(() => planTurnOn(session, [{ keyId: 1, methods: new Map() }], {}), code("BAD_INPUT"));
  assert.throws(() => planTurnOn(session, [{ keyId: 1, methods: ["seed"] }], {}), code("BAD_INPUT"));
  assert.throws(() => planTurnOn(session, [{ keyId: 1, methods: null }], {}), code("BAD_INPUT"));
  assert.equal(session.entries.size, 0);
});

// §1: values, not just shapes.

test("sessionSet refuses out-of-range seed, roll and card values", () => {
  const session = createSecureSession();
  const seed = seedEntry(12);
  seed.indices[0] = 2048;
  seed.count = 1;
  assert.throws(() => sessionSet(session, 1, "seed", seed), code("BAD_ENTRY"));

  const rolls = rollsEntry("base10", 6);
  rolls.rolls[0] = 7;
  rolls.count = 1;
  assert.throws(() => sessionSet(session, 1, "rolls", rolls), code("BAD_ENTRY"));

  const cards = cardsEntry("shuffle", 6);
  cards.cards[0] = 52;
  cards.count = 1;
  assert.throws(() => sessionSet(session, 1, "cards", cards), code("BAD_ENTRY"));

  assert.equal(session.entries.size, 0);
});

test("sessionSet refuses a frozen entry", () => {
  const session = createSecureSession();
  const frozen = Object.freeze(seedEntry(12));
  assert.throws(() => sessionSet(session, 1, "seed", frozen), code("BAD_ENTRY"));
  assert.equal(session.entries.size, 0);
});

test("planTurnOn turns out-of-range values and frozen entries into invalid blockers", () => {
  const session = createSecureSession();
  const seed = seedEntry(12);
  seed.indices[0] = 2048;
  seed.count = 1;
  const rolls = rollsEntry("base10", 6);
  rolls.rolls[0] = 7;
  rolls.count = 1;
  const cards = cardsEntry("shuffle", 6);
  cards.cards[0] = 52;
  cards.count = 1;
  const frozen = Object.freeze(seedEntry(12));
  const plan = planTurnOn(session, [
    { keyId: 1, methods: { seed: "a" } },
    { keyId: 2, methods: { rolls: "b" } },
    { keyId: 3, methods: { cards: "c" } },
    { keyId: 4, methods: { seed: "d" } },
  ], {
    seed: (text) => (text === "a" ? seed : frozen),
    rolls: () => rolls,
    cards: () => cards,
  });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [
    { keyId: "1", method: "seed", reason: "invalid" },
    { keyId: "2", method: "rolls", reason: "invalid" },
    { keyId: "3", method: "cards", reason: "invalid" },
    { keyId: "4", method: "seed", reason: "invalid" },
  ]);
  assert.equal(plan.staged.length, 0);
  assert.equal(session.entries.size, 0);
});

// §2: one entry, one place.

test("sessionSet refuses to install the same object under two keys", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  assert.throws(() => sessionSet(session, 2, "seed", entry), code("BAD_ENTRY"));
  assert.equal(session.entries.size, 1);
  assert.equal(sessionGet(session, 1, "seed"), entry);
  assert.equal(sessionGet(session, 2, "seed"), null);
});

test("planTurnOn blocks a converter that returns one shared object for two keys", () => {
  const session = createSecureSession();
  const shared = seedEntry(12);
  const plan = planTurnOn(session, [
    { keyId: 1, methods: { seed: "a" } },
    { keyId: 2, methods: { seed: "b" } },
  ], { seed: () => shared });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "2", method: "seed", reason: "invalid" }]);
  assert.equal(plan.staged.length, 1);
  assert.equal(plan.staged[0].entry, shared);
  discardPlan(plan);
  assert.equal(shared.wiped, true);
});

test("planTurnOn blocks a converter that returns an installed entry", () => {
  const session = createSecureSession();
  const installed = seedEntry(12);
  sessionSet(session, 1, "seed", installed);
  const plan = planTurnOn(session, [{ keyId: 2, methods: { seed: "b" } }], { seed: () => installed });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "2", method: "seed", reason: "invalid" }]);
  assert.equal(plan.staged.length, 0);
  assert.equal(installed.wiped, false);
  assert.equal(sessionGet(session, 1, "seed"), installed);
});

test("planTurnOn gives a duplicate blocker for the same canonical pair", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [
    { keyId: 1, methods: { seed: "a" } },
    { keyId: "1", methods: { seed: "b" } },
  ], { seed: () => seedEntry(12) });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "1", method: "seed", reason: "duplicate" }]);
  assert.equal(plan.staged.length, 1);
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 0);
  discardPlan(plan);
});

// §3: edits invalidate late results.

test("seedSet on an installed entry makes a guard stale", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  seedSet(entry, 0, 5);
  assert.equal(guard.current(), false);
});

test("rollsPush on an installed entry makes a guard stale", () => {
  const session = createSecureSession();
  const entry = rollsEntry("base10", 6);
  sessionSet(session, 1, "rolls", entry);
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  rollsPush(entry, 3);
  assert.equal(guard.current(), false);
});

test("touchEntry on an installed entry makes a guard stale", () => {
  const session = createSecureSession();
  const entry = keyEntry();
  sessionSet(session, 1, "key", entry);
  const guard = sessionGuard(session);
  assert.equal(guard.current(), true);
  touchEntry(entry);
  assert.equal(guard.current(), false);
});

// §4: turn-off plans refuse what cannot be restored faithfully.

test("planTurnOff blocks a wiped entry and never serializes it", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 5);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  wipeEntry(entry);
  let serialized = false;
  const plan = planTurnOff(session, { seed: () => { serialized = true; return "text"; } });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "1", method: "seed", reason: "invalid" }]);
  assert.equal(serialized, false);
  assert.equal(plan.staged.length, 0);
});

test("commitTurnOff convert attaches the texts to a WIPE_PARTIAL error", () => {
  const session = createSecureSession();
  const entry = keyEntry();
  entry.vault.setText("secret");
  sessionSet(session, 1, "key", entry);
  session.on = true;
  const plan = planTurnOff(session, { key: () => "xprv-text" });
  assert.equal(plan.ok, true);
  Object.freeze(entry);
  let caught;
  try { commitTurnOff(session, plan, "convert"); } catch (error) { caught = error; }
  assert.ok(caught instanceof SecureEntryError);
  assert.equal(caught.code, "WIPE_PARTIAL");
  assert.deepEqual(caught.texts, [{ keyId: "1", method: "key", text: "xprv-text" }]);
  assert.equal(Object.keys(caught).includes("texts"), false);
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
});

// §5: plan kinds are enforced.

test("commitTurnOn refuses an off-plan", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  sessionSet(session, 1, "seed", entry);
  session.on = true;
  const plan = planTurnOff(session, { seed: () => "text" });
  assert.equal(plan.kind, "off");
  const before = session.generation;
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 1);
  assert.equal(session.on, true);
  assert.equal(session.generation, before);
  assert.equal(entry.wiped, false);
});

test("commitTurnOff convert refuses an on-plan", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }], { seed: () => seedEntry(12) });
  assert.equal(plan.kind, "on");
  const before = session.generation;
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 0);
  assert.equal(session.on, false);
  assert.equal(session.generation, before);
  discardPlan(plan);
});

// §6: coded errors only.

test("wipeEntry on a malformed entry throws BAD_ENTRY, not a TypeError", () => {
  assert.throws(() => wipeEntry({ kind: "seed" }), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "seed", indices: [0, 0, 0] }), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "rolls" }), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "cards" }), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "key" }), code("BAD_ENTRY"));
  assert.throws(() => wipeEntry({ kind: "key", vault: {} }), code("BAD_ENTRY"));
});

// Claude's round-3 check (Muse's review): an entry owned by another session
// is refused before any install, and wiping a frozen entry is a coded refusal.
test("an entry installed in another session is blocked at planning and refused at commit before any install", () => {
  const sessionA = createSecureSession();
  const sessionB = createSecureSession();
  const shared = seedEntry(12);
  seedSet(shared, 0, 5);
  sessionSet(sessionA, 1, "seed", shared);
  const plan = planTurnOn(sessionB, [{ keyId: 2, methods: { seed: "x" } }], { seed: () => shared });
  assert.equal(plan.ok, false);
  assert.ok(plan.blockers.some((b) => b.reason === "invalid"));
  const fresh = seedEntry(12);
  const forged = { kind: "on", ok: true, generation: sessionB.generation, blockers: [], staged: [
    { keyId: "3", method: "seed", entry: fresh },
    { keyId: "4", method: "seed", entry: shared },
  ] };
  assert.throws(() => commitTurnOn(sessionB, forged), (error) => error instanceof SecureEntryError && error.code === "PLAN_BLOCKED");
  assert.equal(sessionB.entries.size, 0, "nothing was installed in session B");
  assert.equal(sessionA.entries.size, 1, "session A is untouched");
});

test("wiping a frozen entry zeroes its buffer and throws a coded BAD_ENTRY", () => {
  const entry = seedEntry(12);
  seedSet(entry, 0, 7);
  const buffer = entry.indices;
  Object.freeze(entry);
  assert.throws(() => wipeEntry(entry), (error) => error instanceof SecureEntryError && error.code === "BAD_ENTRY");
  assert.ok(buffer.every((value) => value === 0), "the word buffer is zeroed even though the entry is frozen");
});

test("commitTurnOff clear also wipes a pending turn-on plan's staged entries", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 9); return entry; },
  });
  assert.equal(plan.ok, true);
  const staged = plan.staged[0].entry;
  const buffer = staged.indices;
  assert.deepEqual(commitTurnOff(session, plan, "clear"), []);
  assert.ok(buffer.every((value) => value === 0), "the staged word buffer is zeroed");
  assert.equal(staged.wiped, true);
  assert.equal(plan.staged.length, 0);
});

test("commitTurnOff clear with a turn-off plan wipes the live entries once and returns no texts", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 4);
  sessionSet(session, 1, "seed", entry);
  const plan = planTurnOff(session, { seed: () => "text" });
  assert.deepEqual(commitTurnOff(session, plan, "clear"), []);
  assert.ok(entry.indices.every((value) => value === 0));
  assert.equal(session.entries.size, 0);
});

test("an entry whose owner cannot be redefined is refused with BAD_ENTRY before any install", () => {
  const session = createSecureSession();
  const odd = seedEntry(12);
  Object.defineProperty(odd, "owner", { value: null, writable: false, configurable: false });
  assert.throws(() => sessionSet(session, 1, "seed", odd), code("BAD_ENTRY"));
  assert.equal(session.entries.size, 0);
  const good = seedEntry(12);
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }, { keyId: 2, methods: { seed: "b" } }], {
    seed: (text) => (text === "a" ? good : odd),
  });
  assert.equal(plan.ok, false);
  assert.deepEqual(plan.blockers, [{ keyId: "2", method: "seed", reason: "invalid" }]);
  discardPlan(plan);
  assert.equal(session.entries.size, 0);
});

test("an entry with a read-only rev is refused with BAD_ENTRY before its buffer changes", () => {
  const entry = seedEntry(12);
  Object.defineProperty(entry, "rev", { value: 0, writable: false, configurable: true });
  assert.throws(() => seedSet(entry, 0, 5), code("BAD_ENTRY"));
  assert.equal(entry.indices[0], 0, "the word buffer is untouched");
  assert.equal(entry.count, 0);
  assert.throws(() => touchEntry(entry), code("BAD_ENTRY"));
  const rolls = rollsEntry("base10", 10);
  Object.defineProperty(rolls, "rev", { get: () => 0, configurable: true });
  assert.throws(() => rollsPush(rolls, 3), code("BAD_ENTRY"));
  assert.equal(rolls.rolls[0], 0);
});

test("replacing an entry installs the new one even when the old one cannot be marked wiped", () => {
  const session = createSecureSession();
  const old = seedEntry(12);
  seedSet(old, 0, 6);
  sessionSet(session, 1, "seed", old);
  const oldBuffer = old.indices;
  Object.freeze(old);
  const replacement = seedEntry(12);
  sessionSet(session, 1, "seed", replacement);
  assert.equal(sessionGet(session, 1, "seed"), replacement);
  assert.ok(oldBuffer.every((value) => value === 0), "the replaced word buffer is zeroed");
});

// Red team on efa778cc (Kimi K3.1, SE-01).
test("a repeat direct wipe makes a guard taken after the refill stale", () => {
  const session = createSecureSession();
  const key = keyEntry();
  sessionSet(session, 1, "key", key);
  wipeEntry(key);
  key.vault.setText("refilled secret");
  touchEntry(key);
  const guard = sessionGuard(session);
  wipeEntry(key);
  assert.equal(key.vault.length, 0);
  assert.equal(guard.current(), false, "the second wipe invalidates late results");
});

// Review on efa778cc (Kimi K3).
test("wiping a frozen installed entry still makes a guard stale before it refuses", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 3);
  sessionSet(session, 1, "seed", entry);
  const guard = sessionGuard(session);
  Object.freeze(entry);
  assert.throws(() => wipeEntry(entry), code("BAD_ENTRY"));
  assert.ok(entry.indices.every((value) => value === 0));
  assert.equal(guard.current(), false);
});

// Red team on efa778cc (Kimi K3.1, SE-02).
test("a blocked turn-off plan carries no secret text", () => {
  const secret = "SENTINEL-SEED-SECRET-9f3a";
  const session = createSecureSession();
  sessionSet(session, 1, "seed", seedEntry(12));
  sessionSet(session, 2, "key", keyEntry());
  let calls = 0;
  const missing = planTurnOff(session, { seed: () => { calls += 1; return secret; } });
  assert.equal(missing.ok, false);
  assert.deepEqual(missing.blockers, [{ keyId: "2", method: "key", reason: "no-serializer" }]);
  assert.equal(calls, 0, "nothing is serialized once a blocker is known");
  assert.equal(missing.staged.length, 0);
  // A serializer that fails after another succeeded: the texts made so far
  // are dropped with the plan.
  const failing = planTurnOff(session, { seed: () => secret, key: () => { throw new Error("no"); } });
  assert.equal(failing.ok, false);
  assert.deepEqual(failing.blockers, [{ keyId: "2", method: "key", reason: "invalid" }]);
  assert.equal(failing.staged.length, 0);
  assert.equal(JSON.stringify(failing).includes(secret), false);
  assert.throws(() => commitTurnOff(session, failing, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 2);
});

// Codex review on efa778cc.
test("deleting a key makes its pending turn-on plan stale", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { rolls: "16" } }], {
    rolls: (text) => { const entry = rollsEntry("base10", 2); for (const face of text) rollsPush(entry, Number(face)); return entry; },
  });
  assert.equal(plan.ok, true);
  const staged = plan.staged[0].entry;
  sessionDeleteKey(session, 1);
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_STALE"));
  assert.equal(sessionGet(session, 1, "rolls"), null);
  assert.equal(session.on, false);
  discardPlan(plan);
  assert.ok(staged.rolls.every((value) => value === 0));
});

// Review on efa778cc (Kimi K3).
test("a discarded turn-on plan cannot be committed", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 9); return entry; },
  });
  assert.equal(plan.ok, true);
  discardPlan(plan);
  const before = session.generation;
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_BLOCKED"));
  assert.equal(session.on, false);
  assert.equal(session.entries.size, 0);
  assert.equal(session.generation, before);
});

// Review on efa778cc (GLM 5.3).
test("commitTurnOff convert refuses a plan that names one entry twice", () => {
  const session = createSecureSession();
  const first = seedEntry(12), second = seedEntry(12);
  seedSet(first, 0, 1);
  seedSet(second, 0, 2);
  sessionSet(session, 1, "seed", first);
  sessionSet(session, 2, "seed", second);
  const plan = planTurnOff(session, { seed: () => "text" });
  assert.equal(plan.ok, true);
  plan.staged = [plan.staged[0], plan.staged[0]];
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_BLOCKED"));
  assert.equal(session.entries.size, 2);
  assert.equal(second.indices[0], 2, "the entry the plan left out is not wiped");
});

// Review on 89f0ab00 (DeepSeek V4.1 red team, MiniMax).
test("End Session wipes a pending turn-on plan's staged entries", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 9); return entry; },
  });
  assert.equal(plan.ok, true);
  const staged = plan.staged[0].entry;
  const buffer = staged.indices;
  sessionWipe(session);
  assert.ok(buffer.every((value) => value === 0), "the staged word buffer is zeroed");
  assert.equal(staged.wiped, true);
  assert.equal(plan.staged.length, 0);
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_STALE"));
  assert.equal(session.on, false);
  assert.equal(session.entries.size, 0);
});

test("deleting a key wipes a pending turn-on plan's staged entries at once", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { rolls: "16" } }, { keyId: 2, methods: { seed: "abandon" } }], {
    rolls: (text) => { const entry = rollsEntry("base10", 2); for (const face of text) rollsPush(entry, Number(face)); return entry; },
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 3); return entry; },
  });
  assert.equal(plan.ok, true);
  const [rolls, seed] = plan.staged.map((item) => item.entry);
  sessionDeleteKey(session, 1);
  assert.ok(rolls.rolls.every((value) => value === 0), "the deleted key's staged rolls are zeroed");
  assert.ok(seed.indices.every((value) => value === 0), "the stale plan's other staged entries are zeroed too");
  assert.throws(() => commitTurnOn(session, plan), code("PLAN_STALE"));
});

test("committed and discarded plans leave the pending set, so End Session never wipes a live entry twice", () => {
  const session = createSecureSession();
  const converters = { seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 6); return entry; } };
  const kept = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon" } }], converters);
  const dropped = planTurnOn(session, [{ keyId: 2, methods: { seed: "abandon" } }], converters);
  discardPlan(dropped);
  const live = kept.staged[0].entry;
  commitTurnOn(session, kept);
  assert.equal(session.pending.size, 0);
  assert.equal(sessionGet(session, 1, "seed"), live);
  assert.equal(live.indices[0], 6, "committing does not wipe the installed entry");
  sessionWipe(session);
  assert.ok(live.indices.every((value) => value === 0));
});

test("a blocked turn-on plan's staged entries are wiped by End Session too", () => {
  const session = createSecureSession();
  const plan = planTurnOn(session, [{ keyId: 1, methods: { seed: "abandon", unknown: "x" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 8); return entry; },
  });
  assert.equal(plan.ok, false);
  const staged = plan.staged[0].entry;
  sessionWipe(session);
  assert.ok(staged.indices.every((value) => value === 0));
});

// Review on f5a552f8 (Kimi K3.1 red team, MiniMax, GLM 5.3).
test("End Session drops a pending turn-off plan's texts", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 7);
  sessionSet(session, 1, "seed", entry);
  const plan = planTurnOff(session, { seed: () => "SECRET-SEED-TEXT" });
  assert.equal(plan.ok, true);
  const item = plan.staged[0];
  sessionWipe(session);
  assert.equal(plan.staged.length, 0);
  assert.equal(item.text, "", "a caller still holding the item no longer sees the text");
  assert.equal(session.pending.size, 0);
  assert.throws(() => commitTurnOff(session, plan, "convert"), code("PLAN_STALE"));
});

test("deleting a key drops every pending turn-off plan's texts", () => {
  const session = createSecureSession();
  const first = seedEntry(12), second = seedEntry(12);
  seedSet(first, 0, 1);
  seedSet(second, 0, 2);
  sessionSet(session, 1, "seed", first);
  sessionSet(session, 2, "seed", second);
  const plan = planTurnOff(session, { seed: (entry) => `words-${entry.indices[0]}` });
  assert.equal(plan.ok, true);
  const items = [...plan.staged];
  sessionDeleteKey(session, 1);
  assert.ok(items.every((item) => item.text === ""));
  assert.equal(plan.staged.length, 0);
  assert.equal(second.indices[0], 2, "the other key's live entry is not wiped");
  assert.equal(sessionGet(session, 2, "seed"), second);
});

test("discarded and committed turn-off plans leave the pending set; discarding never wipes a live entry", () => {
  const session = createSecureSession();
  const entry = seedEntry(12);
  seedSet(entry, 0, 4);
  sessionSet(session, 1, "seed", entry);
  const dropped = planTurnOff(session, { seed: () => "words" });
  const item = dropped.staged[0];
  discardPlan(dropped);
  assert.equal(item.text, "");
  assert.equal(session.pending.size, 0);
  assert.equal(entry.indices[0], 4);
  const plan = planTurnOff(session, { seed: () => "words" });
  assert.equal(session.pending.size, 1);
  assert.deepEqual(commitTurnOff(session, plan, "convert"), [{ keyId: "1", method: "seed", text: "words" }]);
  assert.equal(session.pending.size, 0);
});

test("an entry staged by another pending turn-on plan is blocked, so discarding one plan never wipes the other's entry", () => {
  const session = createSecureSession();
  const shared = seedEntry(12);
  seedSet(shared, 0, 7);
  const converters = { seed: () => shared };
  const first = planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }], converters);
  const second = planTurnOn(session, [{ keyId: 2, methods: { seed: "b" } }], converters);
  assert.equal(first.ok, true);
  assert.equal(second.ok, false);
  assert.ok(second.blockers.some((b) => b.reason === "invalid"));
  commitTurnOn(session, first);
  discardPlan(second);
  assert.equal(sessionGet(session, 1, "seed"), shared);
  assert.equal(shared.wiped, false);
  assert.equal(shared.indices[0], 7);
});

test("discarding a plan whose staged entry is installed leaves the live entry alone", () => {
  const session = createSecureSession();
  const converters = { seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 5); return entry; } };
  const first = planTurnOn(session, [{ keyId: 1, methods: { seed: "a" } }], converters);
  const live = first.staged[0].entry;
  const second = planTurnOn(session, [{ keyId: 2, methods: { seed: "b" } }], converters);
  const own = second.staged[0].entry;
  commitTurnOn(session, first);
  second.staged.push({ keyId: "3", method: "seed", entry: live });
  discardPlan(second);
  assert.ok(own.indices.every((value) => value === 0), "the plan's own staged entry is wiped");
  assert.equal(live.wiped, false);
  assert.equal(live.indices[0], 5);
  assert.equal(sessionGet(session, 1, "seed"), live);
});

test("a turn-on plan commits only into the session it was made for", () => {
  const sessionA = createSecureSession();
  const sessionB = createSecureSession();
  const plan = planTurnOn(sessionA, [{ keyId: 1, methods: { seed: "a" } }], {
    seed: () => { const entry = seedEntry(12); seedSet(entry, 0, 3); return entry; },
  });
  assert.equal(plan.ok, true);
  assert.equal(sessionA.generation, sessionB.generation);
  assert.throws(() => commitTurnOn(sessionB, plan), code("PLAN_STALE"));
  assert.equal(sessionB.entries.size, 0);
  assert.equal(sessionB.on, false);
  commitTurnOn(sessionA, plan);
  assert.equal(sessionA.entries.size, 1);
});
