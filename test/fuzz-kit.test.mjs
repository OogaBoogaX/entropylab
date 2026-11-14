import { test } from "node:test";
import assert from "node:assert/strict";
import { fuzzEnv, mulberry32, replayLine, withReplay, shrink } from "./fuzz-kit.mjs";

const withEnv = (prefix, vars, fn) => {
  const saved = {};
  for (const [key, value] of Object.entries(vars)) {
    saved[key] = process.env[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
};

test("mulberry32 is deterministic", () => {
  const a = mulberry32(42);
  const b = mulberry32(42);
  assert.deepEqual([a(), a(), a()], [b(), b(), b()]);
});

test("fuzzEnv defaults and overrides", () => {
  const prefix = "FUZZ_KIT_ENV";
  withEnv(prefix, {
    [`${prefix}_SEED`]: undefined,
    [`${prefix}_ITERATIONS`]: undefined,
  }, () => {
    assert.deepEqual(fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }), { seed: 7, iterations: 9 });
  });
  withEnv(prefix, {
    [`${prefix}_SEED`]: "16",
    [`${prefix}_ITERATIONS`]: "30",
  }, () => {
    assert.deepEqual(fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }), { seed: 16, iterations: 30 });
  });
  // The knob only widens: a smaller run would fail the coverage floors.
  for (const narrower of ["0", "1", "8"]) {
    withEnv(prefix, { [`${prefix}_ITERATIONS`]: narrower }, () => {
      assert.throws(() => fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }), /can only widen the run/);
    });
  }
  withEnv(prefix, { [`${prefix}_ITERATIONS`]: "9" }, () => {
    assert.equal(fuzzEnv(prefix, { defaultSeed: 7, defaultIterations: 9 }).iterations, 9);
  });
});

test("fuzzEnv refuses malformed seed and iteration values", () => {
  const prefix = "FUZZ_KIT_BAD_ENV";
  const malformed = ["", " ", "  ", "-1", "+1", "1.5", "abc", "0x10", "1e3", " 1", "1 ", String(Number.MAX_SAFE_INTEGER + 1)];
  for (const key of ["SEED", "ITERATIONS"]) {
    for (const value of malformed) {
      withEnv(prefix, {
        [`${prefix}_SEED`]: undefined,
        [`${prefix}_ITERATIONS`]: undefined,
        [`${prefix}_${key}`]: value,
      }, () => {
        assert.throws(
          () => fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }),
          new RegExp(`${prefix}_${key} must be a non-negative decimal integer`),
        );
      });
    }
  }
});

test("fuzzEnv refuses seeds that do not fit 32 bits", () => {
  const prefix = "FUZZ_KIT_SEED32";
  withEnv(prefix, {
    [`${prefix}_SEED`]: "4294967296",
    [`${prefix}_ITERATIONS`]: "1",
  }, () => {
    assert.throws(
      () => fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }),
      new RegExp(`${prefix}_SEED must be a non-negative decimal integer no greater than 4294967295`),
    );
  });
  withEnv(prefix, {
    [`${prefix}_SEED`]: "4294967295",
    [`${prefix}_ITERATIONS`]: "1",
  }, () => {
    assert.equal(fuzzEnv(prefix, { defaultSeed: 1, defaultIterations: 1 }).seed, 4294967295);
  });
});

test("fuzzEnv refuses invalid defaults", () => {
  const prefix = "FUZZ_KIT_BAD_DEFAULTS";
  withEnv(prefix, {
    [`${prefix}_SEED`]: undefined,
    [`${prefix}_ITERATIONS`]: undefined,
  }, () => {
    for (const defaultSeed of [-1, 1.5, 0x100000000, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(
        () => fuzzEnv(prefix, { defaultSeed, defaultIterations: 1 }),
        /default seed must be a 32-bit unsigned integer/,
      );
    }
    for (const defaultIterations of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(
        () => fuzzEnv(prefix, { defaultSeed: 1, defaultIterations }),
        /default iterations must be a non-negative safe integer/,
      );
    }
  });
});

test("replayLine quotes the file and anchors an escaped test name", () => {
  const line = replayLine("HDKEY_FUZZ", 123, 456, "rust-bitcoin (WASM) and @scure/bip32 derive identical nodes", "test/a b/hdkey.test.mjs");
  assert.equal(
    line,
    "Replay: HDKEY_FUZZ_SEED=123 HDKEY_FUZZ_ITERATIONS=456 node --test --test-name-pattern '^rust-bitcoin \\(WASM\\) and @scure/bip32 derive identical nodes$' 'test/a b/hdkey.test.mjs'",
  );
  const pattern = line.match(/--test-name-pattern '([^']*)'/)[1];
  assert.ok(new RegExp(pattern).test("rust-bitcoin (WASM) and @scure/bip32 derive identical nodes"));
  assert.ok(!new RegExp(pattern).test("prefix rust-bitcoin (WASM) and @scure/bip32 derive identical nodes"));
});

test("replayLine shell-quotes a single quote in the file", () => {
  const line = replayLine("P", 1, 2, "name", "test/it's here.test.mjs");
  assert.ok(line.endsWith("'test/it'\\''s here.test.mjs'"));
});

test("withReplay appends the line without losing the original assertion", () => {
  const error = new assert.AssertionError({ message: "original failure" });
  const returned = withReplay(error, "Replay: P_SEED=1 P_ITERATIONS=2 node --test 'x'");
  assert.equal(returned, error);
  assert.match(error.message, /^original failure\nReplay: P_SEED=1 P_ITERATIONS=2 node --test 'x'$/);
});

test("shrink keeps only candidates that throw the same assertion message", () => {
  const original = { a: [1, 2, 3, 4], b: "hello world", c: 42, d: { e: "xyz", f: [5, 6] } };
  const predicate = (candidate) => {
    if (Array.isArray(candidate.a) && candidate.a.includes(3) &&
        typeof candidate.b === "string" && candidate.b.includes("hello") &&
        candidate.c === 42) {
      throw new Error("same failure");
    }
    throw new Error("different failure");
  };
  const shrunk = shrink(original, predicate);
  assert.ok(JSON.stringify(shrunk).length < JSON.stringify(original).length);
  assert.deepEqual(shrunk.a, [3]);
  assert.equal(shrunk.b, "hello");
  assert.equal(shrunk.c, 42);
  assert.equal(shrunk.d, undefined);
  assert.throws(() => predicate(shrunk), /same failure/);
});

test("shrink returns the original when the predicate does not throw", () => {
  const original = { a: 1, b: 2 };
  assert.deepEqual(shrink(original, () => false), original);
});

test("shrink reduces root-level scalar cases", () => {
  assert.equal(shrink("aaaaaaaa", (s) => { if (typeof s === "string" && s.startsWith("aa")) throw new Error("same"); throw new Error("other"); }), "aa");
  assert.equal(shrink(42, (n) => { if (typeof n === "number" && n >= 0) throw new Error("same"); throw new Error("other"); }), 0);
  assert.equal(shrink(true, (v) => { if (v === true || v === 0) throw new Error("same"); throw new Error("other"); }), 0);
  assert.equal(shrink(null, (v) => { if (v === null || v === 0) throw new Error("same"); throw new Error("other"); }), 0);
});
