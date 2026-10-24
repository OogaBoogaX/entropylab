// Shared fuzz harness: deterministic PRNG, env-driven seed/iteration
// selection, replayable failures, and a ddmin-style shrinker.
const escapeRegExp = (text) => String(text).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const mulberry32 = (seed) => {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const envInt = (name, raw, max) => {
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${name} must be a non-negative decimal integer${max === 0xffffffff ? " no greater than 4294967295" : ""}, got ${raw}`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > max) {
    throw new Error(`${name} must be a non-negative decimal integer${max === 0xffffffff ? " no greater than 4294967295" : ""}, got ${raw}`);
  }
  return value;
};

export const fuzzEnv = (prefix, { defaultSeed, defaultIterations }) => {
  if (!Number.isSafeInteger(defaultSeed) || defaultSeed < 0 || defaultSeed > 0xffffffff) {
    throw new Error(`default seed must be a 32-bit unsigned integer, got ${defaultSeed}`);
  }
  if (!Number.isSafeInteger(defaultIterations) || defaultIterations < 0) {
    throw new Error(`default iterations must be a non-negative safe integer, got ${defaultIterations}`);
  }
  const seedRaw = process.env[`${prefix}_SEED`];
  const iterationsRaw = process.env[`${prefix}_ITERATIONS`];
  const seed = seedRaw === undefined ? defaultSeed : envInt(`${prefix}_SEED`, seedRaw, 0xffffffff);
  const iterations = iterationsRaw === undefined ? defaultIterations : envInt(`${prefix}_ITERATIONS`, iterationsRaw, Number.MAX_SAFE_INTEGER);
  // The knob widens a run. Each fuzzer's coverage floors ("every flavor
  // exercised", minimum build counts) are calibrated to its default count, so
  // a smaller run would fail them for no defect: refuse it up front.
  if (iterations < defaultIterations) {
    throw new Error(`${prefix}_ITERATIONS can only widen the run: got ${iterations}, the default is ${defaultIterations}`);
  }
  return { seed, iterations };
};

const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;

export const replayLine = (prefix, seed, iterations, testName, file) => {
  const pattern = `^${escapeRegExp(testName)}$`;
  return `Replay: ${prefix}_SEED=${seed} ${prefix}_ITERATIONS=${iterations} node --test --test-name-pattern ${shellQuote(pattern)} ${shellQuote(file)}`;
};

export const withReplay = (error, line) => {
  if (error && typeof error === "object" && typeof error.message === "string") {
    error.message += `\n${line}`;
  }
  return error;
};

const size = (value) => JSON.stringify(value).length;
const clone = (value) => JSON.parse(JSON.stringify(value));
const getAt = (root, path) => path.reduce((node, key) => node[key], root);
const setAt = (root, path, value) => {
  if (path.length === 0) return value;
  const parent = getAt(root, path.slice(0, -1));
  parent[path[path.length - 1]] = value;
  return root;
};

const collectReductions = (node, path, root, out) => {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const candidate = clone(root);
      getAt(candidate, path).splice(i, 1);
      out.push(candidate);
    }
    node.forEach((child, i) => collectReductions(child, [...path, i], root, out));
    return;
  }
  if (typeof node === "string") {
    const variants = ["", node.slice(0, Math.floor(node.length / 2)), node.slice(Math.floor(node.length / 2)), node.slice(0, -1), node.slice(1)];
    for (const variant of variants) {
      if (variant === node) continue;
      const candidate = clone(root);
      out.push(setAt(candidate, path, variant));
    }
    return;
  }
  if (node && typeof node === "object") {
    for (const key of Object.keys(node)) {
      const candidate = clone(root);
      delete getAt(candidate, path)[key];
      out.push(candidate);
    }
    for (const key of Object.keys(node)) {
      collectReductions(node[key], [...path, key], root, out);
    }
    return;
  }
  for (const empty of [0, "", null]) {
    if (node === empty) continue;
    const candidate = clone(root);
    out.push(setAt(candidate, path, empty));
  }
};

export const shrink = (caseObj, predicate) => {
  let baseline;
  try {
    predicate(caseObj);
    return clone(caseObj);
  } catch (error) {
    baseline = error && error.message;
  }
  if (typeof baseline !== "string") return clone(caseObj);
  let current = clone(caseObj);
  let changed = true;
  while (changed) {
    changed = false;
    const candidates = [];
    collectReductions(current, [], current, candidates);
    for (const candidate of candidates) {
      if (size(candidate) < size(current)) {
        let same = false;
        try {
          predicate(candidate);
        } catch (error) {
          same = error && error.message === baseline;
        }
        if (same) {
          current = candidate;
          changed = true;
          break;
        }
      }
    }
  }
  return current;
};
