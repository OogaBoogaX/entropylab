// Tests for src/js/browser-check.js using Node's built-in test runner.
// The module is a browser IIFE, so each test executes it inside a sandbox
// with stubbed window/document/crypto/BigInt/TextEncoder globals and asserts
// when it kills the page (replaces document.body with the failure report)
// and when it leaves a healthy page untouched.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const src = read("src/js/browser-check.js");

// entropylab.html is a CI-generated artifact, not a committed file. Tests that
// read it require a fresh local build.
const ensureBuild = () => {
  if (!existsSync(join(root, "entropylab.html"))) {
    execFileSync(process.execPath, [join(root, "scripts/build.mjs")], { stdio: "inherit" });
  }
};

const PAGE = '<div id="btc-calc">wallet app</div>';

// A deterministic but well-behaved CSPRNG stub: every call fills the buffer
// with a distinct nonzero pattern so the uniqueness check can pass.
const workingCrypto = () => {
  let salt = 0;
  return {
    getRandomValues(bytes) {
      for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + salt * 17 + 1) & 0xff;
      salt += 1;
      return bytes;
    },
  };
};

// The disclaimer's proof digit is not drawn from the CSPRNG; a single-byte
// draw (the old proof digit's shape) fails the test that asserts it is gone.
const noProofDrawCrypto = () => {
  const base = workingCrypto();
  return {
    getRandomValues(array) {
      if (array.length === 1) throw new Error("the disclaimer drew from the CSPRNG");
      return base.getRandomValues(array);
    },
  };
};

// A performance.now() stand-in whose readings the tests set: the first is
// taken when the overlay is revealed, the next when "I Understand" is pressed.
const fakeClock = (...readings) => ({ now: () => readings.shift() });
const DIGIT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];
// The digits whose proof sentence the second step is showing.
const shownProofDigits = (elements) =>
  DIGIT_WORDS.flatMap((_, digit) => (elements[`beta-disclaimer-proof-text-${digit}`].hidden ? [] : [digit]));

// A minimal in-memory localStorage stand-in for the disclaimer gate tests.
const memoryStorage = (initial = {}) => ({
  getItem: (key) => (key in initial ? initial[key] : null),
  setItem: (key, value) => {
    initial[key] = String(value);
  },
  dump: () => initial,
});

// A fake disclaimer overlay recording what the gate did: two step cards, the
// first step's accept button and the second step's confirm button.
const disclaimerDom = () => {
  const calls = { shown: false, focused: false, confirmFocused: false, dismissed: false, removed: 0, onClick: null, onConfirm: null };
  const overlay = {
    hidden: true,
    classList: {
      add: (name) => {
        if (name === "is-visible") calls.shown = true;
        if (name === "is-dismissed") calls.dismissed = true;
      },
    },
    remove: () => {
      calls.removed += 1;
    },
    addEventListener: (type, fn) => {
      if (type === "keydown") calls.onKeydown = fn;
    },
  };
  const accept = {
    focus: () => {
      calls.focused = true;
    },
    addEventListener: (type, fn) => {
      if (type === "click") calls.onClick = fn;
    },
  };
  const confirm = {
    disabled: true,
    setAttribute: () => {},
    focus: () => {
      calls.confirmFocused = true;
    },
    addEventListener: (type, fn) => {
      if (type === "click") calls.onConfirm = fn;
    },
  };
  const attributes = {};
  overlay.setAttribute = (name, value) => {
    attributes[name] = value;
  };
  const proof = {
    value: "",
    focus: () => {
      calls.proofFocused = true;
    },
    addEventListener: (type, fn) => {
      if (type === "input") calls.onProofInput = fn;
    },
  };
  // What the reader types into the proof field, then the input event it fires.
  calls.type = (value) => {
    proof.value = value;
    calls.onProofInput?.();
  };
  // One sentence per digit, hidden, as the template ships them.
  const proofTexts = Object.fromEntries(DIGIT_WORDS.map((_, digit) => [`beta-disclaimer-proof-text-${digit}`, { hidden: true }]));
  const stepOne = { hidden: false }, stepTwo = { hidden: true };
  return {
    calls,
    attributes,
    elements: {
      "beta-disclaimer": overlay,
      "beta-disclaimer-accept": accept,
      "beta-disclaimer-step-1": stepOne,
      "beta-disclaimer-step-2": stepTwo,
      "beta-disclaimer-confirm": confirm,
      "beta-disclaimer-proof": proof,
      ...proofTexts,
    },
  };
};

const loadModule = (overrides = {}) => {
  const options = {
    secure: true,
    cryptoImpl: workingCrypto(),
    bigIntImpl: BigInt,
    textEncoderImpl: TextEncoder,
    textDecoderImpl: TextDecoder,
    webAssemblyImpl: WebAssembly,
    hasBody: true,
    normalizeImpl: undefined, // when present in overrides, replaces String.prototype.normalize
    elements: {}, // DOM elements the disclaimer gate can find, by id
    storage: memoryStorage(),
    performanceImpl: fakeClock(0, 0),
    ...overrides,
  };
  const body = { innerHTML: PAGE };
  const documentElement = { dataset: {} };
  const sandbox = {
    window: { isSecureContext: options.secure },
    document: {
      documentElement,
      getElementById: (id) => options.elements[id] ?? null,
      ...(options.hasBody ? { body } : {}),
    },
    crypto: options.cryptoImpl,
    BigInt: options.bigIntImpl,
    TextEncoder: options.textEncoderImpl,
    TextDecoder: options.textDecoderImpl,
    WebAssembly: options.webAssemblyImpl,
    Uint8Array,
    localStorage: options.storage,
    performance: options.performanceImpl,
    // Run callbacks synchronously so assertions see the post-fade state.
    requestAnimationFrame: (fn) => fn(),
    setTimeout: (fn) => fn(),
  };
  const originalNormalize = String.prototype.normalize;
  if ("normalizeImpl" in overrides) String.prototype.normalize = overrides.normalizeImpl;
  try {
    new Function(...Object.keys(sandbox), src)(...Object.values(sandbox));
  } finally {
    String.prototype.normalize = originalNormalize;
  }
  return { body, documentElement };
};

const assertPageKilled = (body, failedNames) => {
  assert.ok(!body.innerHTML.includes("btc-calc"), "application markup survived the failure screen");
  assert.match(body.innerHTML, /<svg class="sanity-failure-icon"/);
  assert.match(body.innerHTML, /Host failed basic sanity checks/);
  assert.match(body.innerHTML, /This page should not be used until checks passed\./);
  assert.match(body.innerHTML, /<table class="sanity-failure-table">/);
  assert.match(body.innerHTML, /<thead><tr><th>Startup sanity check<\/th><th>Result<\/th><\/tr><\/thead>/);
  const rows = body.innerHTML.match(/<tr><td>[^<]+<\/td><td>Failed<\/td><\/tr>/g) ?? [];
  assert.deepEqual(
    rows.map((row) => row.match(/<td>([^<]+)<\/td>/)[1]),
    failedNames,
  );
};

test("never generates network traffic", () => {
  assert.doesNotMatch(src, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport|EventSource/);
});

test("a sane browser keeps the page intact and records the barrage outcome", () => {
  const { body, documentElement } = loadModule();
  assert.equal(body.innerHTML, PAGE);
  assert.equal(documentElement.dataset.browserChecks, "6");
  assert.equal(documentElement.dataset.browserFailed, "0");
});

test("an insecure context kills the page and lists the failure", () => {
  const { body, documentElement } = loadModule({ secure: false });
  assert.equal(documentElement.dataset.browserFailed, "1");
  assertPageKilled(body, ["Secure browser context"]);
});

test("a missing WebCrypto API kills the page", () => {
  const { body } = loadModule({ cryptoImpl: undefined });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("a missing getRandomValues function kills the page", () => {
  const { body } = loadModule({ cryptoImpl: {} });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("a CSPRNG that does not return the buffer kills the page", () => {
  const cryptoImpl = workingCrypto();
  cryptoImpl.getRandomValues = (bytes) => {
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 31 + 1) & 0xff;
    return undefined;
  };
  const { body } = loadModule({ cryptoImpl });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("a zero-filled CSPRNG kills the page", () => {
  const { body } = loadModule({ cryptoImpl: { getRandomValues: (bytes) => bytes.fill(0) } });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("a CSPRNG repeating identical fills kills the page", () => {
  const { body } = loadModule({ cryptoImpl: { getRandomValues: (bytes) => bytes.fill(7) } });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("missing BigInt kills the page without a parse error", () => {
  const { body } = loadModule({ bigIntImpl: undefined });
  assertPageKilled(body, ["BigInt arithmetic"]);
});

test("wrong BigInt arithmetic kills the page", () => {
  const { body } = loadModule({ bigIntImpl: (value) => Number(value) });
  assertPageKilled(body, ["BigInt arithmetic"]);
});

test("missing TextEncoder kills the page", () => {
  const { body } = loadModule({ textEncoderImpl: undefined });
  assertPageKilled(body, ["TextEncoder/TextDecoder (UTF-8)"]);
});

test("missing TextDecoder kills the page", () => {
  const { body } = loadModule({ textDecoderImpl: undefined });
  assertPageKilled(body, ["TextEncoder/TextDecoder (UTF-8)"]);
});

test("a wrong UTF-8 encoding kills the page", () => {
  const textEncoderImpl = class { encode() { return new Uint8Array([0x3f]); } };
  const { body } = loadModule({ textEncoderImpl });
  assertPageKilled(body, ["TextEncoder/TextDecoder (UTF-8)"]);
});

test("a wrong UTF-8 decoding kills the page", () => {
  const textDecoderImpl = class { decode() { return "?"; } };
  const { body } = loadModule({ textDecoderImpl });
  assertPageKilled(body, ["TextEncoder/TextDecoder (UTF-8)"]);
});

test("missing WebAssembly kills the page", () => {
  const { body } = loadModule({ webAssemblyImpl: undefined });
  assertPageKilled(body, ["WebAssembly (secp256k1 engine)"]);
  assert.match(body.innerHTML, /Lockdown Mode block WebAssembly/);
  assert.match(body.innerHTML, /page-menu button/);
  assert.match(body.innerHTML, /turn off Lockdown Mode for this website/);
});

test("a CSP or engine that refuses WebAssembly compilation kills the page", () => {
  const webAssemblyImpl = {
    Module: class {
      constructor() {
        throw new Error("Refused to compile WebAssembly");
      }
    },
  };
  const { body } = loadModule({ webAssemblyImpl });
  assertPageKilled(body, ["WebAssembly (secp256k1 engine)"]);
  assert.match(body.innerHTML, /Lockdown Mode/);
});

test("a non-WASM failure keeps the generic air-gap advice", () => {
  const { body } = loadModule({ secure: false });
  assertPageKilled(body, ["Secure browser context"]);
  assert.doesNotMatch(body.innerHTML, /Lockdown Mode/);
  assert.match(body.innerHTML, /Firefox on a trusted, air-gapped computer/);
});

test("missing String.normalize kills the page", () => {
  const { body } = loadModule({ normalizeImpl: undefined });
  assertPageKilled(body, ["String.normalize (NFKD)"]);
});

test("a wrong NFKD normalization kills the page", () => {
  const { body } = loadModule({ normalizeImpl: function () { return this.toString(); } });
  assertPageKilled(body, ["String.normalize (NFKD)"]);
});

test("multiple failures are all listed in one table", () => {
  const { body, documentElement } = loadModule({ secure: false, bigIntImpl: undefined });
  assert.equal(documentElement.dataset.browserChecks, "6");
  assert.equal(documentElement.dataset.browserFailed, "2");
  assertPageKilled(body, ["Secure browser context", "BigInt arithmetic"]);
});

test("a check that throws is reported as a failure, not a crash", () => {
  const cryptoImpl = {
    getRandomValues() {
      throw new Error("CSPRNG exploded");
    },
  };
  const { body } = loadModule({ cryptoImpl });
  assertPageKilled(body, ["crypto.getRandomValues (CSPRNG)"]);
});

test("a missing document.body still records the outcome without throwing", () => {
  const { documentElement } = loadModule({ secure: false, hasBody: false });
  assert.equal(documentElement.dataset.browserChecks, "6");
  assert.equal(documentElement.dataset.browserFailed, "1");
});

test("the barrage runs before the application scripts in the template", () => {
  const template = read("src/index.html");
  const checkToken = template.indexOf("/*@@JS_BROWSER_CHECK@@*/");
  const mainToken = template.indexOf('<script id="btc-calc-script">');
  assert.ok(checkToken !== -1, "template is missing the browser-check script token");
  assert.ok(mainToken !== -1, "template is missing the application script tag");
  assert.ok(checkToken < mainToken, "browser-check must run before the application scripts");
});

test("the build inlines the module and the failure screen is styled", () => {
  const build = read("scripts/build.mjs");
  const css = read("src/css/styles.css");
  assert.match(build, /browser-check\.js/);
  assert.match(build, /\/\*@@JS_BROWSER_CHECK@@\*\//);
  for (const selector of [
    ".sanity-failure {",
    ".sanity-failure-card {",
    ".sanity-failure-icon {",
    ".sanity-failure-title {",
    ".sanity-failure-message {",
    ".sanity-failure-table {",
    ".sanity-failure-table th, .sanity-failure-table td {",
    ".sanity-failure-advice {",
    ".sanity-failure-advice + .sanity-failure-advice {",
  ]) {
    assert.ok(css.includes(selector), `styles.css is missing ${selector}`);
  }
});

test("the compiled application ships the inlined barrage", () => {
  ensureBuild();
  const compiled = read("entropylab.html");
  assert.match(compiled, /Host failed basic sanity checks/);
  assert.match(compiled, /data-browser-checks|dataset\.browserChecks/);
  assert.doesNotMatch(compiled, /\/\*@@JS_BROWSER_CHECK@@\*\//);
});

// The source token {{VERSION}} stands in for the running release here; the
// build substitutes the package version into the compiled artifact (asserted
// below), so acceptance recorded under one release never silences the next.
// Security contract: the page is entered only after both acknowledgements.
// The first "I Understand" must not store acceptance or dismiss the gate: it
// only swaps in the second step, which names what the browser cannot protect.
// Only the second acknowledgement stores acceptance and removes the gate.
test("the beta disclaimer shows on first boot and acceptance is stored for the running version", () => {
  const { calls, elements, attributes } = disclaimerDom();
  const storage = memoryStorage();
  // 12.7 s from reveal to "I Understand": tenths digit 7.
  loadModule({ elements, storage, performanceImpl: fakeClock(1000, 13700) });
  assert.equal(elements["beta-disclaimer"].hidden, false, "the overlay was not revealed");
  assert.ok(calls.shown, "the fade-in class was not applied");
  assert.ok(calls.focused, "the accept button was not focused");
  assert.equal(elements["beta-disclaimer-step-2"].hidden, true, "the second step showed before the first was accepted");
  assert.equal(typeof calls.onClick, "function", "no accept handler was registered");
  calls.onClick();
  // Step one accepted: step two shows, and nothing is stored or dismissed yet.
  assert.equal(storage.dump()["entropylab-disclaimer-accepted"], undefined, "the first acknowledgement stored acceptance");
  assert.equal(calls.dismissed, false, "the first acknowledgement dismissed the gate");
  assert.equal(calls.removed, 0, "the first acknowledgement removed the gate");
  assert.equal(elements["beta-disclaimer-step-1"].hidden, true, "the first step stayed visible");
  assert.equal(elements["beta-disclaimer-step-2"].hidden, false, "the second step did not show");
  assert.ok(calls.proofFocused, "the second step's proof field was not focused");
  assert.equal(attributes["aria-labelledby"], "beta-disclaimer-confirm-title", "the dialog is not named by the second step");
  assert.equal(attributes["aria-describedby"], "beta-disclaimer-confirm-text", "the dialog is not described by the second step");
  assert.equal(typeof calls.onConfirm, "function", "no confirm handler was registered");
  // The second acknowledgement waits for proof of reading: a digit taken
  // from the reading time, named by its own sentence, typed back as the digit.
  assert.deepEqual(shownProofDigits(elements), [7], "the second step does not show the timed digit's sentence alone");
  const confirm = elements["beta-disclaimer-confirm"];
  assert.equal(confirm.disabled, true, "the second step's button was enabled before the proof");
  calls.onConfirm();
  assert.equal(storage.dump()["entropylab-disclaimer-accepted"], undefined, "an unproven click stored acceptance");
  assert.equal(calls.dismissed, false, "an unproven click dismissed the gate");
  for (const wrong of ["3", "seven", "77", "0", "8"]) {
    calls.type(wrong);
    assert.equal(confirm.disabled, true, `the button enabled for ${JSON.stringify(wrong)}`);
    calls.onConfirm();
    assert.equal(storage.dump()["entropylab-disclaimer-accepted"], undefined, `${JSON.stringify(wrong)} passed the gate`);
  }
  calls.type(" 7 ");
  assert.equal(confirm.disabled, false, "the button stayed disabled after typing the timed digit");
  calls.onConfirm();
  assert.equal(storage.dump()["entropylab-disclaimer-accepted"], "{{VERSION}}");
  assert.ok(calls.dismissed, "the fade-out class was not applied");
  assert.equal(calls.removed, 1, "the overlay was not removed after the fade");
});

test("a stored acceptance for the running version skips the beta disclaimer", () => {
  const { calls, elements } = disclaimerDom();
  loadModule({ elements, storage: memoryStorage({ "entropylab-disclaimer-accepted": "{{VERSION}}" }) });
  assert.equal(elements["beta-disclaimer"].hidden, true, "the overlay was revealed");
  assert.equal(calls.shown, false);
  assert.equal(calls.removed, 1, "the accepted overlay was not removed outright");
});

test("an acceptance stored under another version re-asks", () => {
  const { calls, elements } = disclaimerDom();
  loadModule({ elements, storage: memoryStorage({ "entropylab-disclaimer-accepted": "0.0.0" }) });
  assert.equal(elements["beta-disclaimer"].hidden, false, "the overlay stayed hidden");
  assert.ok(calls.shown, "the disclaimer did not re-ask");
});

test("unavailable storage fails open: the disclaimer still shows and dismissal still works", () => {
  const { calls, elements } = disclaimerDom();
  const throwingStorage = {
    getItem() {
      throw new Error("denied");
    },
    setItem() {
      throw new Error("denied");
    },
  };
  loadModule({ elements, storage: throwingStorage });
  assert.equal(elements["beta-disclaimer"].hidden, false, "the overlay stayed hidden");
  assert.ok(calls.shown, "the disclaimer did not show");
  calls.onClick();
  assert.equal(calls.dismissed, false, "the first acknowledgement dismissed the gate");
  calls.type(String(shownProofDigits(elements)[0]));
  calls.onConfirm();
  assert.ok(calls.dismissed, "the fade-out class was not applied");
  assert.equal(calls.removed, 1, "the overlay was not removed after the fade");
});

test("the compiled disclaimer acceptance is keyed to the package version", () => {
  ensureBuild();
  const compiled = read("entropylab.html");
  const { version } = JSON.parse(read("package.json"));
  assert.match(compiled, /const KEY = "entropylab-disclaimer-accepted";/);
  assert.ok(
    compiled.includes(`const VERSION = "${version}";`),
    "the compiled gate does not embed the package version",
  );
});

// The proof digit comes from how long the first step was open, in tenths of
// a second, mod 10 — never from the CSPRNG. Tenths rather than milliseconds
// so a clock coarsened to 100 ms (Firefox resistFingerprinting, Tor Browser)
// still yields every digit instead of always 0.
test("the proof digit is the tenths digit of the first step's reading time and draws no randomness", () => {
  for (const [shown, accepted, expected] of [
    [500, 500, 0], // pressed instantly
    [500, 599.9, 0], // still inside the first tenth
    [500, 600, 1],
    [0, 4300, 3],
    [250, 9250, 0], // 9.0 s wraps to 0
    [0, 100000, 0], // a 100 ms-clamped clock reads exact hundreds
    [0, 100400, 4],
  ]) {
    const { calls, elements } = disclaimerDom();
    loadModule({ elements, cryptoImpl: noProofDrawCrypto(), performanceImpl: fakeClock(shown, accepted) });
    calls.onClick();
    assert.deepEqual(shownProofDigits(elements), [expected], `${accepted - shown} ms did not show the sentence for ${expected} alone`);
    calls.type(String((expected + 1) % 10));
    assert.equal(elements["beta-disclaimer-confirm"].disabled, true, "a digit other than the timed one was accepted");
    calls.type(String(expected));
    assert.equal(elements["beta-disclaimer-confirm"].disabled, false, "the timed digit did not enable the button");
  }
});

// Before "I Understand" there is no digit yet, so nothing typed can pass.
test("no proof is accepted before the first step is acknowledged", () => {
  const { calls, elements } = disclaimerDom();
  loadModule({ elements, performanceImpl: fakeClock(0, 0) });
  assert.deepEqual(shownProofDigits(elements), [], "a proof sentence showed before the first step was acknowledged");
  for (const value of ["", "0", "undefined", "null", "NaN"]) {
    calls.type(value);
    assert.equal(elements["beta-disclaimer-confirm"].disabled, true, `${JSON.stringify(value)} enabled the button early`);
  }
});

// The gate writes no words of its own. Each digit's sentence ships whole in
// the template, hidden, so the boot i18n sweep translates all ten before the
// reader gets there, and the catalog extractor hands each to the translators
// as one complete sentence (a word dropped into the middle of a sentence
// stays English and cannot be reordered around).
test("every proof sentence ships whole and hidden in the template, as a translation source", async () => {
  const { collectSources, normalize } = await import("../scripts/i18n-sources.mjs");
  const sources = await collectSources(root);
  const template = read("src/index.html");
  for (const [digit, word] of DIGIT_WORDS.entries()) {
    const match = template.match(new RegExp(`<span id="beta-disclaimer-proof-text-${digit}"([^>]*)>([^<]*)</span>`));
    assert.ok(match, `the template has no proof sentence for ${digit}`);
    assert.match(match[1], /(^|\s)hidden(\s|=|$)/, `the proof sentence for ${digit} is not hidden at birth`);
    const sentence = normalize(match[2]);
    assert.ok(sources.has(sentence), `the proof sentence for ${digit} is not a translation source`);
    const named = DIGIT_WORDS.filter((name) => new RegExp(`\\b${name}\\b`).test(sentence));
    assert.deepEqual(named, [word], `the proof sentence for ${digit} names ${named.join(", ") || "no digit"}`);
  }
});
