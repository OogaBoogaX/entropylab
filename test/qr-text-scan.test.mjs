import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mountTextScan } from "../src/js/qr-text-scan.js";
import { MiniDocument } from "./mini-dom.mjs";
import { collectSources } from "../scripts/i18n-sources.mjs";
import { hodlCborBstr, hodlUrEncodeMessage, watchOnlyQrPlan } from "../src/js/psbt-ur.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SOURCE = readFileSync(new URL("../src/js/qr-text-scan.js", import.meta.url), "utf8");

const BOLT11 = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
const SP = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
const SP2 = "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn";
const XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const TPUB = "tpubDCHZAX9rt6AMCqXFKo8DTQj3moR5fEozbLupqHq6GrA9s44DdnPSpuNv3fZPR8nAK7mGQFpdGSSF1Ky6Rqjb29JYzaDU998qiv99SWG1pAM";
const PUB = `pkh([420c9ea3/44h/1h/0h]${TPUB}/0/*)#789zdhaw`;
const PRIV = "pkh([420c9ea3/44h/1h/0h]tprv8fbX277cjiUgKNVTS9Td414wCmu9Vud623K3YmnnraMm2ZoT1PZreQm3sYtEsmzaz5KifqfkKEm2Q5e7e4wPpWYsbmEKXNzksR8RiJkmM8U/0/*)#jwsdcell";
const bytesOf = (text) => new TextEncoder().encode(text);

class FakeInputEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = !!init.bubbles;
    this.inputType = init.inputType ?? "";
  }
}

const makeDecoder = () => {
  const calls = { stop: 0 };
  return {
    calls,
    decode() { return Promise.resolve({ code: -1 }); },
    stop() {
      calls.stop += 1;
      return Promise.resolve({ scrubbed: true });
    },
  };
};

const makeScanner = () => {
  const calls = { start: 0, stop: 0 };
  return {
    calls,
    start() { calls.start += 1; },
    stop() { calls.stop += 1; },
  };
};

const setup = ({ id = "text-scan", accept = "lightning", mode = "replace", win, isShown } = {}) => {
  const doc = new MiniDocument();
  const host = doc.createElement("div");
  host.id = id;
  doc.body.appendChild(host);
  const field = doc.createElement("textarea");
  const events = [];
  field.addEventListener("input", (event) => events.push(event));
  const decoder = makeDecoder();
  const scanner = makeScanner();
  const created = { decoders: 0, scanners: 0, scannerArgs: null };
  const loads = { count: 0 };
  const options = {
    field,
    accept,
    mode,
    onLoad: () => { loads.count += 1; },
    createDecoder: () => {
      created.decoders += 1;
      return decoder;
    },
    createScanner: (args) => {
      created.scanners += 1;
      created.scannerArgs = args;
      return scanner;
    },
    wasmBytes: () => new Uint8Array([1, 2, 3]),
    doc,
    win: win ?? { InputEvent: FakeInputEvent },
  };
  if (isShown) options.isShown = isShown;
  const panel = mountTextScan(host, options);
  return { doc, host, field, events, decoder, scanner, created, loads, panel };
};

const byId = (ctx, suffix) => ctx.host.querySelector(`#${ctx.host.id}-${suffix}`);
const openPanel = (ctx) => byId(ctx, "open").dispatchEvent({ type: "click" });
const stateOf = (ctx) => byId(ctx, "status").getAttribute("data-scan-state");

const testPanel = (name, fn) => {
  test(name, () => {
    const created = [];
    const make = (options) => {
      const ctx = setup(options);
      created.push(ctx);
      return ctx;
    };
    try {
      fn(make);
    } finally {
      for (const ctx of created) ctx.panel.destroy();
    }
  });
};

testPanel("an empty lightning field is filled from the camera", (make) => {
  const ctx = make();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  assert.equal(ctx.field.value, BOLT11);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.events[0].type, "input");
  assert.equal(ctx.events[0].bubbles, true);
  assert.equal(ctx.events[0].inputType, "insertFromPaste");
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(stateOf(ctx), "loaded");
});

testPanel("replace mode asks, and Keep leaves the field unchanged", (make) => {
  const ctx = make();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(byId(ctx, "confirm").hidden, false);
  byId(ctx, "keep").dispatchEvent({ type: "click" });
  assert.equal(stateOf(ctx), "kept");
  assert.equal(ctx.field.value, "old");
  assert.equal(ctx.events.length, 0);
  assert.equal(byId(ctx, "confirm").hidden, true);
});

testPanel("Replace writes the scanned text", (make) => {
  const ctx = make();
  ctx.field.value = "old";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  byId(ctx, "replace").dispatchEvent({ type: "click" });
  assert.equal(ctx.field.value, BOLT11);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.events[0].inputType, "insertFromPaste");
  assert.equal(stateOf(ctx), "loaded");
  assert.equal(byId(ctx, "confirm").hidden, true);
});

testPanel("the wrong kind leaves the field unchanged", (make) => {
  const ctx = make();
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(SP));
  assert.equal(ctx.field.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(stateOf(ctx), "wrong-kind");
});

testPanel("a private descriptor is refused and not repeated", (make) => {
  const ctx = make({ id: "desc-scan", accept: "descriptor" });
  ctx.field.value = "keep";
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(PRIV));
  assert.equal(ctx.field.value, "keep");
  assert.equal(ctx.events.length, 0);
  assert.equal(stateOf(ctx), "private-key");
  assert.equal(byId(ctx, "status").textContent.includes("tprv"), false);
  const pub = make({ id: "desc-pub", accept: "descriptor" });
  openPanel(pub);
  pub.created.scannerArgs.onResult(bytesOf(PUB));
  assert.equal(pub.field.value, PUB);
  assert.equal(stateOf(pub), "loaded");
});

testPanel("an xprv is refused and an xpub is loaded", (make) => {
  const ctx = make({ id: "xpub-scan", accept: "xpub" });
  openPanel(ctx);
  ctx.created.scannerArgs.onResult(bytesOf(XPRV));
  assert.equal(ctx.field.value, "");
  assert.equal(ctx.events.length, 0);
  assert.equal(stateOf(ctx), "private-key");
  ctx.created.scannerArgs.onResult(bytesOf(XPUB));
  assert.equal(ctx.field.value, XPUB);
  assert.equal(stateOf(ctx), "loaded");
  assert.equal(ctx.events.length, 1);
});

testPanel("silent-payment append adds a line and refuses a duplicate", (make) => {
  const ctx = make({ id: "sp-scan", accept: "sp", mode: "append" });
  openPanel(ctx);
  const starts = ctx.scanner.calls.start;
  ctx.created.scannerArgs.onResult(bytesOf(SP));
  assert.equal(ctx.field.value, SP);
  assert.equal(stateOf(ctx), "added");
  assert.equal(byId(ctx, "confirm").hidden, true);
  assert.equal(ctx.events.length, 1);
  assert.equal(ctx.scanner.calls.start, starts + 1);
  assert.equal(byId(ctx, "video").hidden, false);
  assert.equal(byId(ctx, "stop").hidden, false);
  ctx.created.scannerArgs.onResult(bytesOf(SP2));
  assert.equal(ctx.field.value, `${SP}\n${SP2}`);
  assert.equal(stateOf(ctx), "added");
  assert.equal(byId(ctx, "confirm").hidden, true);
  assert.equal(ctx.events.length, 2);
  assert.equal(ctx.scanner.calls.start, starts + 2);
  assert.equal(byId(ctx, "video").hidden, false);
  ctx.created.scannerArgs.onResult(bytesOf(SP));
  assert.equal(stateOf(ctx), "already-listed");
  assert.equal(ctx.field.value, `${SP}\n${SP2}`);
  assert.equal(ctx.events.length, 2);
  assert.equal(byId(ctx, "confirm").hidden, true);
  assert.equal(ctx.scanner.calls.start, starts + 3);
  assert.equal(byId(ctx, "video").hidden, false);
  assert.equal(byId(ctx, "stop").hidden, false);
});

testPanel("a multi-part descriptor shows progress and then loads", (make) => {
  const keys = Array.from({ length: 9 }, (_, i) => `[d34db33f/48h/0h/${i}h/2h]${XPUB}/<0;1>/*`);
  const longText = `wsh(sortedmulti(2,${keys.join(",")}))`;
  const parts = watchOnlyQrPlan(longText).parts;
  assert.ok(parts.length >= 2);
  const ctx = make({ id: "desc-parts", accept: "descriptor" });
  openPanel(ctx);
  const starts = ctx.scanner.calls.start;
  for (let i = 0; i < parts.length - 1; i++) {
    ctx.created.scannerArgs.onResult(bytesOf(parts[i]));
    assert.equal(ctx.scanner.calls.start, starts + i + 1);
    assert.equal(byId(ctx, "progress").hidden, false);
  }
  ctx.created.scannerArgs.onResult(bytesOf(parts[parts.length - 1]));
  assert.equal(ctx.field.value, longText);
  assert.equal(stateOf(ctx), "loaded");
});

testPanel("crypto-output and BBQr are refused", (make) => {
  const ctx = make({ id: "desc-format", accept: "descriptor" });
  openPanel(ctx);
  const [part] = hodlUrEncodeMessage("crypto-output", hodlCborBstr(bytesOf("x")));
  ctx.created.scannerArgs.onResult(bytesOf(part));
  assert.equal(stateOf(ctx), "unsupported-format");
  assert.equal(ctx.field.value, "");
  ctx.created.scannerArgs.onResult(bytesOf("B$2U0100"));
  assert.equal(stateOf(ctx), "unsupported-format");
  assert.equal(ctx.events.length, 0);
});

testPanel("hiding the page or concealing drops a pending replace", (make) => {
  const hidden = make();
  hidden.field.value = "old";
  openPanel(hidden);
  hidden.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  assert.equal(byId(hidden, "confirm").hidden, false);
  const stops = hidden.scanner.calls.stop;
  hidden.doc.visibilityState = "hidden";
  hidden.doc.dispatchEvent({ type: "visibilitychange" });
  assert.equal(hidden.scanner.calls.stop, stops + 1);
  assert.equal(byId(hidden, "confirm").hidden, true);
  byId(hidden, "replace").dispatchEvent({ type: "click" });
  assert.equal(hidden.field.value, "old");
  assert.equal(hidden.events.length, 0);

  const concealed = make({ id: "text-conceal" });
  concealed.field.value = "old";
  openPanel(concealed);
  concealed.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  const concealStops = concealed.scanner.calls.stop;
  concealed.doc.dispatchEvent({ type: "hodl:conceal" });
  assert.equal(concealed.scanner.calls.stop, concealStops + 1);
  assert.equal(byId(concealed, "confirm").hidden, true);
  byId(concealed, "replace").dispatchEvent({ type: "click" });
  assert.equal(concealed.field.value, "old");
  assert.equal(concealed.events.length, 0);
});

testPanel("a hidden host stops the camera and drops a pending scan", (make) => {
  const ticks = [];
  const cleared = [];
  const win = {
    InputEvent: FakeInputEvent,
    setInterval(fn, ms) {
      const id = ticks.length + 1;
      ticks.push({ id, fn, ms });
      return id;
    },
    clearInterval(id) { cleared.push(id); },
  };
  const hidden = make({ id: "text-hidden", win, isShown: () => false });
  hidden.field.value = "keep-me";
  openPanel(hidden);
  hidden.created.scannerArgs.onResult(bytesOf("lightning:" + BOLT11));
  assert.equal(byId(hidden, "confirm").hidden, false);
  assert.equal(ticks.length, 1);
  assert.equal(ticks[0].ms, 500);
  const stops = hidden.scanner.calls.stop;
  ticks[0].fn();
  assert.equal(hidden.scanner.calls.stop, stops + 1);
  assert.equal(stateOf(hidden), "stopped");
  byId(hidden, "replace").dispatchEvent({ type: "click" });
  assert.equal(hidden.field.value, "keep-me");
  assert.equal(hidden.events.length, 0);
  hidden.panel.destroy();
  assert.deepEqual(cleared, [ticks[0].id]);

  const visibleTicks = [];
  let visibleCleared = 0;
  const shown = make({
    id: "text-shown",
    win: {
      InputEvent: FakeInputEvent,
      setInterval(fn) {
        visibleTicks.push(fn);
        return 4;
      },
      clearInterval(id) {
        assert.equal(id, 4);
        visibleCleared += 1;
      },
    },
    isShown: () => true,
  });
  openPanel(shown);
  const shownStops = shown.scanner.calls.stop;
  visibleTicks[0]();
  assert.equal(shown.scanner.calls.stop, shownStops);
  assert.equal(stateOf(shown), "scanning");
  shown.panel.destroy();
  assert.equal(visibleCleared, 1);
});

testPanel("opening a second panel closes the first", (make) => {
  const a = make({ id: "text-a" });
  const b = make({ id: "text-b", accept: "xpub" });
  openPanel(a);
  assert.equal(byId(a, "open").getAttribute("aria-expanded"), "true");
  const stops = a.scanner.calls.stop;
  openPanel(b);
  assert.equal(byId(a, "open").getAttribute("aria-expanded"), "false");
  assert.equal(a.scanner.calls.stop, stops + 1);
  assert.equal(byId(b, "open").getAttribute("aria-expanded"), "true");
});

testPanel("destroy empties the host, removes the listeners, and can run twice", (make) => {
  const ctx = make({ id: "text-destroy" });
  openPanel(ctx);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 1);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 1);
  ctx.panel.destroy();
  assert.equal(ctx.host.childNodes.length, 0);
  assert.equal(ctx.doc.listenerCount("visibilitychange"), 0);
  assert.equal(ctx.doc.listenerCount("hodl:conceal"), 0);
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);
  ctx.panel.destroy();
  assert.equal(ctx.scanner.calls.stop, 1);
  assert.equal(ctx.decoder.calls.stop, 1);

  const a = make({ id: "host-a" });
  const b = make({ id: "host-b" });
  for (const suffix of ["open", "panel", "status", "progress", "video", "canvas", "stop", "close", "confirm", "confirm-text", "replace", "keep"]) {
    assert.ok(a.host.querySelector(`#host-a-${suffix}`));
    assert.ok(b.host.querySelector(`#host-b-${suffix}`));
    assert.equal(a.host.querySelector(`#host-b-${suffix}`), null);
  }
});

test("mount throws before it touches the host", () => {
  const doc = new MiniDocument();
  const field = doc.createElement("textarea");
  const win = { InputEvent: FakeInputEvent };
  const bare = doc.createElement("div");
  assert.throws(() => mountTextScan(bare, { field, accept: "lightning", doc, win }));
  assert.equal(bare.childNodes.length, 0);
  const host = doc.createElement("div");
  host.id = "text-bad";
  assert.throws(() => mountTextScan(host, { field, accept: "seed", doc, win }));
  assert.throws(() => mountTextScan(host, { field, accept: "lightning", mode: "append", doc, win }));
  assert.equal(host.childNodes.length, 0);
});

test("every visible string is a t() literal the catalog sweep collects", async () => {
  assert.match(SOURCE, /import \{ t \} from "\.\/i18n\.js";/);
  assert.doesNotMatch(SOURCE, /\btranslate\b/);
  for (const name of ["STATUS_TEXT", "OPEN_TEXT", "WRONG_KIND_TEXT"]) {
    const block = SOURCE.match(new RegExp(`const ${name} = \\{\\n([\\s\\S]*?)\\n\\};`))?.[1];
    assert.ok(block, `${name} is missing`);
    for (const line of block.split("\n")) {
      if (!line.trim() || line.trim().startsWith("//")) continue;
      assert.match(line, /^  (?:"[\w-]+"|\w+): \(\) => t\("[^"]+"\),$/, `${name} line is not a t() thunk: ${line.trim()}`);
    }
  }
  for (const literal of SOURCE.matchAll(/text: ([^,\n}]+)/g)) {
    assert.match(literal[1].trim(), /^(?:t\("[^"]+"\)|STATUS_TEXT\.\w+\(\)|OPEN_TEXT\[accept\]\(\))$/);
  }
  const sources = await collectSources(ROOT);
  for (const literal of SOURCE.matchAll(/\bt\("([^"]+)"/g)) assert.ok(sources.has(literal[1]), `the catalog sweep misses: ${literal[1]}`);
});
