import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { UrCapture, AexbCapture } from "../src/js/aexb-capture.js";
import { aexbDecode, aexbEncodePackage } from "../src/js/aexb.js";
import { hashesReady } from "../src/js/hashes.js";
import { secp256k1Ready } from "../src/js/secp256k1.js";
await hashesReady;
await secp256k1Ready;
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "./fixtures/aexb/protocol-v1-multislot-vectors.json",
      import.meta.url,
    ),
  ),
);
const fountain = JSON.parse(
  readFileSync(
    new URL("./fixtures/aexb/capture-fountain.json", import.meta.url),
  ),
);
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const transcript = c => [...c.messages.values()].map(e=>Buffer.from(e.bytes).toString("hex")).join("\n");
const message = (stage) => fixture.messages.find((m) => m.stage === stage);
test("finish clears retained buffers when slot-count lookup throws", () => {
  const c = new AexbCapture();
  for (const stage of [2,3,4]) c.accept(bytes(message(stage).package_hex));
  const retained = [...c.messages.values()].flatMap(({bytes,decoded}) => [bytes,
    ...Object.values(decoded).filter(v => v instanceof Uint8Array),
    ...decoded.slots.flatMap(slot => Object.values(slot).filter(v => v instanceof Uint8Array))]);
  assert.ok(retained.some(b => b.some(v => v !== 0)));
  // Fault injection at the metadata lookup, not a malformed-wire claim.
  c.messages.get = () => { throw Error("slot-count lookup failed"); };
  assert.deepEqual(c.finish(), {ok:false,reason:"VERIFICATION_UNAVAILABLE",checkedSlots:0,totalSlots:0});
  assert.ok(retained.every(b => b.every(v => v === 0)));
  assert.deepEqual(c.snapshot(), {stages:[],verdict:null});
});
// Inject an unexpected verifier exception after decoding, without weakening
// the real decoder's point validation. Completion must still wipe all stages.
for (const order of [[2,3,4],[2,4,3],[3,2,4],[3,4,2],[4,2,3],[4,3,2]])
  test(`verifier exception fails safely and finish wipes all stages: ${order}`, () => {
    const c = new AexbCapture();
    const set = c.messages.set.bind(c.messages);
    c.messages.set = (stage, entry) => {
      if (stage === 4) Object.defineProperty(entry.decoded, "signatures", {
        get() { throw new Error("injected verifier failure"); },
      });
      return set(stage, entry);
    };
    const inputs = order.map(stage => bytes(message(stage).package_hex));
    for (const input of inputs) assert.doesNotThrow(() => c.accept(input));
    assert.equal(c.snapshot().verdict.ok, false);
    assert.equal(c.snapshot().verdict.reason, "VERIFICATION_UNAVAILABLE");
    assert.doesNotThrow(() => c.accept(inputs[2]), "duplicate must not rethrow");
    assert.equal(c.checkTransaction(), null);
    const totalSlots = c.messages.get(4).decoded.slots.length;
    const retained = [...c.messages.values()].flatMap(({bytes,decoded}) => [bytes,
      ...Object.values(decoded).filter(v => v instanceof Uint8Array),
      ...decoded.slots.flatMap(slot => Object.values(slot).filter(v => v instanceof Uint8Array))]);
    assert.ok(retained.some(b => b.some(v => v !== 0)));
    assert.deepEqual(c.finish(), {ok:false,reason:"VERIFICATION_UNAVAILABLE",checkedSlots:0,totalSlots});
    assert.ok(retained.every(b => b.every(v => v === 0)));
    assert.deepEqual(c.snapshot(), {stages:[],verdict:null});
    assert.equal(c.finish(), null);
  });
test("off-curve opening is rejected before capture", () => {
  for (const stage of [2,3,4]) {
    const input = bytes(message(stage).package_hex);
    const opening = aexbDecode(input).slots[0].opening;
    const offset = Buffer.from(input).indexOf(opening);
    assert.ok(offset >= 0);
    input.fill(0, offset, offset + 33);
    input[offset] = 2; // x=0 is not a secp256k1 point.
    const c = new AexbCapture();
    assert.throws(() => c.accept(input), /invalid signer opening/);
    assert.deepEqual(c.snapshot(), {stages:[],verdict:null});
  }
});
// DeepSeek revision18 F1: accept fixed-width CRC32 even below 65536 without
// relaxing canonical metadata, byte-string envelopes or final CRC checks.
// Independent oracle: Python zlib.crc32(bytes.fromhex('474145585400b6c7'))
// is 0x0000b35d. These literal CBOR parts encode that eight-byte message.
test("F1: small fixed-width CRC32 completes a multipart UR", async () => {
  const { hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  for (const checksum of ["1a0000b35d", "19b35d"]) {
    const c = new UrCapture();
    const frame = (seq, data) => `ur:x-btc-anti-exfil/${seq}-2/` +
      hodlBytewordsEncode(bytes(`85${seq === 1 ? "01" : "02"}0208${checksum}44${data}`));
    assert.equal(c.receive(frame(1, "47414558")).complete, false);
    const result = c.receive(frame(2, "5400b6c7"));
    assert.equal(result.complete, true);
    assert.deepEqual(result.bytes, bytes("4145585400b6c7"));
    result.bytes.fill(0);
    c.clear();
  }
});
test("F1: checksum width exception does not relax other CBOR fields", async () => {
  const { hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  for (const payload of [
    "85180102081a0000b35d4447414558", // nonminimal sequence
    "85011802081a0000b35d4447414558", // nonminimal count
    "85010218081a0000b35d4447414558", // nonminimal message length
    "850102081a0000b35d580447414558", // nonminimal byte-string length
    "850102081b000000000000b35d4447414558", // uint64 checksum
    "850102083a0000b35d4447414558", // negative checksum
    "850102081a00", // truncated checksum
  ]) {
    const retained = [], c = new UrCapture({ track: retained });
    assert.throws(() => c.receive("ur:x-btc-anti-exfil/1-2/" + hodlBytewordsEncode(bytes(payload))), /CBOR_/);
    assert.equal(retained.length, 0);
  }
});
test("F1: small fixed-width checksum still requires matching message CRC", async () => {
  const { hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  const c = new UrCapture();
  c.receive("ur:x-btc-anti-exfil/1-2/" + hodlBytewordsEncode(bytes("850102081a0000b35c4447414558")));
  assert.throws(() => c.receive("ur:x-btc-anti-exfil/2-2/" + hodlBytewordsEncode(bytes("850202081a0000b35c445400b6c7"))), /MESSAGE_CHECKSUM/);
});
// Contract: accept only bounded, checksum-valid UR messages from one canonical
// AEXT session; identical repeats are harmless, conflicts never replace evidence.
for (const item of fountain.messages)
  test(`fountain recovery without the first cycle, stage ${item.stage}`, () => {
    const c = new UrCapture();
    let result;
    for (const frame of item.frames) {
      result = c.receive(frame);
      if (result.complete) break;
    }
    assert.equal(result.complete, true);
    assert.deepEqual(result.bytes, bytes(item.package_hex));
  });
test("published sequential frames tolerate repeats and reverse order", () => {
  const c = new UrCapture();
  let result;
  for (const frame of [...message(3).medium_ur_parts].reverse()) {
    result = c.receive(frame);
    if (!result.complete) c.receive(frame);
  }
  assert.deepEqual(result.bytes, bytes(message(3).package_hex));
});
test("wrong UR type, excessive input and checksum errors are rejected", () => {
  const c = new UrCapture();
  const f = message(2).medium_ur_parts[0];
  assert.throws(
    () => c.receive(f.replace(/X-BTC-ANTI-EXFIL/i, "crypto-psbt")),
    /TYPE/,
  );
  assert.throws(() => c.receive("a".repeat(20001)), /LIMIT/);
  assert.throws(() => c.receive(f.slice(0, -2) + "zz"));
  assert.equal(c.progress().received, 0);
});
test("interleaved message frames cannot contaminate an assembly", () => {
  const c = new UrCapture();
  c.receive(message(2).medium_ur_parts[0]);
  assert.throws(() => c.receive(message(3).medium_ur_parts[1]), /MIXED/);
  c.clear();
  assert.equal(c.progress().received, 0);
});

test("nonzero fountain padding is refused even when message CRC is unchanged", async () => {
  const { hodlBytewordsDecode, hodlBytewordsEncode, hodlUrPartParse } = await import("../src/js/psbt-ur.js");
  const frames = message(3).medium_ur_parts;
  const words = frames.at(-1).split("/");
  const payload = hodlBytewordsDecode(words.at(-1));
  const part = hodlUrPartParse(payload);
  assert.ok(part.seqLen * part.data.length > part.messageLen, "fixture has padding");
  payload[payload.length - 1] = 1;
  const changed = words.slice(0, -1).join("/") + "/" + hodlBytewordsEncode(payload);
  const c = new UrCapture();
  for (const frame of frames.slice(0, -1)) c.receive(frame);
  assert.throws(() => c.receive(changed), /MESSAGE_CHECKSUM/);
  assert.equal(c.progress().received, 0);
});
test("session requires all 2/3/4 stages before full verdict, any capture order", () => {
  const c = new AexbCapture();
  assert.deepEqual(c.snapshot().stages, []);
  c.accept(bytes(message(4).package_hex));
  assert.equal(c.snapshot().verdict, null);
  c.accept(bytes(message(2).package_hex));
  assert.equal(c.snapshot().verdict, null);
  c.accept(bytes(message(3).package_hex));
  assert.deepEqual(c.snapshot().stages, [2, 3, 4]);
  assert.equal(c.snapshot().verdict.ok, true);
  assert.equal(transcript(c).split("\n").length, 3);
  c.clear();
  assert.equal(transcript(c), "");
  assert.equal(c.snapshot().verdict, null);
});
test("duplicate evidence is idempotent; conflicting evidence stays rejected", () => {
  const c = new AexbCapture();
  const m = message(2);
  c.accept(bytes(m.package_hex));
  c.accept(bytes(m.package_hex));
  assert.deepEqual(c.snapshot().stages, [2]);
  const changed = aexbDecode(bytes(m.package_hex));
  changed.slots[0].messageHash[0] ^= 1;
  assert.throws(() => c.accept(aexbEncodePackage(changed)), /CONFLICT/);
  assert.equal(transcript(c), m.package_hex.toLowerCase());
});
for (const field of ["sessionId", "psbtDigest"])
  test(`reject different ${field} without losing accepted evidence`, () => {
    const c = new AexbCapture();
    c.accept(bytes(message(3).package_hex));
    const changed = aexbDecode(bytes(message(2).package_hex));
    changed[field][0] ^= 1;
    assert.throws(() => c.accept(aexbEncodePackage(changed)), /SESSION/);
    assert.deepEqual(c.snapshot().stages, [3]);
  });
test("stage 1 and raw AEXB are not camera-session messages", () => {
  const c = new AexbCapture();
  assert.throws(() => c.accept(bytes(message(1).package_hex)), /STAGE/);
  assert.throws(() => c.accept(bytes(message(2).message_hex)), /ENVELOPE/);
});
test("captured bytes are owned by the collector", () => {
  const c = new AexbCapture();
  const input = bytes(message(2).package_hex);
  c.accept(input);
  input.fill(0);
  assert.equal(transcript(c), message(2).package_hex.toLowerCase());
});

// Independent QR encoder -> bundled camera decoder -> transport collector.
test("pixels from the existing QR encoder decode into a published UR frame", async () => {
  const { encode } = await import("uqr");
  const { Worker } = await import("node:worker_threads");
  const { buildQrWorkerSource } = await import("../scripts/qr-worker-source.mjs");
  const { QR_WASM_B64 } = await import("../src/js/qr-wasm-b64.js");
  const text = message(2).medium_ur_parts[0],
    qr = encode(text, { border: 4 }),
    scale = 5,
    w = qr.size * scale;
  const pixels = new Uint8ClampedArray(w * w * 4);
  for (let y = 0; y < w; y++)
    for (let x = 0; x < w; x++) {
      const at = (y * w + x) * 4,
        v = qr.data[Math.floor(y / scale)][Math.floor(x / scale)] ? 0 : 255;
      pixels.set([v, v, v, 255], at);
    }
  const worker = new Worker(`const { parentPort } = require("node:worker_threads");
    globalThis.self = { onmessage: null, postMessage(m,t) { parentPort.postMessage(m,t); } };
    parentPort.on("message", data => self.onmessage?.({data}));
` + await buildQrWorkerSource(), {eval:true});
  const next = () => new Promise((resolve, reject) => {
    worker.once("message", resolve); worker.once("error", reject);
  });
  try {
    let ready = next();
    const wasm = Uint8Array.from(Buffer.from(QR_WASM_B64, "base64"));
    worker.postMessage({type:"init", wasm:wasm.buffer}, [wasm.buffer]);
    assert.equal((await ready).type, "ready");
    const gray = Uint8Array.from({length:w*w}, (_,i) => pixels[i*4]);
    pixels.fill(0);
    ready = next();
    worker.postMessage({type:"decode",run:1,width:w,height:w,gray:gray.buffer}, [gray.buffer]);
    const reply = await ready;
    assert.equal(reply.code, text.length);
    const payload = new Uint8Array(reply.payload);
    assert.equal(new TextDecoder().decode(payload), text);
    payload.fill(0);
  } finally { await worker.terminate(); }
});


test("conflicting fragment and whole-message checksum fail closed", async () => {
  const { hodlBytewordsDecode, hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  const frames = message(2).medium_ur_parts;
  const words = frames[0].split("/");
  const payload = hodlBytewordsDecode(words.at(-1));
  payload[payload.length - 1] ^= 1;
  const changed = words.slice(0, -1).join("/") + "/" + hodlBytewordsEncode(payload);
  const conflict = new UrCapture(); conflict.receive(frames[0]);
  assert.throws(() => conflict.receive(changed), /CONFLICTING_FRAME/);
  const bad = new UrCapture(); bad.receive(changed);
  assert.throws(() => { for (const frame of frames.slice(1)) bad.receive(frame); }, /MESSAGE_CHECKSUM/);
  assert.equal(bad.progress().received, 0);
});

test("fountain part count is bounded before any row allocation", () => {
  const c = new UrCapture();
  const frame = message(2).medium_ur_parts[0].replace(/1-\d+/, "1-513");
  assert.throws(() => c.receive(frame), /PART_LIMIT/);
  assert.equal(c.progress().received, 0);
});

test("cross-network messages cannot enter the captured session", () => {
  const c = new AexbCapture();c.accept(bytes(message(3).package_hex));
  const changed = aexbDecode(bytes(message(2).package_hex));changed.network = 1;
  assert.throws(() => c.accept(aexbEncodePackage(changed)), /SESSION_MISMATCH/);
  assert.deepEqual(c.snapshot().stages, [3]);
});


test("camera demo success covers real PSBT signing hashes; chosen-nonce demo fails S2C despite valid ECDSA", async () => {
  const {secp256k1:curve}=await import("@noble/curves/secp256k1.js");
  const {Transaction}=await import("@scure/btc-signer");
  const demo=JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json",import.meta.url)));
  for(const [name, scenario] of Object.entries(demo.scenarios)) {
    const c=new AexbCapture();
    for(const m of scenario.messages)c.accept(bytes(m.package_hex));
    const verdict=c.snapshot().verdict;
    assert.equal(verdict.ok,name==="success");
    if(name==="success") assert.deepEqual(c.checkTransaction(), {ok:true,reason:null,checkedSlots:2,totalInputs:2,checkedInputs:[0,1]});
    if(name!=="success")assert.ok(verdict.slots.every(slot=>slot.reason==="OPENING_MISMATCH"));
    const decoded=aexbDecode(bytes(scenario.messages[2].package_hex));
    const signed=Transaction.fromPSBT(new Uint8Array(Buffer.from(scenario.signed_psbt_base64,"base64")));
    for(const slot of decoded.slots) {
      assert.equal(curve.verify(slot.signature,slot.messageHash,slot.signerPubkey,{prehash:false,lowS:true}),true);
      const der=signed.getInput(slot.inputIndex).partialSig[0][1].slice(0,-1);
      assert.deepEqual(curve.Signature.fromBytes(der,"der").toBytes("compact"),slot.signature);
    }
  }
});

// Keep references deliberately: checking only an empty Map would not prove wiping.
test("clear overwrites all collector-owned message buffers before releasing them", () => {
  const c = new AexbCapture();
  for (const stage of [2,3,4]) c.accept(bytes(message(stage).package_hex));
  const retained = [...c.messages.values()].flatMap(({bytes,decoded}) => [bytes,
    ...Object.values(decoded).filter(v => v instanceof Uint8Array),
    ...decoded.slots.flatMap(slot => Object.values(slot).filter(v => v instanceof Uint8Array))]);
  assert.ok(retained.some(v => v.some(byte => byte !== 0)));
  c.clear();
  assert.ok(retained.every(v => v.every(byte => byte === 0)));
  assert.equal(c.messages.size, 0);
});
test("clear overwrites incomplete UR rows before releasing them", () => {
  // The shared collector's allocation tracker replaces the old assembler's
  // public rows Map; keep the same retained-reference overwrite assertion.
  const retained = [];
  const c = new UrCapture({ track: retained }); c.receive(message(3).medium_ur_parts[0]);
  assert.ok(retained.length > 0);
  c.clear();
  assert.ok(retained.every(v => v.every(byte => byte === 0)));
  assert.deepEqual(c.progress(), {received:0,total:0,complete:false});
});

test("shared collector completion wipes fragments and caller owns the output", () => {
  const retained = [], c = new UrCapture({ track: retained });
  let result;
  for (const frame of message(3).medium_ur_parts) result = c.receive(frame);
  assert.deepEqual(result.bytes, bytes(message(3).package_hex));
  assert.ok(retained.length > 0 && retained.every(b => b.every(v => v === 0)));
  c.clear();
  assert.deepEqual(result.bytes, bytes(message(3).package_hex));
  result.bytes.fill(0);
  assert.deepEqual(c.progress(), { received: 0, total: 0, complete: false });
});

test("shared collection preserves ceremony limits and canonical byte envelopes", async () => {
  const { hodlUrPartCbor, hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  const frame = (count, length, size) => "ur:x-btc-anti-exfil/1-" + count + "/" +
    hodlBytewordsEncode(hodlUrPartCbor(1, count, length, 0x12345678, new Uint8Array(size)));
  for (const raw of [frame(2, 8194, 8193), frame(253, 2065601, 8192), frame(513, 513, 1)]) {
    const retained = [], c = new UrCapture({ track: retained });
    assert.ok(raw.length < 20000, "test reaches the inner limit");
    assert.throws(() => c.receive(raw), /PART_LIMIT/);
    assert.equal(retained.length, 0);
  }
  for (const [payload, error] of [
    [Uint8Array.of(0x58, 1, 65), /NONCANONICAL/],
    [Uint8Array.of(0x41, 65, 0), /TRAILING/],
    [Uint8Array.of(0x42, 65), /LENGTH/],
  ]) {
    const c = new UrCapture();
    assert.throws(() => c.receive("ur:x-btc-anti-exfil/" + hodlBytewordsEncode(payload)), error);
    c.clear();
  }
});

test("duplicate fragments do not inflate progress and conflict requires reset", async () => {
  const { hodlBytewordsDecode, hodlBytewordsEncode } = await import("../src/js/psbt-ur.js");
  const frames = message(3).medium_ur_parts;
  const c = new UrCapture(), first = c.receive(frames[0]);
  assert.deepEqual(c.receive(frames[0]), first);
  const words = frames[0].split("/"), payload = hodlBytewordsDecode(words.at(-1));
  payload[payload.length - 1] ^= 1;
  assert.throws(() => c.receive(words.slice(0, -1).join("/") + "/" + hodlBytewordsEncode(payload)), /CONFLICT/);
  assert.throws(() => c.receive(frames[1]), /CONFLICT/);
  c.clear();
  assert.deepEqual(c.receive(frames[0]), first);
});

test("synthetic transcript math cannot masquerade as embedded-PSBT validation", () => {
  const c=new AexbCapture();for(const stage of [2,3,4])c.accept(bytes(message(stage).package_hex));
  assert.equal(c.snapshot().verdict.ok,true);
  assert.deepEqual(c.checkTransaction(),{ok:false,reason:"TRANSACTION_INVALID",checkedSlots:0});
  c.clear();assert.equal(c.checkTransaction(),null);
});

test("finish returns only a verdict and wipes captured buffers before either result is shown", () => {
  const demo=JSON.parse(readFileSync(new URL("./fixtures/aexb/camera-demo.json",import.meta.url)));
  for(const [name,scenario] of Object.entries(demo.scenarios)) {
    const c=new AexbCapture();c.accept(bytes(scenario.messages[0].package_hex));
    assert.equal(c.finish(),null);assert.deepEqual(c.snapshot().stages,[2]);
    for(const m of scenario.messages.slice(1))c.accept(bytes(m.package_hex));
    const retained=[...c.messages.values()].flatMap(({bytes,decoded})=>[bytes,decoded.psbt,...decoded.slots.flatMap(s=>Object.values(s).filter(v=>v instanceof Uint8Array))]);
    const result=c.finish();assert.equal(result.ok,name==='success');
    assert.deepEqual(Object.keys(result).sort(),(name==='success'?['checkedInputs','checkedSlots','ok','reason','totalInputs','totalSlots']:['checkedSlots','ok','reason','totalSlots']));
    assert.ok(retained.every(v=>v.every(byte=>byte===0)));
    assert.equal(transcript(c),'');assert.equal(c.checkTransaction(),null);assert.deepEqual(c.snapshot().stages,[]);
  }
});

// Retain rejected temporary copies, including the assembled message on bad CRC.
test("rejected UR fragment and checksum copies are overwritten", async () => {
 const {hodlBytewordsDecode,hodlBytewordsEncode}=await import("../src/js/psbt-ur.js");
 const frames=message(3).medium_ur_parts,words=frames[0].split('/'),payload=hodlBytewordsDecode(words.at(-1));
 payload[payload.length-1]^=1;
 const changed=words.slice(0,-1).join('/')+'/'+hodlBytewordsEncode(payload);
 for(const kind of ['conflict','checksum']) {
  const c=new UrCapture();const retained=[];const slice=Uint8Array.prototype.slice;
  // Capture only sizeable transport copies, not short public PRNG digests.
  Uint8Array.prototype.slice=function(...args){const result=slice.apply(this,args);if(result.length>8)retained.push(result);return result;};
  try {
   if(kind==='conflict'){c.receive(frames[0]);assert.throws(()=>c.receive(changed),/CONFLICTING_FRAME/);}
   else {c.receive(changed);assert.throws(()=>{for(const f of frames.slice(1))c.receive(f)},/MESSAGE_CHECKSUM/);}
   c.clear();
  } finally {Uint8Array.prototype.slice=slice;}
  assert.ok(retained.length>1);assert.ok(retained.every(b=>b.every(x=>x===0)),kind+' retained nonzero rejected copies');
 }
});
