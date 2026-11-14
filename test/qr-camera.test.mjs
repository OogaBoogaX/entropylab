import test from "node:test";
import assert from "node:assert/strict";
import { CameraCapture } from "../src/js/qr-camera.js";
const video = () => ({ srcObject: null, play: async () => {}, pause() {} });
test("stop during permission request retires the late stream", async () => {
  let resolve;
  let stopped = 0;
  const c = new CameraCapture({
    getUserMedia: () => new Promise((r) => (resolve = r)),
    decode: () => null,
  });
  const v = video();
  const pending = c.start(v, "camera", () => {});
  c.stop();
  resolve({
    getTracks: () => [
      {
        stop() {
          stopped++;
        },
      },
    ],
  });
  await pending;
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});
test("stop during frame decode cannot deliver stale text", async () => {
  let resolve;
  let delivered = 0,
    stopped = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({
      getTracks: () => [
        {
          stop() {
            stopped++;
          },
        },
      ],
    }),
    decode: () => new Promise((r) => (resolve = r)),
  });
  const v = video();
  await c.start(v, "camera", () => delivered++);
  c.stop();
  resolve("secret");
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(delivered, 0);
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});
test("play failure releases every track", async () => {
  let stopped = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({
      getTracks: () => [
        {
          stop() {
            stopped++;
          },
        },
      ],
    }),
    decode: () => null,
  });
  const v = video();
  v.play = async () => {
    throw Error("play");
  };
  await assert.rejects(c.start(v, "", () => {}));
  assert.equal(stopped, 1);
  assert.equal(v.srcObject, null);
});


test("disconnect stops the stream and reports one disconnect without late frames", async (t) => {
  let ended, stops=0, delivered=0; const errors=[];
  const track={stop(){stops++;},addEventListener(name,fn){if(name==="ended")ended=fn;}};
  const c=new CameraCapture({getUserMedia:async()=>({getTracks:()=>[track]}),decode:()=>null});
  t.after(()=>c.stop()); const v=video();await c.start(v,"uvc",()=>delivered++,e=>errors.push(e.code));
  assert.equal(typeof ended,"function");ended();ended();
  assert.equal(stops,1);assert.equal(v.srcObject,null);assert.equal(delivered,0);
  assert.deepEqual(errors,["CAMERA_DISCONNECTED"]);
});


test("camera stop retires pending decoder work before it can deliver", async () => {
  let retirements = 0, resolve, delivered = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({ getTracks: () => [] }),
    decode: () => new Promise(r => { resolve = r; }),
    stopDecode: () => { retirements++; },
  });
  await c.start(video(), "", () => delivered++);
  const before = retirements;
  c.stop();
  assert.equal(retirements, before + 1);
  resolve("late");
  await new Promise(r => setTimeout(r, 0));
  assert.equal(delivered, 0);
});

for (const failure of ["play", "decode", "disconnect"]) {
  test(`camera ${failure} failure retires its decoder`, async () => {
    let retired = 0, ended;
    const c = new CameraCapture({
      getUserMedia: async () => ({ getTracks: () => [{ stop() {}, addEventListener(_, fn) { ended = fn; } }] }),
      decode: () => { if (failure === "decode") throw Error("decoder failed"); return null; },
      stopDecode: () => { retired++; },
    });
    const v = video();
    if (failure === "play") v.play = async () => { throw Error("play failed"); };
    if (failure === "play") await assert.rejects(c.start(v, "", () => {}));
    else {
      await c.start(v, "", () => {});
      if (failure === "disconnect") ended();
    }
    assert.equal(retired, 2); // Initial lifetime reset, then failure retirement.
    assert.equal(v.srcObject, null);
    c.stop();
  });
}


test("throwing decoder shutdown cannot prevent camera cleanup or deliver a late frame", async () => {
  let throwOnStop = false, stopped = 0, resolve, delivered = 0;
  const c = new CameraCapture({
    getUserMedia: async () => ({ getTracks: () => [{ stop() { stopped++; } }] }),
    decode: () => new Promise(r => { resolve = r; }),
    stopDecode: () => { if (throwOnStop) throw Error("shutdown failed"); },
  });
  const v = video();
  await c.start(v, "", () => delivered++);
  throwOnStop = true;
  try { c.stop(); } catch { /* Assert cleanup independently of the thrown error. */ }
  assert.equal(stopped, 1, "camera track must stop even when decoder retirement throws");
  assert.equal(v.srcObject, null);
  assert.equal(c.stream, null);
  assert.equal(c.video, null);
  assert.doesNotThrow(() => c.stop(), "Clear callers must be able to continue clearing transcripts");
  resolve("late");
  await new Promise(r => setTimeout(r, 0));
  assert.equal(delivered, 0);
});
