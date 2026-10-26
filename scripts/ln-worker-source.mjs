// Bundles the Lightning key worker (src/js/ln-worker.js) into the source
// string the page starts as a Web Worker from a Blob. scripts/build.mjs
// injects it into the page; test/lightning-worker.test.mjs runs the same
// string under node:worker_threads, so what ships is what is tested.
//
// The worker is bundled without the base64 WebAssembly module (the page
// hands it the module bytes at start), so the page does not carry the
// module twice. The wrapper runs the bundle only once those bytes arrived.
import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

// entropylab-wasm-b64.js resolves to an empty stand-in inside the worker.
const moduleBytesAtRuntime = {
  name: "wasm-module-bytes-at-runtime",
  setup(builder) {
    builder.onResolve({ filter: /entropylab-wasm-b64\.js$/ }, () => ({ path: "entropylab-wasm-b64", namespace: "runtime-bytes" }));
    builder.onLoad({ filter: /.*/, namespace: "runtime-bytes" }, () => ({ contents: 'export const ENTROPYLAB_WASM_B64 = "";', loader: "js" }));
  },
};

export async function buildLnWorkerSource() {
  const result = await build({
    entryPoints: [join(root, "src/js/ln-worker.js")],
    bundle: true,
    minify: true,
    write: false,
    format: "iife",
    platform: "browser",
    target: "es2022",
    legalComments: "none",
    charset: "utf8",
    plugins: [moduleBytesAtRuntime],
  });
  const bundle = result.outputFiles[0].text;
  // The first message carries the module bytes; the bundle's own handler
  // replaces this one when it runs, before the next message is dispatched.
  return [
    '"use strict";',
    "self.onmessage = function (event) {",
    "  var data = event.data;",
    '  if (!data || data.type !== "init" || !(data.wasm instanceof ArrayBuffer)) return;',
    "  self.onmessage = null;",
    "  self.__entropyLabWasmBytes = data.wasm;",
    bundle,
    '  self.postMessage({ type: "ready" });',
    "};",
    "",
  ].join("\n");
}
