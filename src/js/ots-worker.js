// Entry of the OpenTimestamps verification worker. The build bundles this
// file into a string the page starts as a Web Worker; the page hands it the
// WebAssembly module bytes in the first message. Parsing, verification and
// hashing the original file run here, never on the page's thread, so a
// hostile proof or a large file cannot freeze the page.
//
// Protocol (after the page's { type: "init", wasm } message, which the
// bundle wrapper consumes):
//   page -> worker  { type: "verify", run, proof, header, expected, original }
//   worker -> page  { type: "verified", run, result }
//   worker -> page  { type: "error", run, error: { name, code, message } }
import { verifyOts } from "./ots-verifier.js";

const ERROR_NAMES = new Set(["OtsParseError", "OtsBudgetError", "RangeError", "TypeError", "Error"]);

const failure = (run, error) => ({
  type: "error",
  run,
  error: {
    name: ERROR_NAMES.has(error && error.name) ? error.name : "Error",
    code: error && error.code != null ? error.code : null,
    message: error && typeof error.message === "string" ? error.message : "Verification failed.",
  },
});

self.onmessage = async (event) => {
  const data = event.data;
  if (!data || typeof data !== "object" || data.type !== "verify") {
    self.postMessage({
      type: "error",
      run: data && typeof data === "object" ? data.run : undefined,
      error: { name: "Error", code: "BAD_MESSAGE", message: "Bad message." },
    });
    return;
  }
  const { run } = data;
  try {
    const result = await verifyOts({
      proofBytes: new Uint8Array(data.proof),
      header: data.header ? new Uint8Array(data.header) : null,
      expectedDigest: data.expected ? new Uint8Array(data.expected) : null,
      originalFileBytes: data.original ? new Uint8Array(data.original) : null,
    });
    self.postMessage({ type: "verified", run, result });
  } catch (error) {
    self.postMessage(failure(run, error));
  }
};
