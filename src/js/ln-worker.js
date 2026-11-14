// Entry of the Lightning key worker. The build bundles this file (with the
// real aezeed, BIP32, BIP39 and hsm_secret modules) into a string the page
// starts as a Web Worker; the page hands it the WebAssembly module bytes in
// the first message. The seed's secrets live here, not in the page: the page
// gets the public result, and the secret text only while the user reveals
// it. Clear, a format or network change, End Session and page hide ask this
// worker to scrub its secrets and overwrite its WebAssembly memory, then
// terminate it, so its whole heap goes with it.
//
// Protocol (after the page's { type: "init", wasm } message, which the
// bundle wrapper consumes):
//   page -> worker  { type: "derive", run, format, words, text, passphrase, coinType, network }
//   worker -> page  { type: "derived", run, request: "derive", result }  public fields only
//   worker -> page  { type: "error", run, request, error: { message, key, vars, code } }
//   page -> worker  { type: "reveal", run }
//   worker -> page  { type: "revealed", run, request: "reveal", secrets: { entropyHex, saltHex, rootXprv } }
//   page -> worker  { type: "load-hsm", run, bytes }   the hsm_secret file's bytes
//   worker -> page  { type: "hsm-loaded", run, request: "load-hsm" }  the words stay here
//   page -> worker  { type: "drop-hsm" }   typing is the most recent entry
//   page -> worker  { type: "drop" }   a refused derive wipes the held secrets
//   page -> worker  { type: "scrub" }   the page is about to terminate this worker
//   worker -> page  { type: "scrubbed" }   secrets dropped, WebAssembly memory overwritten
import { createLnKeyHandler } from "./lightning-derive.js";
import { retireWasm } from "./entropylab-wasm.js";

// scrubWasm is the same retireWasm End Session uses on the page: on scrub
// this worker overwrites its own WebAssembly memory before the page
// terminates it.
const handle = createLnKeyHandler((message) => self.postMessage(message), { scrubWasm: retireWasm });
self.onmessage = (event) => handle(event.data);
