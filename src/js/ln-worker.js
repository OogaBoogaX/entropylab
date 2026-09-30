// Entry of the Lightning key worker. The build bundles this file (with the
// real aezeed, BIP32 and BIP39 modules) into a string the page starts as a
// Web Worker; the page hands it the WebAssembly module bytes in the first
// message. The seed's secrets live here, not in the page: the page gets the
// public result, and the secret text only while the user reveals it. Clear,
// a format or network change, and page hide terminate this worker, so its
// whole heap and WebAssembly memory go with it.
//
// Protocol (after the page's { type: "init", wasm } message):
//   page -> worker  { type: "derive", run, format, words, passphrase, coinType }
//   worker -> page  { type: "derived", run, result }   public fields only
//   worker -> page  { type: "error", run, error: { message, key, vars, code } }
//   page -> worker  { type: "reveal", run }
//   worker -> page  { type: "revealed", run, secrets: { entropyHex, saltHex, rootXprv } }
import { deriveLightning } from "./lightning-derive.js";
import { hex } from "./coders.js";

let held = null; // the last derivation's secrets

const drop = () => {
  if (held) {
    if (held.entropy) held.entropy.fill(0);
    if (held.salt) held.salt.fill(0);
  }
  held = null;
};

self.onmessage = (event) => {
  const data = event.data;
  if (!data) return;
  if (data.type === "derive") {
    drop();
    try {
      const { result, secret } = deriveLightning(data);
      held = secret;
      self.postMessage({ type: "derived", run: data.run, result });
    } catch (exception) {
      drop();
      self.postMessage({
        type: "error",
        run: data.run,
        error: {
          message: exception instanceof Error ? exception.message : String(exception),
          key: typeof exception?.key === "string" ? exception.key : undefined,
          vars: exception?.vars,
          code: exception?.code,
        },
      });
    }
  } else if (data.type === "reveal") {
    const secrets = held
      ? { entropyHex: held.entropy ? hex.encode(held.entropy) : null, saltHex: held.salt ? hex.encode(held.salt) : null, rootXprv: held.rootXprv }
      : null;
    self.postMessage({ type: "revealed", run: data.run, secrets });
  }
};
