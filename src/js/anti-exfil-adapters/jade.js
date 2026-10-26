// Jade anti-exfil transcript adapter.
// Pure module: no DOM, no shared state, no curve math.

import { hex } from "../coders.js";

export function detect(input) {
  try {
    return normalize(input) !== null;
  } catch {
    return false;
  }
}

export function normalize(input) {
  if (!input || !String(input).trim()) return null;
  let text = String(input).replace(/0x/gi, ""), tokens = text.split(/[^0-9a-fA-F]+/).filter((token) => token.length), host = null, openings = [];
  for (let token of tokens) {
    if (token.length === 64) {
      if (host) throw new Error("Paste one 32-byte Jade host nonce.");
      host = hex.decode(token.toLowerCase());
    } else if (token.length === 66) {
      let opening = hex.decode(token.toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) throw new Error("Jade opening R must be a compressed secp256k1 point.");
      openings.push(opening);
    } else if (token.length === 130) {
      if (host || openings.length) throw new Error("Paste the host nonce and opening once, or as separate hex values.");
      host = hex.decode(token.slice(0, 64).toLowerCase());
      let opening = hex.decode(token.slice(64).toLowerCase());
      if (opening[0] !== 2 && opening[0] !== 3) throw new Error("Jade opening R must be a compressed secp256k1 point.");
      openings.push(opening);
    } else if (token.length < 64) continue;
    else throw new Error("Jade anti-exfil transcript wants a 32-byte host nonce \u03C1 and a 33-byte compressed opening R, as hex.");
  }
  if (!host || !openings.length) throw new Error("Jade anti-exfil needs both the host nonce \u03C1 and the signer opening R.");
  return { kind: "jade", host, openings };
}
