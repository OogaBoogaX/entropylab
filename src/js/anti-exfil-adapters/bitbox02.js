// BitBox02 anti-klepto transcript adapter.
// Pure module: no DOM, no shared state, no curve math.

import { hex } from "../coders.js";
import { sha256 } from "../hashes.js";
import { hodlParseBitboxTranscript } from "../psbt-bitbox.js";

export function detect(input) {
  try {
    return normalize(input) !== null;
  } catch {
    return false;
  }
}

export function normalize(input) {
  const parsed = hodlParseBitboxTranscript(input, hex.decode, sha256);
  if (!parsed) return null;
  return {
    kind: "bitbox02",
    host: parsed.hostNonce,
    openings: [parsed.opening],
    commitment: parsed.commitment,
    commitmentMatches: parsed.commitmentMatches,
  };
}
