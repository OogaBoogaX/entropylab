// AEXB-v1 transcript adapter.
// Pure module: no DOM, no shared state, no curve math.

import { aexbDecode } from "../aexb.js";

export function detect(input) {
  try {
    aexbDecode(input);
    return true;
  } catch {
    return false;
  }
}

export function normalize(input) {
  return { kind: "aexb", decoded: aexbDecode(input) };
}
