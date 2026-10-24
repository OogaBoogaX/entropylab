// BIP 388 wallet policy export from an already-derived watch-only multisig.
//
// Template + key vector. Calculator export, not a generator. No entropy, no
// I/O, no private keys. `/**` means receive and change (`/<0;1>/*`).
// Taproot-with-NUMS and BIP45 two-step tails are refused.

import {
  assertMatchingWatchDescriptors,
  canonicalizeWatchDescriptor,
  stripDescriptorChecksum,
} from "./core-importdescriptors.js";

const PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
const RANGED_KEY = /(\[(?:[0-9a-fA-F]{8})\/[^\]]+\])?((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]{90,})\/([01])\/\*/g;
const NUMS_TR = /^tr\([0-9a-fA-F]{64},/;

function codecOf(decode, encode) {
  return decode && encode ? { decode, encode } : null;
}

function originToBip388(info) {
  return info.replace(/\[([0-9a-fA-F]{8})\/([^\]]+)\]/, (_, fingerprint, path) =>
    `[${fingerprint}/${path.replace(/(\d+)h/gi, "$1'")}]`);
}

function extractRangedKeys(body, branch) {
  const keys = [];
  const seen = new Set();
  RANGED_KEY.lastIndex = 0;
  let match;
  while ((match = RANGED_KEY.exec(body))) {
    const info = `${match[1] || ""}${match[2]}`;
    if (seen.has(match[2])) throw new Error("BIP 388 export: a key appears in more than one slot.");
    seen.add(match[2]);
    if (match[3] !== branch) {
      throw new Error("BIP 388 export: every receive key must end in /0/* and every change key in /1/*.");
    }
    keys.push(info);
  }
  if (!keys.length) throw new Error("BIP 388 export: no /0/* or /1/* xpub keys in the descriptor.");
  return keys;
}

function toTemplate(body, keys) {
  let template = body;
  for (let i = keys.length - 1; i >= 0; i--) {
    const info = keys[i];
    template = template.split(`${info}/0/*`).join(`@${i}/**`);
    template = template.split(`${info}/1/*`).join(`@${i}/**`);
  }
  if (PRIVATE_KEY.test(template) || /[xt]pub|[xt]prv/i.test(template)) {
    throw new Error("BIP 388 export: leftover extended key after building the template.");
  }
  if (/\/\d+\/\*/.test(template)) throw new Error("BIP 388 export: only /0/* and /1/* tails are supported (no BIP45).");
  for (let i = 0; i < keys.length; i++) {
    if (!template.includes(`@${i}/**`)) throw new Error(`BIP 388 export: missing placeholder @${i}.`);
  }
  return template;
}

export function buildBip388Policy({ receiveDescriptor, changeDescriptor, decode, encode } = {}) {
  const receive = String(receiveDescriptor ?? "").trim();
  if (!receive) throw new Error("No watch-only descriptor to export as a BIP 388 policy.");
  const codec = codecOf(decode, encode);
  const canonicalReceive = canonicalizeWatchDescriptor(receive, codec, "Receive descriptor");
  let canonicalChange = "";
  if (changeDescriptor) {
    canonicalChange = canonicalizeWatchDescriptor(changeDescriptor, codec, "Change descriptor");
    assertMatchingWatchDescriptors(canonicalReceive, canonicalChange);
  }
  const body = stripDescriptorChecksum(canonicalReceive);
  if (NUMS_TR.test(body)) throw new Error("BIP 388 export: taproot with a NUMS internal key is not a BIP 388 policy (keys must be xpubs).");
  const keys = extractRangedKeys(body, "0");
  const descriptorTemplate = toTemplate(body, keys);
  if (canonicalChange) {
    const changeBody = stripDescriptorChecksum(canonicalChange);
    // The change side must be the same keys, every one on /1/*.
    extractRangedKeys(changeBody, "1");
    const changeTemplate = toTemplate(changeBody, keys);
    if (changeTemplate !== descriptorTemplate) throw new Error("BIP 388 export: receive and change do not share one policy template.");
  }
  return {
    descriptorTemplate,
    keys: keys.map(originToBip388),
  };
}

export function formatBip388Policy(policy) {
  const lines = [
    "# BIP 388 wallet policy",
    "# Watch-only. EntropyLab calculator export. Cannot spend.",
    "",
    `descriptor_template: ${policy.descriptorTemplate}`,
    "",
    "keys:",
  ];
  policy.keys.forEach((key, index) => lines.push(`@${index} ${key}`));
  lines.push("");
  return lines.join("\n");
}

export function buildBip388PolicyText(options) {
  return formatBip388Policy(buildBip388Policy(options));
}

export function bip388PolicyFilename(wallet = {}) {
  const m = wallet.m;
  const n = wallet.n;
  if (Number.isSafeInteger(m) && Number.isSafeInteger(n)) return `entropylab-msig-${m}of${n}-bip388.txt`;
  return "entropylab-bip388.txt";
}
