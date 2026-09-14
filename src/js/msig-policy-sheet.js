// Watch-only multisig policy sheet.
//
// One-page print/save of an already-derived MS Station result: policy, co-signer
// fingerprints, descriptor checksum, receive address 0. Calculator export, not
// a generator. No private keys, no mnemonic, no entropy.

const PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
const SCRIPT_LABEL = {
  p2sh: "Legacy",
  "p2sh-p2wsh": "Nested SegWit",
  p2wsh: "Native SegWit",
  p2tr: "Taproot",
};

function stripChecksum(descriptor) {
  const text = String(descriptor ?? "");
  const hash = text.lastIndexOf("#");
  return hash >= 0 ? text.slice(0, hash) : text;
}

function descriptorChecksumOf(descriptor) {
  const text = String(descriptor ?? "");
  const hash = text.lastIndexOf("#");
  if (hash < 0 || hash + 9 !== text.length) return "";
  const checksum = text.slice(hash + 1);
  return /^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$/.test(checksum) ? checksum : "";
}

function firstReceive(wallet) {
  const branch = wallet.addressBranches?.find((entry) => entry.branch === 0);
  const row = Array.isArray(branch?.rows) && branch.rows[0]
    ? branch.rows[0]
    : Array.isArray(wallet.receive) ? wallet.receive[0] : null;
  const address = String(row?.address ?? "").trim();
  if (!address) return null;
  return { address, path: String(row.path ?? ""), index: Number.isSafeInteger(row.index) ? row.index : 0 };
}

function coSigners(wallet) {
  if (Array.isArray(wallet.scriptOrder) && wallet.scriptOrder.length) {
    return wallet.scriptOrder.map((item, index) => ({
      position: Number.isSafeInteger(item.position) ? item.position : index + 1,
      fingerprint: String(item.fingerprint ?? ""),
      path: String(item.path ?? ""),
    }));
  }
  const body = stripChecksum(wallet.receiveDescriptor);
  const found = [];
  const pattern = /\[([0-9a-fA-F]{8})\/([^\]]+)\]/g;
  let match;
  while ((match = pattern.exec(body))) {
    found.push({ position: found.length + 1, fingerprint: match[1], path: match[2] });
  }
  return found;
}

function policyOp(wallet) {
  const sorted = wallet.sorted !== false;
  if (wallet.script === "p2tr") return sorted ? "sortedmulti_a" : "multi_a";
  return sorted ? "sortedmulti" : "multi";
}

export function canPrintPolicySheet(wallet) {
  if (!wallet || wallet.kind !== "msig") return false;
  if (PRIVATE_KEY.test(String(wallet.receiveDescriptor ?? "")) || PRIVATE_KEY.test(String(wallet.changeDescriptor ?? ""))) return false;
  if (!descriptorChecksumOf(wallet.receiveDescriptor || wallet.walletDescriptor || "")) return false;
  return Boolean(firstReceive(wallet));
}

export function policySheetFilename(wallet = {}) {
  const m = wallet.m;
  const n = wallet.n;
  const policy = Number.isSafeInteger(m) && Number.isSafeInteger(n) ? `msig-${m}of${n}` : "msig";
  return `entropylab-${policy}-watch-only-policy.txt`;
}

export function buildPolicySheet(wallet) {
  if (!canPrintPolicySheet(wallet)) throw new Error("Watch-only policy sheet needs a derived multisig with receive address 0.");
  const receive = wallet.receiveDescriptor || wallet.walletDescriptor;
  if (PRIVATE_KEY.test(receive) || PRIVATE_KEY.test(String(wallet.changeDescriptor ?? ""))) {
    throw new Error("Watch-only policy sheet refused an extended private key.");
  }
  const row = firstReceive(wallet);
  const checksum = descriptorChecksumOf(receive);
  const network = String(wallet.network || "mainnet");
  return {
    m: wallet.m,
    n: wallet.n,
    network,
    networkLoud: network !== "mainnet",
    script: wallet.script,
    scriptLabel: SCRIPT_LABEL[wallet.script] || "Unknown",
    sorted: wallet.sorted !== false,
    policyOp: policyOp(wallet),
    checksum,
    keys: coSigners(wallet),
    address: row.address,
    addressPath: row.path,
    addressIndex: row.index,
    receiveDescriptor: receive,
  };
}

export function policySheetText(wallet) {
  const sheet = buildPolicySheet(wallet);
  const lines = [
    "ENTROPYLAB — WATCH-ONLY MULTISIG POLICY SHEET",
    "Calculator export. Not a generator. Cannot spend.",
    "",
    `Network: ${sheet.network}`,
    `Script: ${sheet.scriptLabel}`,
    `Policy: ${sheet.m}-of-${sheet.n} ${sheet.policyOp}`,
    `Descriptor checksum: #${sheet.checksum}`,
    "",
    "Co-signers (script order):",
  ];
  for (const key of sheet.keys) {
    const origin = key.fingerprint ? `${key.fingerprint}${key.path ? "/" + key.path : ""}` : "(no origin)";
    lines.push(`${key.position}  ${origin}`);
  }
  lines.push("", `Receive address #${sheet.addressIndex}:`, sheet.address);
  if (sheet.addressPath) lines.push(`Path: ${sheet.addressPath}`);
  lines.push(
    "",
    "WARNING: Watch-only policy. Cannot spend. Verify this address on every signer before funding.",
    "",
    "Watch-only receive descriptor:",
    sheet.receiveDescriptor,
    "",
  );
  return lines.join("\n");
}

function escapeHtml(value) {
  return Array.from(String(value ?? ""), (character) => {
    if (character === "&") return "\u0026amp;";
    if (character === "<") return "\u0026lt;";
    if (character === ">") return "\u0026gt;";
    if (character === '"') return "\u0026quot;";
    if (character === "'") return "\u0026#39;";
    return character;
  }).join("");
}

export function policySheetHtml(wallet, { qrSvg } = {}) {
  const sheet = buildPolicySheet(wallet);
  const qr = typeof qrSvg === "function" ? qrSvg(sheet.address) : "";
  const keys = sheet.keys.map((key) => {
    const origin = key.fingerprint ? `${key.fingerprint}${key.path ? "/" + key.path : ""}` : "(no origin)";
    return `<li><span class="msig-policy-pos">${escapeHtml(String(key.position))}</span> <code>${escapeHtml(origin)}</code></li>`;
  }).join("");
  const networkClass = sheet.networkLoud ? " msig-policy-network-loud" : "";
  return `<article class="msig-policy-sheet">
  <header class="msig-policy-head">
    <p class="msig-policy-mark">EntropyLab</p>
    <p class="msig-policy-kicker">Watch-only multisig policy</p>
    <p class="msig-policy-network${networkClass}">${escapeHtml(sheet.network)}</p>
  </header>
  <p class="msig-policy-policy"><strong>${escapeHtml(String(sheet.m))}-of-${escapeHtml(String(sheet.n))}</strong> · ${escapeHtml(sheet.scriptLabel)} · ${escapeHtml(sheet.policyOp)}</p>
  <p class="msig-policy-checksum">Descriptor checksum <code>#${escapeHtml(sheet.checksum)}</code></p>
  <h2>Co-signers</h2>
  <ol class="msig-policy-keys">${keys}</ol>
  <h2>Receive address #${escapeHtml(String(sheet.addressIndex))}</h2>
  <div class="msig-policy-address">
    ${qr ? `<div class="qr qr-policy">${qr}</div>` : ""}
    <p class="mono msig-policy-addr">${escapeHtml(sheet.address)}</p>
    ${sheet.addressPath ? `<p class="mono msig-policy-path">${escapeHtml(sheet.addressPath)}</p>` : ""}
  </div>
  <p class="msig-policy-warning">Watch-only policy. Cannot spend. Verify this address on every signer before funding.</p>
</article>`;
}
