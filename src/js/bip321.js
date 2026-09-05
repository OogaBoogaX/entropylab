// BIP-321 bitcoin: URI parse/print for Silent Payments, plus the BIP-353 DNS
// TXT a human pastes on a domain they control.
//
// Calculator only. Never fetch, never resolve DNS, never talk to a name
// service. A name like you@example.com is printed as the lookup hostname to
// create — the user brings the published URI back in.

const SP_ADDRESS = /^(sp|tsp)1[0-9a-z]{60,}$/i;
const LIGHTNING_KEYS = new Set(["lightning", "lno"]);

function decodeComponent(raw, what) {
  try {
    return decodeURIComponent(String(raw).replace(/\+/g, "%20"));
  } catch {
    throw new Error(`Malformed percent-encoding in the ${what}.`);
  }
}

function parseQuery(query) {
  if (!query) return [];
  return String(query).split("&").filter(Boolean).map((part) => {
    const eq = part.indexOf("=");
    const key = decodeComponent(eq === -1 ? part : part.slice(0, eq), "URI parameter name");
    const value = decodeComponent(eq === -1 ? "" : part.slice(eq + 1), "URI parameter");
    return { key: key.toLowerCase(), value };
  });
}

function assertSilentPaymentAddress(address) {
  const text = String(address || "").trim().toLowerCase();
  if (!SP_ADDRESS.test(text)) throw new Error("Not a silent payment address.");
  return text;
}

// bitcoin:?sp=<sp1q…>  — no on-chain address, no Lightning, no amount.
export function encodeBitcoinUri(address) {
  return `bitcoin:?sp=${assertSilentPaymentAddress(address)}`;
}

export function encodeBip353Txt(address) {
  return encodeBitcoinUri(address);
}

// BIP-353: user@domain → user.user._bitcoin-payment.domain — the fixed "user"
// label sits between the local part and _bitcoin-payment. There is no
// domain-only form; a bare domain is refused. A pasted ₿ prefix is display
// chrome, never part of the DNS label.
export function bip353Lookup(name) {
  const trimmed = String(name || "").trim().replace(/^₿/, "");
  if (!trimmed) return null;
  if (/\s/.test(trimmed)) throw new Error("A payment name cannot contain spaces.");
  if (/^bitcoin:/i.test(trimmed)) throw new Error("That is a URI, not a payment name.");
  const at = trimmed.lastIndexOf("@");
  if (at === -1) throw new Error("A payment name needs a user part, like you@example.com.");
  if (at === 0) throw new Error("Payment name is missing the user part before @.");
  if (at === trimmed.length - 1) throw new Error("Payment name is missing the domain after @.");
  const user = trimmed.slice(0, at);
  const domain = trimmed.slice(at + 1);
  if (!/^[A-Za-z0-9._-]+$/.test(domain) || !domain.includes(".")) {
    throw new Error("Payment name domain must look like example.com.");
  }
  if (!/^[A-Za-z0-9._-]+$/.test(user)) {
    throw new Error("Payment name user part can only use letters, digits, dot, underscore, or hyphen.");
  }
  const lookup = `${user.toLowerCase()}.user._bitcoin-payment.${domain.toLowerCase()}`;
  return { name: `${user}@${domain}`, lookup };
}

export function parseBitcoinUri(raw) {
  const text = String(raw || "").trim().replace(/^['"]|['"]$/g, "");
  const match = text.match(/^bitcoin:(?:\/\/)?([^?]*)(?:\?([^#]*))?(?:#.*)?$/i);
  if (!match) return null;
  const params = parseQuery(match[2] || "");
  for (const { key } of params) {
    if (key.startsWith("req-")) throw new Error(`Unsupported required URI parameter: ${key}.`);
  }
  const silentPayments = params.filter((item) => item.key === "sp").map((item) => assertSilentPaymentAddress(item.value));
  const lightning = params.some((item) => LIGHTNING_KEYS.has(item.key));
  const amount = params.find((item) => item.key === "amount")?.value ?? "";
  return {
    scheme: "bitcoin",
    address: match[1] || "",
    silentPayments,
    lightning,
    amount,
  };
}

// One recipient line: a raw sp1q/tsp1q, or a bitcoin:?sp= URI, plus optional
// trailing output count. Names like you@domain are refused — we do not resolve.
export function parseRecipientLine(line) {
  let text = String(line || "").trim();
  if (!text) throw new Error("Empty recipient line.");
  let count = 1;
  const counted = text.match(/^(.*\S)\s+(\d+)$/);
  if (counted) {
    text = counted[1];
    count = Number(counted[2]);
    if (!Number.isInteger(count) || count < 1) throw new Error("Recipient count must be a positive integer.");
  }
  if (/^bitcoin:/i.test(text)) {
    const uri = parseBitcoinUri(text);
    if (!uri) throw new Error("Not a bitcoin: URI.");
    if (!uri.silentPayments.length) throw new Error("No silent payment (sp=) in this URI.");
    if (uri.silentPayments.length > 1 && counted) {
      throw new Error("A URI with several sp= values cannot take a trailing count.");
    }
    return uri.silentPayments.map((address) => ({
      address,
      count,
      lightning: uri.lightning,
    }));
  }
  if (text.includes("@") && !SP_ADDRESS.test(text)) {
    throw new Error("This page does not resolve DNS. Paste a bitcoin:?sp= URI or an sp1q address.");
  }
  if (!SP_ADDRESS.test(text)) throw new Error(`Not a silent payment address: ${text.slice(0, 24)}`);
  return [{ address: text.toLowerCase(), count, lightning: false }];
}

export function parseRecipientLines(text) {
  const lines = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) throw new Error("Paste at least one silent payment address.");
  const recipients = [];
  let lightning = false;
  for (const line of lines) {
    for (const row of parseRecipientLine(line)) {
      recipients.push({ address: row.address, count: row.count });
      if (row.lightning) lightning = true;
    }
  }
  return { recipients, lightning };
}
