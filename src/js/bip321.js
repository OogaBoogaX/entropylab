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
  const trimmed = String(address || "").trim();
  // Bech32m is all-lowercase or all-uppercase; mixed case is invalid and must
  // be rejected before normalization launders it (issue #335).
  if (trimmed !== trimmed.toLowerCase() && trimmed !== trimmed.toUpperCase()) {
    throw new Error("A silent payment address must be all lowercase or all uppercase, not mixed case.");
  }
  const text = trimmed.toLowerCase();
  if (!SP_ADDRESS.test(text)) throw new Error("Not a silent payment address.");
  return text;
}

// A BIP-321 amount is decimal BTC, exactly as in BIP-21. Parse to satoshis
// with integer math — never f64 — and reject everything out of scope:
// duplicate parameters, negatives, exponents, non-numeric text, amounts past
// the 21M supply cap, and sub-satoshi precision (issue #326).
function parseBtcAmount(raw) {
  const text = String(raw);
  if (!/^\d+(\.\d+)?$/.test(text)) throw new Error("The URI's amount must be decimal BTC, like 0.01.");
  const [whole, fraction = ""] = text.split(".");
  if (fraction.length > 8) throw new Error("The URI's amount carries more precision than one satoshi.");
  const sats = BigInt(whole) * 100000000n + BigInt((fraction + "00000000").slice(0, 8));
  if (sats > 2100000000000000n) throw new Error("The URI's amount exceeds Bitcoin's 21M supply cap.");
  return sats.toString();
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
  // One payment carries one amount; BIP-321 defines a repeated amount
  // parameter as invalid.
  const amounts = params.filter((item) => item.key === "amount");
  if (amounts.length > 1) throw new Error("A bitcoin: URI carries at most one amount.");
  const amount = amounts[0]?.value ?? "";
  return {
    scheme: "bitcoin",
    address: match[1] || "",
    silentPayments,
    lightning,
    amount,
    amountSats: amounts.length ? parseBtcAmount(amount) : null,
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
    // BIP-321 repeats a payment-instruction parameter to offer alternatives
    // the sender chooses among — never instructions to pay them all
    // (issues #321, #363). Identical repeats collapse; distinct instructions
    // select the first supported one, and the choice is surfaced.
    const distinct = [...new Set(uri.silentPayments)];
    if (distinct.length > 1 && counted) {
      throw new Error("A URI with several sp= values cannot take a trailing count.");
    }
    return [{
      address: distinct[0],
      count,
      lightning: uri.lightning,
      amount: uri.amount || null,
      amountSats: uri.amountSats,
      alternatives: distinct.length > 1 ? distinct.length : 0,
    }];
  }
  if (text.includes("@") && !SP_ADDRESS.test(text)) {
    throw new Error("This page does not resolve DNS. Paste a bitcoin:?sp= URI or an sp1q address.");
  }
  if (!SP_ADDRESS.test(text)) throw new Error(`Not a silent payment address: ${text.slice(0, 24)}`);
  return [{ address: assertSilentPaymentAddress(text), count, lightning: false, amount: null, amountSats: null, alternatives: 0 }];
}

export function parseRecipientLines(text) {
  const lines = String(text || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) throw new Error("Paste at least one silent payment address.");
  const recipients = [];
  let lightning = false, alternatives = 0;
  for (const line of lines) {
    for (const row of parseRecipientLine(line)) {
      recipients.push({ address: row.address, count: row.count, amount: row.amount ?? null, amountSats: row.amountSats ?? null });
      if (row.lightning) lightning = true;
      alternatives += row.alternatives ?? 0;
    }
  }
  return { recipients, lightning, alternatives };
}
