// OpenTimestamps verifier UI — issue #315, phase 3.
//
// Pure helpers (testable without DOM):
//   parseHexInput(s)        - hex string → Uint8Array (handles "0x", whitespace)
//   formatResult(out)       - verifier result → {tone, headline, body}
//   formatError(err)        - Error → {tone, headline, body}
//
// DOM wiring:
//   initOtsVerifier(rootEl, { createVerifier }) - wires the fixed ids in the
//                             Verify card to a verifier worker. If rootEl is
//                             omitted, looks up the ids via getElementById.
//
// Result panel MUST show the issue-required warning for MATCHES:
//   "Header supplied by user. Bitcoin chain membership and proof-of-work
//    are not verified."
// plus explicit "NOT yet anchored" framing for PENDING so users cannot
// mistake pending attestations for Bitcoin-anchored timestamps.

import { OTS_LIMITS } from "./ots-parser.js";
import { createOtsVerifier } from "./ots-verify-client.js";

// ---- pure helpers --------------------------------------------------------

export function parseHexInput(s) {
  if (typeof s !== "string") throw new TypeError("hex input must be a string");
  // Trim, then strip a single optional "0x"/"0X" prefix and any whitespace
  // (spaces, tabs, newlines, commas).
  const trimmed = s.trim().replace(/^0x/i, "").replace(/[\s,]+/g, "").toLowerCase();
  if (trimmed.length === 0) throw new RangeError("hex input is empty");
  if (trimmed.length % 2 !== 0) {
    throw new RangeError(`hex input must have an even number of characters; got ${trimmed.length}`);
  }
  if (!/^[0-9a-f]*$/.test(trimmed)) {
    throw new Error("hex input contains non-hex characters");
  }
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function formatResult(out) {
  if (!out || typeof out !== "object") {
    return { tone: "danger", headline: "Error", body: "No verification result." };
  }
  switch (out.result) {
    case "MATCHES_SUPPLIED_HEADER":
      return {
        tone: "success",
        headline: "MATCHES SUPPLIED HEADER",
        body: [
          "The OTS commitment path is cryptographically consistent with the Merkle root contained in the supplied 80-byte Bitcoin block header.",
          "",
          "WARNING — Header supplied by user. Bitcoin chain membership and proof-of-work are not verified. The strongest result available from this offline mode is cryptographic consistency with the bytes you provided. A fabricated header would also pass.",
          "",
          "This does not establish that the supplied header was mined, satisfies Bitcoin proof-of-work, belongs to Bitcoin mainnet, is at the claimed height, or is part of the canonical/best chain.",
        ].join("\n"),
      };
    case "INVALID": {
      let body =
        "At least one completed supported Bitcoin attestation was evaluated, but none matched the supplied header. This is a cryptographic inconsistency between the proof and the header you supplied.";
      const reason = out.reason;
      if (typeof reason === "string") {
        if (reason.startsWith("parse:")) body = "This is not a valid OpenTimestamps proof file.";
        else if (reason === "expected-digest") body = "The proof's file digest does not match the expected digest.";
        else if (reason === "original-file") body = "The original file does not hash to the proof's file digest.";
        else if (reason === "op-too-long") body = "The proof is invalid: an operation exceeds OpenTimestamps' 4096-byte limit.";
        else if (reason === "header-mismatch") body = "No completed Bitcoin attestation in this proof matches the supplied header.";
        body += `\n\nReason: ${reason}`;
      }
      return { tone: "danger", headline: "INVALID", body };
    }
    case "HEADER_REQUIRED":
      return {
        tone: "warning",
        headline: "HEADER REQUIRED",
        body: [
          "Bitcoin header required to evaluate this path.",
          "",
          "This proof has a completed Bitcoin attestation. Supply the block header for one of the claimed heights to check it.",
        ].join("\n"),
      };
    case "INCOMPLETE": {
      const limit =
        typeof out.limit === "string" ? out.limit : typeof out.reason === "string" ? out.reason : "";
      const body =
        "Verification incomplete: this proof exceeds EntropyLab's resource limits. This is not a verdict about the proof.";
      return {
        tone: "warning",
        headline: "INCOMPLETE",
        body: limit ? `${body}\n\nLimit hit: ${limit}` : body,
      };
    }
    case "PENDING":
      return {
        tone: "warning",
        headline: "PENDING — NO COMPLETED BITCOIN ATTESTATION",
        body: [
          "No completed Bitcoin attestation was checked. This verification does not establish Bitcoin anchoring.",
          "",
          "This is not an anchored or confirmed timestamp.",
        ].join("\n"),
      };
    case "UNSUPPORTED":
      return {
        tone: "neutral",
        headline: "UNSUPPORTED",
        body: [
          "No path led to a verifiable verdict in v1 scope. The proof may rely on operation tags or attestation types outside v1 (keccak256, reverse, hexlify, litecoin, or unknown future types). Sibling paths with v1-supported operations were also evaluated.",
          "",
          "UNSUPPORTED — OTS operation not supported by this verifier.",
          "UNSUPPORTED — attestation type not supported by this verifier.",
        ].join("\n"),
      };
    default:
      return { tone: "neutral", headline: String(out.result), body: "" };
  }
}

export function formatError(err) {
  if (err && err.name === "OtsBudgetError" && err.code) {
    return { tone: "danger", headline: `Resource limit: ${err.code}`, body: err.message };
  }
  if (err && err.name === "OtsParseError" && err.code) {
    return { tone: "danger", headline: `Parse error: ${err.code}`, body: err.message };
  }
  if (err instanceof RangeError) {
    return { tone: "danger", headline: "Input length error", body: err.message };
  }
  if (err instanceof TypeError) {
    return { tone: "danger", headline: "Input type error", body: err.message };
  }
  return {
    tone: "danger",
    headline: "Error",
    body: err && err.message ? err.message : String(err),
  };
}

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

// ---- DOM wiring -----------------------------------------------------------

// The markup lives in src/shell.html inside a preview block. This module only
// reads it by id and writes results with textContent / createElement, so no
// verifier-derived string is ever parsed as HTML.

const WIRING_IDS = [
  "verify-card",
  "ots-proof-file",
  "ots-proof-hex",
  "ots-original-file",
  "ots-header-hex",
  "ots-expected-digest",
  "ots-verify",
  "ots-clear",
  "ots-result",
];

// Which safety hook each verdict must expose to the tests, without matching
// English. The wording itself lives in formatResult().
const WARNING_HOOKS = {
  MATCHES_SUPPLIED_HEADER: "header-not-verified",
  INVALID: "invalid",
  PENDING: "not-anchored",
  HEADER_REQUIRED: "header-required",
  INCOMPLETE: "limit",
  UNSUPPORTED: "unsupported",
};

function resolveDocument(root) {
  if (root && typeof root.getElementById === "function") return root;
  if (root && root.ownerDocument && typeof root.ownerDocument.getElementById === "function") {
    return root.ownerDocument;
  }
  if (typeof document !== "undefined" && document && typeof document.getElementById === "function") {
    return document;
  }
  return null;
}

function requireElement(doc, id) {
  const el = doc.getElementById(id);
  if (!el) throw new Error(`initOtsVerifier: missing #${id}`);
  return el;
}

// lengths: the byte lengths accepted. A file digest is 32 bytes for SHA-256
// and 20 for SHA-1 or RIPEMD-160; the verifier compares it with the proof's.
function readOptionalHex(value, lengths, label) {
  if (typeof value !== "string" || value.trim() === "") return undefined;
  const bytes = parseHexInput(value);
  if (!lengths.includes(bytes.length)) {
    const allowed = lengths.map((n) => `${n} bytes (${n * 2} hex chars)`).join(" or ");
    throw new RangeError(`${label} must be exactly ${allowed}; got ${bytes.length} bytes`);
  }
  return bytes;
}

// Refuses a file over the limit before reading it: the parser and verifier
// limits only apply once the bytes are in memory.
async function readFileBytes(input, limit, label) {
  if (!input || !input.files || input.files.length === 0) return undefined;
  const file = input.files[0];
  if (!file || typeof file.arrayBuffer !== "function") {
    throw new TypeError("Selected file could not be read as bytes");
  }
  if (typeof file.size === "number" && file.size > limit) {
    throw new RangeError(`${label} is ${file.size} bytes, limit ${limit}`);
  }
  return new Uint8Array(await file.arrayBuffer());
}

// A pasted proof is refused before parsing when it is longer than the file
// limit allows, with the same error an oversized proof file gets.
function parsePastedProof(value) {
  if (typeof value === "string" && value.length > 4 * OTS_LIMITS.MAX_PROOF_BYTES) {
    throw new RangeError(
      `Proof file is ${Math.floor(value.length / 2)} bytes, limit ${OTS_LIMITS.MAX_PROOF_BYTES}`,
    );
  }
  return parseHexInput(value);
}

// nTime of a Bitcoin block header: uint32 little-endian at byte 68 (#315).
function headerTime(headerBytes) {
  return (
    (headerBytes[68] | (headerBytes[69] << 8) | (headerBytes[70] << 16) | (headerBytes[71] << 24)) >>> 0
  );
}

// Claimed heights and the header's nTime are claims, never verified chain state.
function collectClaims(out, headerBytes) {
  const claims = [];
  const heights = new Set();
  const paths = out && Array.isArray(out.paths) ? out.paths : [];
  for (const path of paths) {
    const att = path && path.attestation;
    if (att && Number.isInteger(att.height)) heights.add(att.height);
  }
  for (const height of [...heights].sort((a, b) => a - b)) {
    claims.push({ kind: "height", text: `OTS attestation claims height: ${height}` });
  }
  if (headerBytes && headerBytes.length === 80) {
    claims.push({
      kind: "header-time",
      text: `Bitcoin header time (claim, not the time the file existed): ${headerTime(headerBytes)}`,
    });
  }
  return claims;
}

function renderPathRow(doc, path) {
  const row = doc.createElement("div");
  row.setAttribute("class", "ots-path");
  row.setAttribute("data-ots-path", String(path && path.outcome));

  const outcome = doc.createElement("span");
  outcome.setAttribute("class", "ots-outcome");
  outcome.setAttribute("data-ots-path-outcome", String(path && path.outcome));
  outcome.textContent = String(path && path.outcome);
  row.appendChild(outcome);

  const ops = doc.createElement("code");
  ops.setAttribute("data-ots-path-ops", "");
  ops.textContent = path && path.opNames && path.opNames.length ? path.opNames.join(" → ") : "(no ops)";
  row.appendChild(ops);

  if (path && path.attestation) {
    const att = doc.createElement("span");
    att.setAttribute("data-ots-path-attestation", String(path.attestation.type));
    att.textContent = path.attestation.uriHex
      ? `${path.attestation.type} URI ${String(path.attestation.uriHex).slice(0, 16)}…`
      : String(path.attestation.type);
    row.appendChild(att);
  }

  if (path && path.finalDigest) {
    const hex = bytesToHex(path.finalDigest);
    const digest = doc.createElement("code");
    digest.setAttribute("data-ots-path-digest", "");
    digest.textContent = hex.length > 16 ? `${hex.slice(0, 16)}…` : hex;
    row.appendChild(digest);
  }

  if (path && path.detail) {
    const detail = doc.createElement("span");
    detail.setAttribute("data-ots-path-detail", "");
    detail.textContent = String(path.detail);
    row.appendChild(detail);
  }

  if (path && path.length !== undefined) {
    const len = doc.createElement("span");
    len.setAttribute("data-ots-path-length", "");
    len.textContent = `${path.length}/${path.limit} bytes`;
    row.appendChild(len);
  }

  return row;
}

// Exported so the verdict wording and its data-* hooks can be tested without
// running the verifier.
export function renderOtsResult(doc, resultEl, out, options = {}) {
  const r = formatResult(out);
  const verdict = out && typeof out.result === "string" ? out.result : "ERROR";

  while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
  resultEl.hidden = false;
  resultEl.setAttribute("data-ots-verdict", verdict);
  resultEl.setAttribute("data-ots-tone", r.tone);

  const warning = WARNING_HOOKS[verdict];
  if (warning) resultEl.setAttribute("data-ots-warning", warning);
  else resultEl.removeAttribute("data-ots-warning");

  if (verdict === "INVALID" && out && typeof out.reason === "string") {
    resultEl.setAttribute("data-ots-reason", out.reason);
  } else {
    resultEl.removeAttribute("data-ots-reason");
  }

  if (verdict === "INCOMPLETE") {
    const limit = out && (out.limit || out.reason);
    if (typeof limit === "string") resultEl.setAttribute("data-ots-limit", limit);
    else resultEl.removeAttribute("data-ots-limit");
  } else {
    resultEl.removeAttribute("data-ots-limit");
  }

  // 1. Headline.
  const headline = doc.createElement("p");
  headline.setAttribute("class", "label");
  headline.setAttribute("data-ots-headline", "");
  headline.textContent = r.headline;
  resultEl.appendChild(headline);

  // 2. Explanation: the first paragraph. 3. Limitations: the rest, in a
  // caution note for MATCHES and PENDING, plain paragraphs otherwise.
  const paragraphs = String(r.body).split("\n\n").filter((para) => para !== "");
  const explanation = paragraphs.shift();
  if (explanation !== undefined) {
    const p = doc.createElement("p");
    p.textContent = explanation;
    resultEl.appendChild(p);
  }
  const cautionVerdicts = verdict === "MATCHES_SUPPLIED_HEADER" || verdict === "PENDING";
  if (paragraphs.length > 0) {
    if (cautionVerdicts) {
      const caution = doc.createElement("div");
      caution.setAttribute("class", "edge-note is-private");
      caution.setAttribute("data-ots-caution", "");
      for (const para of paragraphs) {
        const p = doc.createElement("p");
        p.textContent = para;
        caution.appendChild(p);
      }
      resultEl.appendChild(caution);
    } else {
      for (const para of paragraphs) {
        const p = doc.createElement("p");
        p.textContent = para;
        resultEl.appendChild(p);
      }
    }
  }

  // 4. Claimed heights stay visible for HEADER_REQUIRED; every other verdict
  // puts them inside the paths disclosure.
  const claims = collectClaims(out, options.headerBytes);
  const appendClaims = (container) => {
    for (const claim of claims) {
      const p = doc.createElement("p");
      p.setAttribute("data-ots-claim", claim.kind);
      p.textContent = claim.text;
      container.appendChild(p);
    }
  };
  if (verdict === "HEADER_REQUIRED") appendClaims(resultEl);

  // 5. A file was supplied but never compared: its hash op is one the verifier
  // cannot compute, or it is over the verifier's size limit.
  const originalUnchecked = ["unsupported-hash", "too-large"].includes(out && out.original && out.original.status);
  if (options.originalFileProvided === false || originalUnchecked) {
    const p = doc.createElement("p");
    p.setAttribute("data-ots-original-file", "not-checked");
    p.textContent = "Original file not checked";
    resultEl.appendChild(p);
  }

  // 6. Paths disclosure.
  const paths = out && Array.isArray(out.paths) ? out.paths : [];
  if (paths.length === 0) {
    if (verdict !== "HEADER_REQUIRED") appendClaims(resultEl);
    const p = doc.createElement("p");
    p.setAttribute("data-ots-paths", "");
    p.textContent = "No attestation paths in this proof.";
    resultEl.appendChild(p);
  } else {
    const details = doc.createElement("details");
    details.setAttribute("class", "derivation-advanced");
    details.setAttribute("data-ots-paths", "");
    const summary = doc.createElement("summary");
    summary.textContent = `Attestation paths (${paths.length})`;
    details.appendChild(summary);
    // The rows sit in their own box: browsers put a <details> element's
    // contents in an internal box, so spacing set on <details> never reaches
    // them.
    const body = doc.createElement("div");
    body.setAttribute("class", "ots-paths-body");
    if (verdict !== "HEADER_REQUIRED") appendClaims(body);
    for (const path of paths) body.appendChild(renderPathRow(doc, path));
    details.appendChild(body);
    resultEl.appendChild(details);
  }
}

export function renderOtsError(doc, resultEl, err) {
  const e = formatError(err);
  while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
  resultEl.hidden = false;
  resultEl.setAttribute("data-ots-verdict", "ERROR");
  resultEl.setAttribute("data-ots-tone", e.tone);
  resultEl.removeAttribute("data-ots-warning");
  resultEl.removeAttribute("data-ots-reason");
  resultEl.removeAttribute("data-ots-limit");

  const group = doc.createElement("div");
  group.setAttribute("class", "edge-note-titled");
  group.setAttribute("data-ots-error", "");

  const headline = doc.createElement("p");
  headline.setAttribute("class", "edge-note-title is-private");
  headline.setAttribute("data-ots-headline", "");
  headline.textContent = e.headline;
  group.appendChild(headline);

  const note = doc.createElement("div");
  note.setAttribute("class", "edge-note is-private");
  for (const line of String(e.body).split("\n")) {
    if (line === "") continue;
    const p = doc.createElement("p");
    p.textContent = line;
    note.appendChild(p);
  }
  group.appendChild(note);

  resultEl.appendChild(group);
}

function clearResult(resultEl) {
  while (resultEl.firstChild) resultEl.removeChild(resultEl.firstChild);
  resultEl.hidden = true;
  resultEl.removeAttribute("data-ots-verdict");
  resultEl.removeAttribute("data-ots-tone");
  resultEl.removeAttribute("data-ots-warning");
  resultEl.removeAttribute("data-ots-reason");
  resultEl.removeAttribute("data-ots-limit");
}

export function initOtsVerifier(root, { createVerifier = createOtsVerifier } = {}) {
  const doc = resolveDocument(root);
  if (!doc) throw new TypeError("initOtsVerifier: document is required");

  const els = {};
  for (const id of WIRING_IDS) els[id] = requireElement(doc, id);
  const verifier = createVerifier();

  const proofFile = els["ots-proof-file"];
  const proofHex = els["ots-proof-hex"];
  const originalFile = els["ots-original-file"];
  const headerHex = els["ots-header-hex"];
  const expectedDigest = els["ots-expected-digest"];
  const verifyBtn = els["ots-verify"];
  const clearBtn = els["ots-clear"];
  const resultEl = els["ots-result"];
  const proofName = doc.getElementById("ots-proof-name");
  const originalName = doc.getElementById("ots-original-name");

  // Each Verify click takes a new run number. An edit or Clear moves the
  // counter on and stops the verifier, so a stale run renders nothing.
  let runId = 0;
  const cancelRun = () => {
    runId += 1;
    verifier.stop();
  };

  const proofChoose = doc.getElementById("ots-proof-choose");
  if (proofChoose && typeof proofChoose.addEventListener === "function") {
    proofChoose.addEventListener("click", () => proofFile.click());
  }

  const originalChoose = doc.getElementById("ots-original-choose");
  if (originalChoose && typeof originalChoose.addEventListener === "function") {
    originalChoose.addEventListener("click", () => originalFile.click());
  }

  clearBtn.addEventListener("click", () => {
    cancelRun();
    proofHex.value = "";
    headerHex.value = "";
    expectedDigest.value = "";
    proofFile.value = "";
    originalFile.value = "";
    if (proofName) {
      proofName.textContent = "";
      proofName.hidden = true;
    }
    if (originalName) {
      originalName.textContent = "";
      originalName.hidden = true;
    }
    clearResult(resultEl);
  });

  for (const el of [proofHex, headerHex, expectedDigest, proofFile, originalFile]) {
    el.addEventListener("input", () => {
      cancelRun();
      clearResult(resultEl);
    });
    el.addEventListener("change", () => {
      cancelRun();
      clearResult(resultEl);
    });
  }

  // One proof at a time, the one entered last: a chosen .ots file would
  // otherwise win over a proof pasted afterwards, and Verify would check the
  // file while the box shows the pasted hex.
  proofHex.addEventListener("input", () => {
    if (!proofFile.value) return;
    proofFile.value = "";
    if (proofName) {
      proofName.textContent = "";
      proofName.hidden = true;
    }
  });
  proofFile.addEventListener("change", () => {
    if (proofFile.files && proofFile.files.length > 0) proofHex.value = "";
  });

  for (const [input, note] of [[proofFile, proofName], [originalFile, originalName]]) {
    input.addEventListener("change", () => {
      if (!note) return;
      const file = input.files && input.files[0];
      if (file && file.name) {
        note.textContent = file.name;
        note.hidden = false;
      } else {
        note.textContent = "";
        note.hidden = true;
      }
    });
  }

  verifyBtn.addEventListener("click", async () => {
    const run = ++runId;
    verifyBtn.disabled = true;
    try {
      const fileBytes = await readFileBytes(proofFile, OTS_LIMITS.MAX_PROOF_BYTES, "Proof file");
      if (run !== runId) return;
      const proofBytes = fileBytes || parsePastedProof(proofHex.value);
      const originalFileBytes = await readFileBytes(originalFile, OTS_LIMITS.MAX_ORIGINAL_BYTES, "Original file");
      if (run !== runId) return;
      const headerBytes = readOptionalHex(headerHex.value, [80], "Bitcoin header");
      const expectedBytes = readOptionalHex(expectedDigest.value, [32, 20], "Expected initial digest");
      const out = await verifier.verify({
        proofBytes,
        // The verifier transfers its inputs to the worker; the page keeps its
        // own copy of the header for the header-time claim.
        header: headerBytes ? headerBytes.slice() : headerBytes,
        expectedDigest: expectedBytes,
        originalFileBytes,
      });
      if (run !== runId) return;
      renderOtsResult(doc, resultEl, out, {
        headerBytes,
        originalFileProvided: originalFileBytes !== undefined,
      });
    } catch (err) {
      // A cancelled run was cleared on purpose: render nothing.
      if (err && err.code === "CANCELLED") return;
      if (run !== runId) return;
      renderOtsError(doc, resultEl, err);
    } finally {
      verifyBtn.disabled = false;
    }
  });
}
