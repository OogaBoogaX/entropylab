// OpenTimestamps verifier UI — issue #315, phase 3.
//
// Pure helpers (testable without DOM):
//   parseHexInput(s)        - hex string → Uint8Array (handles "0x", whitespace)
//   formatResult(out)       - verifier result → {tone, headline, body}
//   formatError(err)        - Error → {tone, headline, body}
//   pathSummaryHtml(path)   - one path → HTML string (escaped)
//   pathSummaryListHtml(paths) - list of paths → combined HTML string
//
// DOM wiring:
//   initOtsVerifier(rootEl) - fills the mount point with the UI and
//                             wires the verify button to call verifyOts().
//                             If rootEl is omitted, looks up
//                             #ots-verifier-mount via getElementById.
//
// Result panel MUST show the issue-required warning for MATCHES:
//   "Header supplied by user. Bitcoin chain membership and proof-of-work
//    are not verified."
// plus explicit "NOT yet anchored" framing for PENDING so users cannot
// mistake pending attestations for Bitcoin-anchored timestamps.

import { verifyOts } from "./ots-verifier.js";

// ---- pure helpers --------------------------------------------------------

export function parseHexInput(s) {
  if (typeof s !== "string") throw new TypeError("hex input must be a string");
  // Strip a single optional "0x"/"0X" prefix and any whitespace (spaces,
  // tabs, newlines, commas).
  const trimmed = s.replace(/^0x/i, "").replace(/[\s,]+/g, "").toLowerCase();
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
  switch (out.result) {
    case "MATCHES_SUPPLIED_HEADER":
      return {
        tone: "success",
        headline: "MATCHES SUPPLIED HEADER",
        body: [
          "The OTS commitment path is cryptographically consistent with the Merkle root contained in the supplied 80-byte Bitcoin block header.",
          "",
          "WARNING — Header supplied by user. Bitcoin chain membership and proof-of-work are not verified. The strongest result available from this offline mode is cryptographic consistency with the bytes you provided. A fabricated header would also pass.",
        ].join("\n"),
      };
    case "INVALID":
      return {
        tone: "danger",
        headline: "INVALID",
        body:
          "At least one completed supported Bitcoin attestation was evaluated, but none matched the supplied header. This is a cryptographic inconsistency between the proof and the header you supplied.",
      };
    case "PENDING":
      return {
        tone: "warning",
        headline: "PENDING — NO COMPLETED BITCOIN ATTESTATION",
        body:
          "The proof contains at least one pending attestation but no completed Bitcoin attestation was reached. This is NOT yet anchored to Bitcoin — do not describe this state as a Bitcoin-anchored timestamp or as \"valid pending\".",
      };
    case "UNSUPPORTED":
      return {
        tone: "neutral",
        headline: "UNSUPPORTED",
        body:
          "No path led to a verifiable verdict in v1 scope. The proof may rely on operation tags or attestation types outside v1 (keccak256, reverse, hexlify, litecoin, or unknown future types). Sibling paths with v1-supported operations were also evaluated.",
      };
    default:
      return { tone: "neutral", headline: String(out.result), body: "" };
  }
}

export function formatError(err) {
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

const escapeHtml = (s) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export function pathSummaryHtml(path) {
  const ops = path.opNames && path.opNames.length ? escapeHtml(path.opNames.join(" → ")) : "(no ops)";
  let row = `<div class="ots-path-row">`;
  row += `<span class="ots-outcome ots-outcome-${escapeHtml(path.outcome)}">${escapeHtml(path.outcome)}</span> `;
  row += `<code class="ots-ops">${ops}</code>`;
  if (path.attestation) {
    const uri = path.attestation.uriHex ? ` URI ${escapeHtml(path.attestation.uriHex.slice(0, 16))}…` : "";
    row += ` <span class="ots-att">${escapeHtml(path.attestation.type)}${uri}</span>`;
  }
  if (path.finalDigest) {
    const hex = bytesToHex(path.finalDigest);
    const preview = hex.length > 16 ? `${hex.slice(0, 16)}…` : hex;
    row += ` <code class="ots-digest">${escapeHtml(preview)}</code>`;
  }
  if (path.detail) row += ` <span class="ots-detail">${escapeHtml(path.detail)}</span>`;
  if (path.length !== undefined) row += ` <span class="ots-length">${path.length}/${path.limit} bytes</span>`;
  row += `</div>`;
  return row;
}

export function pathSummaryListHtml(paths) {
  if (!paths || paths.length === 0) {
    return '<p class="muted">No attestation paths in this proof.</p>';
  }
  return paths.map(pathSummaryHtml).join("\n");
}

// ---- DOM wiring -----------------------------------------------------------

const TEMPLATE_HTML = `
<section class="card tool-card ots-verifier-card" aria-labelledby="ots-verifier-heading">
  <div class="kicker">Offline only · No network access</div>
  <h2 id="ots-verifier-heading">OpenTimestamps verifier</h2>
  <p class="muted">
    Verify an OpenTimestamps (<code>.ots</code>) proof against a Bitcoin block header that <strong>you supply</strong>.
    A <code>MATCHES SUPPLIED HEADER</code> result does <strong>NOT</strong> prove the header was mined,
    satisfies proof-of-work, belongs to mainnet, or is part of the canonical chain. It only proves
    cryptographic consistency with the bytes you provide.
  </p>
  <label for="ots-proof-hex"><code>.ots</code> proof (hex)</label>
  <textarea id="ots-proof-hex" rows="6" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" placeholder="Paste the .ots file as hex. Optional 0x prefix and whitespace are ignored."></textarea>
  <label for="ots-header-hex">Bitcoin block header (hex, exactly 80 bytes / 160 hex chars)</label>
  <textarea id="ots-header-hex" rows="3" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" placeholder="80-byte Bitcoin block header, hex-encoded (160 chars). Leave empty to skip Bitcoin evaluation."></textarea>
  <label for="ots-expected-hex">Optional: expected initial digest (hex, 32 bytes)</label>
  <textarea id="ots-expected-hex" rows="2" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" placeholder="Bind this verification to an external commitment (e.g. BIP-322 / PACT). Optional."></textarea>
  <button id="ots-verify-btn" class="btn primary" type="button">Verify</button>
  <div id="ots-result" class="ots-result" hidden></div>
  <details id="ots-paths-detail">
    <summary>Path breakdown</summary>
    <div id="ots-paths" class="ots-paths"></div>
  </details>
</section>
`;

function renderResultInElement(el, tone, headline, body) {
  el.className = `ots-result ots-result-${tone}`;
  const safeHeadline = escapeHtml(headline);
  const safeBody = escapeHtml(body)
    .split("\n")
    .map((line) => (line === "" ? "<br>" : `<p>${line}</p>`))
    .join("");
  el.innerHTML = `<h3>${safeHeadline}</h3>${safeBody}`;
}

export function initOtsVerifier(root) {
  if (!root) {
    if (typeof document === "undefined") {
      throw new Error("initOtsVerifier: no root element provided and document is unavailable");
    }
    root = document.getElementById("ots-verifier-mount");
  }
  if (!(root instanceof Element)) {
    throw new TypeError("initOtsVerifier: mount point element not found");
  }

  root.innerHTML = TEMPLATE_HTML;

  const verifyBtn = root.querySelector("#ots-verify-btn");
  const proofEl = root.querySelector("#ots-proof-hex");
  const headerEl = root.querySelector("#ots-header-hex");
  const expectedEl = root.querySelector("#ots-expected-hex");
  const resultEl = root.querySelector("#ots-result");
  const pathsEl = root.querySelector("#ots-paths");

  verifyBtn.addEventListener("click", async () => {
    verifyBtn.disabled = true;
    resultEl.hidden = false;
    pathsEl.innerHTML = '<p class="muted">Verifying…</p>';

    try {
      const proofBytes = parseHexInput(proofEl.value);
      let headerBytes;
      if (headerEl.value.trim()) {
        headerBytes = parseHexInput(headerEl.value);
        if (headerBytes.length !== 80) {
          throw new RangeError(
            `Bitcoin header must be exactly 80 bytes (160 hex chars); got ${headerBytes.length} bytes`,
          );
        }
      }
      let expectedBytes;
      if (expectedEl.value.trim()) {
        expectedBytes = parseHexInput(expectedEl.value);
        if (expectedBytes.length !== 32) {
          throw new RangeError(
            `Expected initial digest must be 32 bytes (64 hex chars); got ${expectedBytes.length} bytes`,
          );
        }
      }

      const out = await verifyOts({ proofBytes, header: headerBytes, expectedDigest: expectedBytes });
      const r = formatResult(out);
      renderResultInElement(resultEl, r.tone, r.headline, r.body);
      pathsEl.innerHTML = pathSummaryListHtml(out.paths);
    } catch (err) {
      const e = formatError(err);
      renderResultInElement(resultEl, e.tone, e.headline, e.body);
      pathsEl.innerHTML = "";
    } finally {
      verifyBtn.disabled = false;
    }
  });
}
