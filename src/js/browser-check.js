
// Browser sanity check: runs a quick barrage of smoke tests at startup to
// confirm this host can run EntropyLab's wallet math correctly. Every check
// covers a platform feature the application depends on: a secure context,
// the CSPRNG (locked cryptographic dependencies), BigInt arithmetic (key derivation and the SQLite
// writer), UTF-8 TextEncoder/TextDecoder (hashing entropy input and writing
// wallet.dat), NFKD string normalization (BIP39 passphrases), and WebAssembly
// (the secp256k1 curve engine). The
// checks are synchronous, read-only, and generate no network traffic. When
// every check passes the page is left untouched; when any check fails the
// entire page is killed and replaced with a centered failure report listing
// the failed checks, because wallet output from a broken host cannot be
// trusted. This script runs before the application scripts so a host broken
// enough to crash them still gets the failure screen. A second,
// independent unit at the bottom of this file gates the page on the beta
// disclaimer.
(() => {
  // Each check returns true when the browser behaves and throws or returns
  // false when it does not. Keep every check free of BigInt literal syntax
  // so a browser too old for BigInt still parses this file and reports the
  // failure instead of dying silently.
  const checks = [
    {
      name: "Secure browser context",
      run: () => window.isSecureContext === true,
    },
    {
      name: "crypto.getRandomValues (CSPRNG)",
      run: () => {
        if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") return false;
        const first = new Uint8Array(32);
        const second = new Uint8Array(32);
        if (crypto.getRandomValues(first) !== first) return false;
        crypto.getRandomValues(second);
        const allZero = (bytes) => bytes.every((byte) => byte === 0);
        if (allZero(first) || allZero(second)) return false;
        // Two independent CSPRNG fills must not match; a broken generator
        // that repeats the same bytes would silently reuse key material.
        return !first.every((byte, index) => byte === second[index]);
      },
    },
    {
      name: "BigInt arithmetic",
      run: () => {
        if (typeof BigInt !== "function") return false;
        // 2**255 + 1 exercises wide arithmetic across the full secp256k1
        // range without relying on BigInt literal syntax.
        const value = (BigInt(1) << BigInt(255)) + BigInt(1);
        return value.toString(16) === "8" + "0".repeat(62) + "1";
      },
    },
    {
      name: "TextEncoder/TextDecoder (UTF-8)",
      run: () => {
        if (typeof TextEncoder !== "function" || typeof TextDecoder !== "function") return false;
        // U+00E9 (composed e-acute) must encode as UTF-8 C3 A9 and decode back.
        const bytes = new TextEncoder().encode("\u00e9");
        if (bytes.length !== 2 || bytes[0] !== 0xc3 || bytes[1] !== 0xa9) return false;
        return new TextDecoder().decode(bytes) === "\u00e9";
      },
    },
    {
      name: "WebAssembly (secp256k1 engine)",
      run: () => {
        if (typeof WebAssembly !== "object" || typeof WebAssembly.Module !== "function") return false;
        // Compile the smallest valid module (8 bytes, far under the
        // synchronous-compilation size limit): proves both the engine and the
        // content security policy allow WebAssembly before the app boots its
        // secp256k1 module.
        new WebAssembly.Module(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
        return true;
      },
    },
    {
      name: "String.normalize (NFKD)",
      run: () => {
        if (typeof "".normalize !== "function") return false;
        // BIP39 passphrases are NFKD-normalized: U+00E9 must decompose
        // into e + U+0301. Escapes keep file re-encoding from breaking this.
        // escapes so file re-encoding cannot silently break the comparison.
        return "\u00e9".normalize("NFKD") === "e\u0301";
      },
    },
  ];

  const failed = [];
  for (const { name, run } of checks) {
    let ok = false;
    try {
      ok = run() === true;
    } catch {
      ok = false;
    }
    if (!ok) failed.push(name);
  }

  // Record the outcome on <html> so tests and support can confirm the
  // barrage actually ran, even when everything passed and the page lives.
  const root = document.documentElement;
  if (root) {
    root.dataset.browserChecks = String(checks.length);
    root.dataset.browserFailed = String(failed.length);
  }
  if (failed.length === 0 || !document.body) return;

  // Kill the page: replace everything with the centered failure report.
  // Check names are trusted literals defined above, never user input.
  const rows = failed.map((name) => `<tr><td>${name}</td><td>Failed</td></tr>`).join("");
  const wasmFailed = failed.includes("WebAssembly (secp256k1 engine)");
  // Lockdown Mode (iPhone, iPad, Mac) disables WebAssembly. There is no JS
  // secp256k1 fallback: wallet math is libsecp256k1 compiled to WASM.
  const advice = wasmFailed
    ? `<p class="sanity-failure-advice">iPhone, iPad, and Mac Lockdown Mode block WebAssembly. This calculator needs it for secp256k1.</p>
    <p class="sanity-failure-advice">In Safari: tap the page-menu button in the address bar, tap More, turn off Lockdown Mode for this website, then reload. Or open the saved HTML in Firefox on a trusted air-gapped computer. Do not enter seed material until every check passes.</p>`
    : `<p class="sanity-failure-advice">Open this file in a current, mainstream browser such as Firefox on a trusted, air-gapped computer.</p>`;
  document.body.innerHTML = `
<main class="sanity-failure">
  <div class="sanity-failure-card" role="alert">
    <svg class="sanity-failure-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9.5"></circle><path d="M8.5 8.5l7 7M15.5 8.5l-7 7"></path></svg>
    <h1 class="sanity-failure-title">Host failed basic sanity checks</h1>
    <p class="sanity-failure-message">This page should not be used until checks passed.</p>
    <table class="sanity-failure-table">
      <thead><tr><th>Startup sanity check</th><th>Result</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${advice}
  </div>
</main>`;
})();

// Beta disclaimer: a modal gate the user must explicitly accept. The markup
// ships in the static template outside #btc-calc so application boot (which
// replaces that node's contents) cannot wipe it, and it starts hidden so a
// host without JavaScript never sees an overlay it cannot dismiss — this
// script is what reveals it (fade in), and acceptance fades it back out and
// removes it from the document. Acceptance is remembered in localStorage,
// the same site-settings store as the theme, keyed to this build's version:
// every new release asks again. When storage is unavailable (file://
// origins, private modes) the disclaimer simply shows on every load, which
// is the safe direction for a wallet tool. When the sanity barrage above
// has killed the page, the overlay is gone with it and this unit no-ops.
(() => {
  const overlay = document.getElementById("beta-disclaimer");
  const accept = document.getElementById("beta-disclaimer-accept");
  if (!overlay || !accept) return;
  const KEY = "entropylab-beta-accepted";
  const VERSION = "{{VERSION}}";
  let accepted = false;
  try {
    accepted = localStorage.getItem(KEY) === VERSION;
  } catch (e) {}
  if (accepted) {
    overlay.remove();
    return;
  }
  overlay.hidden = false;
  // Two frames: let the overlay paint once at opacity 0 so the is-visible
  // class below actually runs the fade-in transition.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    overlay.classList.add("is-visible");
    accept.focus();
  }));
  accept.addEventListener("click", () => {
    try {
      localStorage.setItem(KEY, VERSION);
    } catch (e) {}
    overlay.classList.add("is-dismissed");
    setTimeout(() => overlay.remove(), 400);
  });
})();
