// Core Wallet tab UI: upload a Bitcoin Core descriptor-wallet wallet.dat,
// see every record decoded, watch the verifier re-check the file's claims,
// and append further descriptors (watch-only or, into a wallet that already
// signs, private) before downloading the rebuilt database.
//
// All parsing, verification and byte-building lives in the pure
// hodlCoreWallet global (src/js/core-wallet.js); this module only renders
// the document and wires the controls, the same split the PSBT editor keeps
// between psbt-wasm.js and psbt-editor.js.
import { t, tHtml } from "./i18n.js";
import { expandableHtml, initExpandable } from "./expandable.js";

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// wallet.dat files of used wallets carry their transaction history; the cap
// keeps a hostile or accidental multi-gigabyte file from stalling the tab.
export const CORE_WALLET_MAX_BYTES = 64 * 1024 * 1024;
const OTHER_RECORD_RENDER_LIMIT = 200;

const OUTPUT_TYPE_NAMES = [
  () => t("Legacy (P2PKH)"),
  () => t("Nested SegWit (P2SH-P2WPKH)"),
  () => t("Native SegWit (P2WPKH)"),
  () => t("Taproot (P2TR)"),
];
const outputTypeName = (type) => (OUTPUT_TYPE_NAMES[type] ?? (() => t("unknown type {n}", { n: type })))();

const TONE_MARK = { ok: "✓", warn: "!", bad: "✗" };

export const initCoreWallet = ({ deps } = {}) => {
  const upload = document.getElementById("core-upload");
  if (!upload) return;
  const $ = (id) => document.getElementById(id);
  const file = $("core-file"), download = $("core-download"), wipe = $("core-wipe");
  const error = $("core-error"), out = $("core-out"), reveal = $("core-reveal");
  const addSection = $("core-add"), addText = $("core-add-text"), addInternal = $("core-add-internal");
  const addActive = $("core-add-active"), addGo = $("core-add-go");

  let doc = null; // parsed wallet document; null when nothing is loaded
  let fileName = "wallet.dat";
  let added = 0; // descriptors appended since upload

  initExpandable();

  const setError = (message) => {
    error.textContent = message || "";
  };

  const checkListHtml = (checks) =>
    `<ul>${checks
      .map(
        (item) =>
          `<li><span class="psbted-note-${item.tone}">${TONE_MARK[item.tone] ?? "?"}</span> <strong>${escapeHtml(item.label)}</strong> — ${escapeHtml(item.detail)}</li>`,
      )
      .join("")}</ul>`;

  const walletRowsHtml = () => {
    const rows = [];
    const push = (field, valueHtml) => rows.push(`<tr><td>${field}</td><td>${valueHtml}</td></tr>`);
    push(tHtml("Network"), doc.network ? escapeHtml(doc.network) : `<span class="psbted-note-bad">${tHtml("unknown application_id 0x{id}", { id: doc.applicationId.toString(16).padStart(8, "0") })}</span>`);
    push(tHtml("SQLite page size"), tHtml("{count} bytes", { count: doc.pageSize }));
    if (doc.meta.version !== undefined) push(tHtml("Client version"), escapeHtml(String(doc.meta.version)));
    if (doc.meta.minversion !== undefined) push(tHtml("Minimum client version"), escapeHtml(String(doc.meta.minversion)));
    if (doc.meta.flags !== undefined) push(tHtml("Wallet flags"), escapeHtml(hodlCoreWallet.flagNames(doc.meta.flags).join(", ") || t("none")));
    for (const [label, locator] of [[t("Best block"), doc.meta.bestBlock], [t("Best block (no merkle)"), doc.meta.bestBlockNoMerkle]]) {
      if (!locator) continue;
      const summary = locator.hashes.length
        ? t("{count} hash(es), tip {hash}", { count: locator.hashes.length, hash: locator.hashes[0] })
        : t("empty locator");
      push(escapeHtml(label), expandableHtml(locator.hashes.join(" "), { label: `${label} hashes` }) + `<br><span class="muted">${escapeHtml(summary)}</span>`);
    }
    push(tHtml("Records in main table"), escapeHtml(String(doc.rows.length)));
    return `<table class="psbted-pairs psbted-kv"><thead><tr><th class="psbted-col-field">${tHtml("Field")}</th><th>${tHtml("Value")}</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
  };

  const descriptorHtml = (entry, index) => {
    const functions = entry.functions.join(" → ") || t("unknown");
    const branch = entry.active?.internal ? t("change") : t("external");
    const rows = [];
    const push = (field, valueHtml) => rows.push(`<tr><td>${field}</td><td>${valueHtml}</td></tr>`);
    push(tHtml("Descriptor"), expandableHtml(entry.descriptor, { label: t("Descriptor {n}", { n: index + 1 }) }));
    push(tHtml("Descriptor ID"), expandableHtml(entry.id, { label: t("Descriptor {n} id", { n: index + 1 }) }));
    push(tHtml("Created"), entry.creationTime ? escapeHtml(new Date(entry.creationTime * 1000).toISOString()) : tHtml("0 (epoch — a fresh wallet)"));
    push(tHtml("Next index"), escapeHtml(String(entry.nextIndex)));
    push(tHtml("Range"), escapeHtml(`${entry.rangeStart} … ${entry.rangeEnd}`));
    push(
      tHtml("Active scriptPubKey"),
      entry.active
        ? tHtml("{branch}, {type}", { branch, type: outputTypeName(entry.active.type) })
        : `<span class="muted">${tHtml("not the active descriptor for its type")}</span>`,
    );
    for (const cache of entry.caches) {
      push(
        tHtml("Cache parent (provider {n})", { n: cache.keyExpIndex }),
        expandableHtml(bytesToHex(cache.body), { label: t("Descriptor {n} cache parent", { n: index + 1 }) }),
      );
    }
    entry.keys.forEach((keyRecord, keyIndex) => {
      push(tHtml("Private key {n}", { n: keyIndex + 1 }), reveal.checked
        ? expandableHtml(bytesToHex(keyRecord.der), { label: t("Descriptor {n} private key (DER)", { n: index + 1 }) })
        : `<span class="muted">${tHtml("present — {bytes} bytes, redacted", { bytes: keyRecord.der.length })}</span>`);
      push(tHtml("Private key {n} pubkey", { n: keyIndex + 1 }), expandableHtml(bytesToHex(keyRecord.pubkey), { label: t("Descriptor {n} key pubkey", { n: index + 1 }) }));
    });
    return `<section class="psbted-map"><h3>${tHtml("Descriptor {n}", { n: index + 1 })}: ${escapeHtml(functions)} · ${escapeHtml(branch)}</h3>
      <table class="psbted-pairs psbted-kv"><tbody>${rows.join("")}</tbody></table></section>`;
  };

  const otherRecordsHtml = () => {
    if (!doc.others.length) return "";
    const shown = doc.others.slice(0, OTHER_RECORD_RENDER_LIMIT);
    const rows = shown
      .map((record) => {
        const note = record.error ? `<span class="psbted-note-bad">${escapeHtml(record.error)}</span>` : "";
        return `<tr>
          <td class="psbted-name">${escapeHtml(record.name ?? t("(unnamed)"))}${note ? `<br>${note}` : ""}</td>
          <td class="psbted-hex">${expandableHtml(bytesToHex(record.key), { label: t("Record key (hex)") })}</td>
          <td class="psbted-hex">${expandableHtml(bytesToHex(record.value), { label: t("Record value (hex)") })}</td>
        </tr>`;
      })
      .join("");
    const more = doc.others.length > shown.length
      ? `<p class="muted">${tHtml("…and {count} more record(s) not listed.", { count: doc.others.length - shown.length })}</p>`
      : "";
    return `<section class="psbted-map"><h3>${tHtml("Other records")}</h3>
      <p class="muted">${tHtml("Records this tool does not decode (transactions, address book, script caches). They are preserved byte-for-byte in the download.")}</p>
      <table class="psbted-pairs"><thead><tr><th>${tHtml("Record")}</th><th>${tHtml("Key (hex)")}</th><th>${tHtml("Value (hex)")}</th></tr></thead><tbody>${rows}</tbody></table>${more}</section>`;
  };

  const render = () => {
    if (!doc) {
      out.innerHTML = "";
      addSection.hidden = true;
      download.disabled = true;
      return;
    }
    let checks = [];
    try {
      checks = hodlCoreWallet.verifyWalletDoc(doc, deps);
    } catch (exception) {
      checks = [{ tone: "bad", label: t("Verification"), detail: exception.message || String(exception) }];
    }
    const bad = checks.filter((item) => item.tone === "bad").length;
    const warned = checks.filter((item) => item.tone === "warn").length;
    const verdict = bad
      ? `<span class="psbted-note-bad">${tHtml("{count} check(s) failed", { count: bad })}</span>`
      : warned
        ? `<span class="psbted-note-warn">${tHtml("all checks passed with {count} warning(s)", { count: warned })}</span>`
        : `<span class="psbted-note-ok">${tHtml("all checks passed")}</span>`;
    const privateKeys = doc.descriptors.reduce((count, entry) => count + entry.keys.length, 0);
    const summary = [
      `<strong>${escapeHtml(doc.network ?? t("unknown network"))}</strong>`,
      t("{count} descriptor(s)", { count: doc.descriptors.length }),
      privateKeys ? t("signing ({count} private key record(s))", { count: privateKeys }) : t("watch-only"),
      t("{count} record(s)", { count: doc.rows.length }),
    ].join(" · ");

    out.innerHTML = `
      <p class="psbt-kv">${summary} · ${verdict}${added ? ` · ${tHtml("{count} descriptor(s) added this session", { count: added })}` : ""}</p>
      <section class="psbted-map"><h3>${tHtml("Verification")}</h3>${checkListHtml(checks)}</section>
      <section class="psbted-map"><h3>${tHtml("Wallet")}</h3>${walletRowsHtml()}</section>
      ${doc.descriptors.map((entry, index) => descriptorHtml(entry, index)).join("")}
      ${otherRecordsHtml()}`;
    addSection.hidden = false;
    download.disabled = false;
  };

  const loadBytes = (bytes, name) => {
    if (bytes.length > CORE_WALLET_MAX_BYTES) throw new Error(t("This wallet file is too large to inspect safely."));
    doc = hodlCoreWallet.parseWalletDat(bytes);
    fileName = name || "wallet.dat";
    added = 0;
  };

  upload.onclick = () => file.click();
  file.addEventListener("change", () => {
    const chosen = file.files?.[0];
    file.value = "";
    if (!chosen) return;
    (async () => {
      try {
        setError(null);
        loadBytes(new Uint8Array(await chosen.arrayBuffer()), chosen.name);
        render();
      } catch (exception) {
        doc = null;
        render();
        setError(exception.message || String(exception));
      }
    })();
  });

  addGo.onclick = () => {
    setError(null);
    if (!doc) return;
    try {
      const unit = hodlCoreWallet.unitFromDescriptor(
        addText.value,
        { internal: addInternal.checked, active: addActive.checked },
        deps,
      );
      const rows = hodlCoreWallet.appendDescriptorRows(doc, unit, deps, Math.floor(Date.now() / 1000));
      // Rebuild and re-read the file, so what renders next is exactly what
      // the download contains — a failed round-trip surfaces here, not in Core.
      doc = hodlCoreWallet.parseWalletDat(hodlCoreWallet.buildWalletDat(doc, rows));
      added++;
      addText.value = "";
      render();
    } catch (exception) {
      setError(exception.message || String(exception));
    }
  };

  download.onclick = () => {
    setError(null);
    if (!doc) return;
    try {
      const bytes = hodlCoreWallet.buildWalletDat(doc);
      const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = fileName;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1e3);
    } catch (exception) {
      setError(exception.message || String(exception));
    }
  };

  wipe.onclick = () => {
    doc = null;
    added = 0;
    addText.value = "";
    reveal.checked = false;
    setError(null);
    render();
  };

  reveal.addEventListener("change", () => render());
};
