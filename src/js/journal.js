// Offline session journal: notepad, session snapshot, debug log — plus the
// encrypted entropy notebook further below. In-memory only. No network, no
// browser storage, no CSPRNG.
import { hex as hexCoder } from "./coders.js";

export const JOURNAL_LOG_LIMIT = 400;
export const NOTEBOOK_FORMAT = "entropylab-notebook";
export const NOTEBOOK_VERSION = 1;
export const NOTEBOOK_MAX_PAGES = 100;
export const NOTEBOOK_MAX_TEXT_LENGTH = 1024 * 1024;

const JOURNAL_FONTS = new Set(["mono", "sans", "serif"]);
const JOURNAL_SIZES = new Set(["small", "medium", "large"]);
const JOURNAL_SPACINGS = new Set(["compact", "comfortable", "spacious"]);
const KEY_REFERENCE_END = "\u2063";
const KEY_REFERENCE_PATTERN = /(◆◆|◈◈) (?:([^\n◆\u2063]*?) )?\[([0-9a-fA-F]{8})\](?:\u2063| ◆)/g;
const BIP85_REFERENCE_LABELS = Object.freeze({
  bip39: "BIP-39",
  wif: "WIF",
  xprv: "XPRV",
  hex: "HEX",
  "pwd-base64": "Base64 password",
  "pwd-base85": "Base85 password",
});

function pad2(n) {
  return String(n).padStart(2, "0");
}

export function formatStamp(date = new Date()) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return "";
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

export function defaultJournalPageStyle() {
  return { font: "mono", size: "medium", spacing: "comfortable" };
}

export function normalizeJournalPageStyle(style) {
  return {
    font: JOURNAL_FONTS.has(style?.font) ? style.font : "mono",
    size: JOURNAL_SIZES.has(style?.size) ? style.size : "medium",
    spacing: JOURNAL_SPACINGS.has(style?.spacing) ? style.spacing : "comfortable",
  };
}

export function journalKeyReferenceToken(name, fingerprint) {
  let cleanName = String(name || "Key").replace(/[\r\n]+/g, " ").replace(/◆/g, "◇").replaceAll(KEY_REFERENCE_END, "").replace(/\s+/g, " ").trim().slice(0, 120) || "Key";
  let cleanFingerprint = String(fingerprint || "").trim().toLowerCase();
  if (!/^[0-9a-f]{8}$/.test(cleanFingerprint)) throw new Error("A key reference needs an 8-character hexadecimal fingerprint.");
  if (cleanName.toLowerCase() === cleanFingerprint) return `◆◆ [${cleanFingerprint}]${KEY_REFERENCE_END}`;
  return `◆◆ ${cleanName} [${cleanFingerprint}]${KEY_REFERENCE_END}`;
}

export function journalBip85ReferenceToken(application, fingerprint) {
  let app = String(application || ""), label = BIP85_REFERENCE_LABELS[app];
  let cleanFingerprint = String(fingerprint || "").trim().toLowerCase();
  if (!label) throw new Error("A BIP-85 reference needs a supported application.");
  if (!/^[0-9a-f]{8}$/.test(cleanFingerprint)) throw new Error("A key reference needs an 8-character hexadecimal fingerprint.");
  return `◈◈ BIP-85 · ${label} [${cleanFingerprint}]${KEY_REFERENCE_END}`;
}

function bip85ReferenceApplication(name) {
  let label = String(name || "").match(/^BIP-85 · (.+)$/)?.[1];
  return Object.keys(BIP85_REFERENCE_LABELS).find((app) => BIP85_REFERENCE_LABELS[app] === label) || "";
}

function referenceFromMatch(match) {
  let fingerprint = match[3].toLowerCase();
  if (match[1] === "◆◆") return { type: "key", name: match[2] || fingerprint, fingerprint };
  let application = bip85ReferenceApplication(match[2]);
  if (!application) return null;
  return { type: "key", name: match[2], fingerprint, source: "bip85", application };
}

export function journalNotebookRuns(text) {
  let source = String(text ?? ""), runs = [], cursor = 0;
  for (let match of source.matchAll(KEY_REFERENCE_PATTERN)) {
    let reference = referenceFromMatch(match);
    if (!reference) continue;
    if (match.index > cursor) runs.push({ type: "text", text: source.slice(cursor, match.index) });
    runs.push(reference);
    cursor = match.index + match[0].length;
  }
  if (cursor < source.length || !runs.length) runs.push({ type: "text", text: source.slice(cursor) });
  return runs;
}

export function journalKeyReferenceRanges(text) {
  return [...String(text ?? "").matchAll(KEY_REFERENCE_PATTERN)].filter(referenceFromMatch).map((match) => ({
    start: match.index,
    end: match.index + match[0].length,
  }));
}

export function journalTextFromRuns(runs) {
  if (!Array.isArray(runs)) throw new Error("A notebook page must contain a content list.");
  let text = "";
  for (let run of runs) {
    if (run?.type === "text" && typeof run.text === "string") text += run.text;
    else if (run?.type === "key" && run.source === "bip85") text += journalBip85ReferenceToken(run.application, run.fingerprint);
    else if (run?.type === "key") text += journalKeyReferenceToken(run.name, run.fingerprint);
    else throw new Error("The notebook contains an unsupported content item.");
    if (text.length > NOTEBOOK_MAX_TEXT_LENGTH) throw new Error("A notebook page is too large to import.");
  }
  return text;
}

export function createJournal() {
  return {
    notesText: "",
    pages: [{ id: 1, number: 1, name: "Page 1", notesText: "", style: defaultJournalPageStyle() }],
    activePage: 0,
    nextPageId: 2,
    nextPageNumber: 2,
    log: [],
    stateText: "",
  };
}

export function formatNotebook(text) {
  let cleaned = String(text ?? "").replace(KEY_REFERENCE_PATTERN, (match, marker, name, fingerprint) => {
    let cleanFingerprint = fingerprint.toLowerCase();
    if (marker === "◈◈") {
      let application = bip85ReferenceApplication(name);
      return application ? `[BIP-85 ${BIP85_REFERENCE_LABELS[application]}: ${cleanFingerprint}]` : match;
    }
    return !name || name.trim().toLowerCase() === cleanFingerprint
      ? `[Key: ${cleanFingerprint}]`
      : `[Key: ${name} · ${cleanFingerprint}]`;
  }).split("\n")
    .filter((line) => !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  (?:Add new note)?$/.test(line))
    .join("\n")
    .trimEnd();
  return cleaned || "No notes.";
}

export function serializeNotebook(journal) {
  let pages = journal?.pages?.length ? journal.pages : createJournal().pages;
  let document = {
    format: NOTEBOOK_FORMAT,
    version: NOTEBOOK_VERSION,
    activePage: Math.max(0, Math.min(Number(journal?.activePage) || 0, pages.length - 1)),
    pages: pages.map((page, index) => ({
      number: Number.isSafeInteger(page.number) && page.number > 0 ? page.number : index + 1,
      name: String(page.name || `Page ${index + 1}`).slice(0, 120),
      style: normalizeJournalPageStyle(page.style),
      content: journalNotebookRuns(page.notesText),
    })),
  };
  return JSON.stringify(document, null, 2) + "\n";
}

export function parseNotebook(text) {
  let document;
  try {
    document = JSON.parse(String(text ?? ""));
  } catch {
    throw new Error("This is not valid notebook JSON.");
  }
  if (!document || document.format !== NOTEBOOK_FORMAT || document.version !== NOTEBOOK_VERSION) {
    throw new Error("This file is not a supported EntropyLab notebook.");
  }
  if (!Array.isArray(document.pages) || !document.pages.length || document.pages.length > NOTEBOOK_MAX_PAGES) {
    throw new Error(`A notebook must contain between 1 and ${NOTEBOOK_MAX_PAGES} pages.`);
  }
  let usedNumbers = new Set(), pages = document.pages.map((page, index) => {
    let preferred = Number.isSafeInteger(page?.number) && page.number > 0 ? page.number : index + 1;
    while (usedNumbers.has(preferred)) preferred++;
    usedNumbers.add(preferred);
    let fallbackName = `Page ${preferred}`;
    let name = typeof page?.name === "string" ? page.name.trim().replace(/\s+/g, " ").slice(0, 120) : "";
    return {
      id: index + 1,
      number: preferred,
      name: name || fallbackName,
      notesText: journalTextFromRuns(page?.content),
      style: normalizeJournalPageStyle(page?.style),
    };
  });
  let activePage = Number.isSafeInteger(document.activePage) ? document.activePage : 0;
  activePage = Math.max(0, Math.min(activePage, pages.length - 1));
  return {
    notesText: pages[activePage].notesText,
    pages,
    activePage,
    nextPageId: pages.length + 1,
    nextPageNumber: pages.reduce((latest, page) => Math.max(latest, page.number), 0) + 1,
    log: [],
    stateText: "",
  };
}

export function journalFromPlainText(text) {
  let journal = createJournal(), value = String(text ?? "");
  if (value.length > NOTEBOOK_MAX_TEXT_LENGTH) throw new Error("The notes file is too large to import.");
  value = journalTextFromRuns(journalNotebookRuns(value));
  journal.notesText = value;
  journal.pages[0].notesText = value;
  return journal;
}

export function notebookPageHasContent(text) {
  return String(text ?? "").split("\n").some((line) => {
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}  (?:Add new note)?\s*$/.test(line)) return false;
    return line.trim().length > 0;
  });
}

export function mergeNotebookImport(journal, imported) {
  let currentPages = journal?.pages?.length ? journal.pages : createJournal().pages;
  let importedPages = imported?.pages;
  if (!importedPages?.length) throw new Error(`A notebook must contain between 1 and ${NOTEBOOK_MAX_PAGES} pages.`);
  let currentActive = Math.max(0, Math.min(Number(journal?.activePage) || 0, currentPages.length - 1));
  let replaceCurrent = !notebookPageHasContent(currentPages[currentActive]?.notesText);
  let insertion = replaceCurrent ? currentActive : currentActive + 1;
  if (currentPages.length - Number(replaceCurrent) + importedPages.length > NOTEBOOK_MAX_PAGES) {
    throw new Error(`A notebook must contain between 1 and ${NOTEBOOK_MAX_PAGES} pages.`);
  }
  let retained = currentPages.filter((_page, index) => !replaceCurrent || index !== currentActive);
  let usedNames = new Set(retained.map((page) => String(page.name || "").trim().replace(/\s+/g, " ").toLowerCase()).filter(Boolean));
  let maxId = currentPages.reduce((latest, page) => Number.isSafeInteger(page.id) && page.id > latest ? page.id : latest, 0);
  let maxNumber = currentPages.reduce((latest, page) => Number.isSafeInteger(page.number) && page.number > latest ? page.number : latest, 0);
  let nextId = Math.max(Number(journal?.nextPageId) || 1, maxId + 1);
  let nextNumber = Math.max(Number(journal?.nextPageNumber) || 1, maxNumber + 1);
  let mapped = importedPages.map((page, index) => {
    let id = replaceCurrent && index === 0 ? currentPages[currentActive].id : nextId++;
    let number = replaceCurrent && index === 0 ? currentPages[currentActive].number : nextNumber++;
    let importedDefault = String(page.name || "").trim() === `Page ${page.number}`;
    let rootName = (importedDefault ? `Page ${number}` : String(page.name || `Page ${number}`).trim().replace(/\s+/g, " ")).slice(0, 120) || `Page ${number}`;
    let name = rootName, suffix = 2;
    while (usedNames.has(name.toLowerCase())) {
      let ending = ` (${suffix++})`;
      name = rootName.slice(0, 120 - ending.length) + ending;
    }
    usedNames.add(name.toLowerCase());
    return { id, number, name, notesText: String(page.notesText || ""), style: normalizeJournalPageStyle(page.style) };
  });
  let pages = [...currentPages];
  pages.splice(insertion, replaceCurrent ? 1 : 0, ...mapped);
  let importedActive = Math.max(0, Math.min(Number(imported.activePage) || 0, mapped.length - 1));
  let activePage = insertion + importedActive;
  return {
    ...journal,
    pages,
    activePage,
    nextPageId: Math.max(nextId, pages.reduce((latest, page) => Math.max(latest, page.id || 0), 0) + 1),
    nextPageNumber: Math.max(nextNumber, pages.reduce((latest, page) => Math.max(latest, page.number || 0), 0) + 1),
    notesText: pages[activePage].notesText,
  };
}

export function formatNotebookPages(pages) {
  if (!pages?.length) return "No notes.";
  if (pages.length === 1) return formatNotebook(pages[0].notesText);
  return pages.map((page) => `${page.name || `Page ${page.number}`}\n${formatNotebook(page.notesText)}`).join("\n\n");
}

export function appendLog(journal, { at, tool, action, detail } = {}, now = new Date()) {
  journal.log.push({
    at: at || formatStamp(now),
    tool: String(tool || ""),
    action: String(action || ""),
    detail: String(detail || "").slice(0, 300),
  });
  while (journal.log.length > JOURNAL_LOG_LIMIT) journal.log.shift();
  return journal.log[journal.log.length - 1];
}

export function formatLog(events) {
  if (!events.length) return "No events yet.";
  return events.map((event) => {
    let detail = event.detail ? `  ${event.detail}` : "";
    return `${event.at}\t${event.tool}\t${event.action}${detail}`;
  }).join("\n");
}

export function snapshotSession(session) {
  let lines = [
    "ENTROPYLAB SESSION STATE",
    `Updated: ${session.capturedAt || ""}`,
    `Build: ${session.version || "unknown"}${session.commit ? ` · ${session.commit}` : ""}`,
    `Private material: ${session.includePrivate ? "INCLUDED" : "omitted"}`,
    "",
  ];
  lines.push("KEYS");
  if (!session.keys?.length) lines.push("(none)");
  else for (let key of session.keys) {
    if (!key.derived) {
      lines.push(`- ${key.name || "Key"} · not derived · method ${key.mode || "unknown"}`);
      continue;
    }
    lines.push(`- ${key.name || "Key"}${key.fingerprint ? ` · fingerprint ${key.fingerprint}` : ""}`);
    if (key.sheet) lines.push(key.sheet, "");
  }
  lines.push("", "MULTISIG");
  if (!session.msigs?.length) lines.push("(none)");
  else for (let msig of session.msigs) {
    if (!msig.derived) {
      lines.push(`- ${msig.name || "Multisig"} · not derived`);
      continue;
    }
    lines.push(`- ${msig.name || "Multisig"}${msig.summary ? ` · ${msig.summary}` : ""}`);
    if (msig.sheet) lines.push(msig.sheet, "");
  }
  lines.push("", "BIP-85");
  if (!session.bip85?.length) lines.push("(none)");
  else for (let child of session.bip85) {
    lines.push(`- ${child.name || "BIP-85"}${child.fingerprint ? ` · ${child.fingerprint}` : ""}${child.app ? ` · ${child.app}` : ""}${child.secret && session.includePrivate ? `\n  ${child.secret}` : ""}`);
  }
  lines.push("", "SILENT PAYMENTS");
  lines.push(session.sp?.derived ? `- fingerprint ${session.sp.fingerprint || "unknown"}${session.sp.address ? `\n  ${session.sp.address}` : ""}` : "- not derived");
  lines.push("", "PSBT");
  lines.push(session.psbt?.loaded ? "- payload present in the inspector" : "- inspector empty");
  lines.push("", "This snapshot lives in this page until you download it. Closing the tab discards it.");
  return lines.join("\n");
}

export function wipeJournal(journal) {
  journal.notesText = "";
  journal.pages = [{ id: 1, number: 1, name: "Page 1", notesText: "", style: defaultJournalPageStyle() }];
  journal.activePage = 0;
  journal.nextPageId = 2;
  journal.nextPageNumber = 2;
  journal.log.length = 0;
  journal.stateText = "";
  return journal;
}
//
// Encryption is a pure function of the user's password and the entries — the
// journal never calls a CSPRNG. The AES-256-GCM key is PBKDF2-SHA-256
// (600,000 rounds) of the password, with the salt derived from the password
// itself under a domain separator. The IV is HMAC-SHA-256 of the plaintext
// under a second derived key (a synthetic IV), so the same password and the
// same entries always produce the same file.
export const JOURNAL_VERSION = 2;
export const JOURNAL_EXPORT_VERSION = 1;
export const JOURNAL_KDF = "PBKDF2-SHA-256";
export const JOURNAL_CIPHER = "AES-256-GCM";
export const JOURNAL_ITERATIONS = 600_000; // OWASP 2023 floor for PBKDF2-HMAC-SHA-256
export const JOURNAL_MIN_ITERATIONS = 100_000; // never open a file cheaper than this
export const JOURNAL_MAX_ITERATIONS = 10_000_000; // a crafted file must not hang the page
export const JOURNAL_SALT_PREFIX = "entropylab-journal-salt-v1:";
export const IV_BYTES = 12;
export const PASSWORD_MIN_LENGTH = 12;
export const METHODS = Object.freeze(["dice", "coin", "hex", "brain", "seed", "cards"]);
const JOURNAL_EXPORT_KINDS = new Set(["notebook", "key-manager", "session-state", "session-log"]);
export const METHOD_LABELS = Object.freeze({
  dice: "Dice rolls",
  coin: "Coin flips",
  hex: "Hex",
  brain: "Brain-wallet text",
  seed: "Manual seed",
  cards: "Playing cards",
});

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function wipeBytes(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
  return bytes;
}

export function wipeEntry(entry) {
  if (!entry) return;
  entry.input = "";
  entry.phrase = "";
  entry.label = "";
  entry.notes = "";
  entry.walletName = "";
  entry.fingerprint = "";
}

export function wipeDocument(doc) {
  if (!doc) return;
  for (const entry of doc.entries || []) wipeEntry(entry);
  doc.entries = [];
  doc.nextId = 1;
}

export function assertPassword(password, { confirm } = {}) {
  if (typeof password !== "string" || !password) throw new Error("Journal password is missing.");
  if (Array.from(password).length < PASSWORD_MIN_LENGTH) throw new Error(`Journal password needs at least ${PASSWORD_MIN_LENGTH} characters.`);
  if (confirm != null && confirm !== password) throw new Error("The two passwords do not match.");
}

function requireSubtle() {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto is unavailable. Open this file in a current browser (a secure context).");
  }
  return crypto.subtle;
}

// The PBKDF2 salt is derived from the password itself (domain-separated), not
// generated: the journal file stays a pure function of what the user typed.
// Salts still differ between passwords, so no precomputed table can be shared
// from one password to the next.
async function deriveMasterBits(password, iterations) {
  const subtle = requireSubtle();
  const ikm = encoder.encode(password);
  const saltInput = encoder.encode(JOURNAL_SALT_PREFIX + password);
  let baseKey;
  try {
    const salt = new Uint8Array(await subtle.digest("SHA-256", saltInput));
    try {
      baseKey = await subtle.importKey("raw", ikm, "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, baseKey, 512));
    } finally {
      wipeBytes(salt);
    }
  } finally {
    wipeBytes(ikm);
    wipeBytes(saltInput);
  }
}

// One PBKDF2 run yields 512 bits: the first half keys AES-GCM, the second
// keys the HMAC that derives IVs. Both are imported non-extractable.
export async function deriveJournalKeys(password, iterations = JOURNAL_ITERATIONS) {
  if (typeof password !== "string" || !password) throw new Error("Journal password is missing.");
  if (!Number.isInteger(iterations) || iterations < JOURNAL_MIN_ITERATIONS || iterations > JOURNAL_MAX_ITERATIONS) {
    throw new Error("This journal file uses an unsupported key-derivation cost.");
  }
  const subtle = requireSubtle();
  const master = await deriveMasterBits(password, iterations);
  try {
    const encKey = await subtle.importKey("raw", master.subarray(0, 32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    const ivKey = await subtle.importKey("raw", master.subarray(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const verify = new Uint8Array(await subtle.digest("SHA-256", master));
    return { encKey, ivKey, verify, iterations };
  } finally {
    wipeBytes(master);
  }
}

export function emptyDocument() {
  return { version: JOURNAL_VERSION, nextId: 1, entries: [] };
}

export function normalizeEntry(entry, now = new Date()) {
  const method = String(entry?.method || "").trim();
  if (!METHODS.includes(method)) throw new Error("Journal method must be dice, coin, hex, brain, seed, or cards.");
  const label = String(entry?.label ?? "").trim();
  if (!label) throw new Error("Every journal entry needs a label.");
  const created = entry?.created ? String(entry.created) : now.toISOString();
  if (!/^\d{4}-\d{2}-\d{2}T/.test(created)) throw new Error("Journal timestamp must be ISO-8601.");
  const walletId = entry?.walletId == null || entry.walletId === "" ? null : Number(entry.walletId);
  if (walletId != null && (!Number.isInteger(walletId) || walletId < 0)) throw new Error("Session wallet id must be a whole number.");
  return {
    id: Number.isInteger(entry?.id) && entry.id > 0 ? entry.id : 0,
    method,
    input: String(entry?.input ?? ""),
    phrase: String(entry?.phrase ?? ""),
    label,
    notes: String(entry?.notes ?? ""),
    created,
    walletId,
    walletName: String(entry?.walletName ?? ""),
    fingerprint: String(entry?.fingerprint ?? "").toLowerCase(),
  };
}

export function addEntry(doc, fields, now = new Date()) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const entry = normalizeEntry({ ...fields, id: doc.nextId || 1 }, now);
  doc.entries = [...doc.entries, entry];
  doc.nextId = entry.id + 1;
  return entry;
}

export function replaceEntry(doc, id, fields) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const index = doc.entries.findIndex((entry) => entry.id === id);
  if (index < 0) throw new Error("That journal entry is not in this file.");
  const previous = doc.entries[index];
  const entry = normalizeEntry({ ...previous, ...fields, id: previous.id, created: previous.created });
  const next = doc.entries.slice();
  wipeEntry(previous);
  next[index] = entry;
  doc.entries = next;
  return entry;
}

export function removeEntry(doc, id) {
  if (!doc || !Array.isArray(doc.entries)) throw new Error("Journal document is missing.");
  const index = doc.entries.findIndex((entry) => entry.id === id);
  if (index < 0) throw new Error("That journal entry is not in this file.");
  const next = doc.entries.slice();
  wipeEntry(next[index]);
  next.splice(index, 1);
  doc.entries = next;
}

export function searchEntries(doc, query) {
  const entries = doc?.entries || [];
  const needle = String(query ?? "").trim().toLowerCase();
  if (!needle) return entries.slice();
  return entries.filter((entry) => String(entry.label || "").toLowerCase().includes(needle));
}

export function snapshotFromKeyState(state) {
  if (!state || state.isLab) return null;
  const fields = state.fields || {};
  const mode = state.mode || "";
  let method = "seed";
  let input = "";
  if (mode === "dice") {
    method = "dice";
    input = state.diceMethod === "dplus" ? fields.dplusDice || "" : state.diceMethod === "bitbox" ? fields.bitboxDice || "" : fields.dice || "";
  } else if (mode === "cards") {
    method = "cards";
    input = state.cardMethod === "direct" ? fields.directCards || "" : fields.cards || "";
  } else if (mode === "hex") {
    method = "hex";
    const format = state.entropyFormat || "hex";
    input = fields[format] || fields.hex || "";
  } else if (mode === "seed") {
    method = "seed";
    input = state.seedMethod === "numbers" ? fields.seedNumbers || "" : fields.seed || "";
  } else if (mode === "key") {
    const kind = fields.keyKind || "";
    if (kind === "brain") {
      method = "brain";
      input = (fields.privateKeys && fields.privateKeys.brain) || fields.key || fields.brainLab || "";
    } else {
      method = "seed";
      input = (fields.privateKeys && (fields.privateKeys[kind] || fields.privateKeys.wif)) || fields.key || "";
    }
  }
  const phrase = state.result?.mnemonic || "";
  if (!String(input).trim() && !String(phrase).trim()) return null;
  return {
    method,
    input: String(input),
    phrase: String(phrase),
    label: String(state.name || state.result?.masterFingerprint || "").trim(),
    notes: fields.pass ? "BIP-39 passphrase was in effect on the linked key. The passphrase itself is not stored here unless you paste it." : "",
    walletId: state.id,
    walletName: String(state.name || ""),
    fingerprint: String(state.result?.masterFingerprint || "").toLowerCase(),
  };
}

export function encodeFile({ iv, ciphertext, iterations = JOURNAL_ITERATIONS }) {
  if (!(iv instanceof Uint8Array) || iv.length !== IV_BYTES) throw new Error("Journal IV must be 12 bytes.");
  if (!(ciphertext instanceof Uint8Array) || !ciphertext.length) throw new Error("Journal ciphertext is missing.");
  if (!Number.isInteger(iterations) || iterations < JOURNAL_MIN_ITERATIONS || iterations > JOURNAL_MAX_ITERATIONS) throw new Error("Journal iteration count is out of range.");
  return {
    entropylabJournal: JOURNAL_VERSION,
    kdf: JOURNAL_KDF,
    iterations,
    cipher: JOURNAL_CIPHER,
    iv: hexCoder.encode(iv),
    ciphertext: hexCoder.encode(ciphertext),
  };
}

export function parseFile(text) {
  let parsed;
  try {
    parsed = typeof text === "string" ? JSON.parse(text) : text;
  } catch {
    throw new Error("That file is not valid JSON.");
  }
  if (!parsed || parsed.entropylabJournal !== JOURNAL_VERSION) throw new Error("That file is not an EntropyLab journal.");
  if (parsed.kdf !== JOURNAL_KDF || parsed.cipher !== JOURNAL_CIPHER) throw new Error("This journal uses an unsupported cipher.");
  if (!Number.isInteger(parsed.iterations) || parsed.iterations < JOURNAL_MIN_ITERATIONS || parsed.iterations > JOURNAL_MAX_ITERATIONS) {
    throw new Error("This journal uses an unsupported key-derivation cost.");
  }
  let iv, ciphertext;
  try {
    iv = hexCoder.decode(String(parsed.iv || ""));
    ciphertext = hexCoder.decode(String(parsed.ciphertext || ""));
  } catch {
    throw new Error("That journal file is missing its IV or ciphertext.");
  }
  if (iv.length !== IV_BYTES || !ciphertext.length) {
    throw new Error("That journal file is missing its IV or ciphertext.");
  }
  return { iv, ciphertext, iterations: parsed.iterations };
}

function parseDocument(plain) {
  let parsed;
  try {
    parsed = JSON.parse(plain);
  } catch {
    throw new Error("The journal file is corrupt.");
  }
  if (!parsed || parsed.version !== JOURNAL_VERSION || !Array.isArray(parsed.entries)) {
    throw new Error("The journal file is corrupt.");
  }
  const nextId = Number.isInteger(parsed.nextId) && parsed.nextId > 0 ? parsed.nextId : 1;
  const entries = parsed.entries.map((entry) => normalizeEntry(entry));
  return { version: JOURNAL_VERSION, nextId, entries };
}

// The IV is a synthetic nonce — HMAC-SHA-256 of the plaintext under its own
// derived key. The same password and entries produce the same file; two
// different plaintexts share an IV only on an HMAC collision. No randomness
// is generated, matching the rest of EntropyLab.
async function sealPlainText(plainText, keys) {
  if (!keys?.encKey || !keys?.ivKey) throw new Error("Unlock the journal before saving.");
  const subtle = requireSubtle();
  const plain = encoder.encode(plainText);
  try {
    const tag = new Uint8Array(await subtle.sign("HMAC", keys.ivKey, plain));
    try {
      const iv = tag.slice(0, IV_BYTES);
      const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, keys.encKey, plain));
      return encodeFile({ iv, ciphertext, iterations: keys.iterations });
    } finally {
      wipeBytes(tag);
    }
  } finally {
    wipeBytes(plain);
  }
}

export async function sealDocument(doc, keys) {
  return sealPlainText(JSON.stringify({
    version: JOURNAL_VERSION,
    nextId: doc.nextId,
    entries: doc.entries,
  }), keys);
}

export async function sealExport(kind, content, keys) {
  if (!JOURNAL_EXPORT_KINDS.has(kind)) throw new Error("That Journal export type is not supported.");
  const file = await sealPlainText(JSON.stringify({
    entropylabJournalExport: JOURNAL_EXPORT_VERSION,
    kind,
    content: String(content ?? ""),
  }), keys);
  return { ...file, entropylabJournalExport: JOURNAL_EXPORT_VERSION };
}

export async function openExport(file, keys) {
  let outer;
  try {
    outer = typeof file === "string" ? JSON.parse(file) : file;
  } catch {
    throw new Error("That encrypted export is not valid JSON.");
  }
  if (!outer || outer.entropylabJournalExport !== JOURNAL_EXPORT_VERSION) throw new Error("That file is not an encrypted Journal export.");
  if (!keys?.encKey || !keys?.ivKey) throw new Error("Open or create the journal before importing an encrypted export.");
  const parsed = parseFile(outer);
  if (parsed.iterations !== keys.iterations) throw new Error("That encrypted export uses a different journal password.");
  const subtle = requireSubtle();
  let plainBytes;
  try {
    plainBytes = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, keys.encKey, parsed.ciphertext));
  } catch {
    throw new Error("That encrypted export uses a different journal password, or the file is damaged.");
  }
  try {
    let payload;
    try {
      payload = JSON.parse(decoder.decode(plainBytes));
    } catch {
      throw new Error("The encrypted Journal export is corrupt.");
    }
    if (!payload || payload.entropylabJournalExport !== JOURNAL_EXPORT_VERSION || !JOURNAL_EXPORT_KINDS.has(payload.kind) || typeof payload.content !== "string") {
      throw new Error("The encrypted Journal export is corrupt.");
    }
    return { kind: payload.kind, content: payload.content };
  } finally {
    wipeBytes(plainBytes);
    wipeBytes(parsed.iv);
    wipeBytes(parsed.ciphertext);
  }
}

export async function openDocument(file, password) {
  const parsed = parseFile(file);
  const keys = await deriveJournalKeys(password, parsed.iterations);
  const subtle = requireSubtle();
  let plainBytes;
  try {
    plainBytes = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: parsed.iv }, keys.encKey, parsed.ciphertext));
  } catch {
    throw new Error("Wrong password, or the file is damaged.");
  }
  try {
    return { keys, doc: parseDocument(decoder.decode(plainBytes)) };
  } finally {
    wipeBytes(plainBytes);
    wipeBytes(parsed.iv);
    wipeBytes(parsed.ciphertext);
  }
}

export async function createDocument(password, confirm) {
  assertPassword(password, { confirm });
  return { keys: await deriveJournalKeys(password), doc: emptyDocument() };
}
