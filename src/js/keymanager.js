// Portable Key Manager payloads. Encryption is supplied by the unlocked
// Entropy Journal so this module never generates salts, nonces, or key data.
export const KEY_VAULT_FORMAT = "entropylab-key-manager";
export const KEY_VAULT_VERSION = 2;
export const KEY_VAULT_MAX_KEYS = 100;
const KEY_NETWORKS = ["mainnet", "testnet", "signet", "regtest"];
const KEY_SCRIPT_IDS = ["bip44", "bip49", "bip84", "bip86"];
const KEY_SCRIPTS = ["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"];

// Compare only after the caller establishes the same wallet from a fresh
// derivation. This is its public setup and available recovery capabilities,
// never an identity proof and never a serialization of its private material.
export function keyResultSetup(result, selectedScript) {
  const index = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 2147483647;
  const text = (value) => typeof value === "string" && value.length > 0;
  const bytes = (value) => ArrayBuffer.isView(value) && value.byteLength > 0;
  if (!result || !["hd", "single"].includes(result.kind) || !KEY_NETWORKS.includes(result.network) || !KEY_SCRIPT_IDS.includes(selectedScript)) return null;
  for (const field of ["entropy", "seed", "privateKey", "minikey"]) if (result[field] != null && !ArrayBuffer.isView(result[field])) return null;
  if (result.brainWalletOutput != null && !["hd", "scalar"].includes(result.brainWalletOutput)) return null;
  const capabilities = {
    mnemonic: bytes(result.entropy), seed: bytes(result.seed), rootPrivate: Boolean(result.rootNode),
    singlePrivate: bytes(result.privateKey), minikey: bytes(result.minikey),
  };
  const setup = { kind: result.kind, network: result.network, selectedScript };
  if (result.kind === "single") {
    if (!bytes(result.privateKey) || result.privateKey.byteLength !== 32 || ![true, false, null].includes(result.compressed)) return null;
    return { ...setup, compressed: result.compressed, brainWalletOutput: result.brainWalletOutput ?? null, capabilities };
  }
  if (!(result.imported === true && result.coinType == null) && !index(result.coinType)) return null;
  if (result.purposeMatch !== undefined && typeof result.purposeMatch !== "boolean") return null;
  const purpose = result.originalPurpose;
  if (result.purposeMatch && !purpose || purpose != null && (!index(purpose.index) || typeof purpose.hardened !== "boolean")) return null;
  if (!Array.isArray(result.accounts) || !result.accounts.length) return null;
  const accounts = [];
  for (const account of result.accounts) {
    if (!account || !KEY_SCRIPTS.includes(account.def?.script) || account.network !== result.network || !text(account.accountPath)
      || typeof account.branchHardened !== "boolean" || typeof account.addressHardened !== "boolean"
      || account.importedFamily != null && !["x", "y", "z"].includes(account.importedFamily)
      || !index(account.branchStart) || !Number.isSafeInteger(account.branchRange) || account.branchRange < 1
      || !Array.isArray(account.addressBranches) || account.addressBranches.length !== account.branchRange) return null;
    const branches = [];
    for (const [offset, branch] of account.addressBranches.entries()) {
      if (!branch || !index(branch.branch) || branch.branch !== account.branchStart + offset || !Array.isArray(branch.rows) || !branch.rows.length) return null;
      const rows = [];
      for (const [position, row] of branch.rows.entries()) {
        if (!row || !index(row.index) || !text(row.path) || position && row.index !== rows[position - 1].index + 1) return null;
        rows.push({ index: row.index, path: row.path });
      }
      branches.push({ branch: branch.branch, rows });
    }
    accounts.push({
      script: account.def.script, accountPath: account.accountPath, importedFamily: account.importedFamily ?? null,
      branchHardened: account.branchHardened, addressHardened: account.addressHardened,
      privateAvailable: Boolean(account.privateNode), branches,
    });
  }
  return {
    ...setup, coinType: result.coinType ?? null, purposeMatch: result.purposeMatch === true,
    originalPurpose: purpose ? { index: purpose.index, hardened: purpose.hardened } : null,
    brainWalletOutput: result.brainWalletOutput ?? null, capabilities, accounts,
  };
}

export function keyVaultIdentity(state) {
  // This identifies a Journal entry, not its wallet: two entries can derive
  // the same root with different networks or paths and both must survive a
  // backup. IDs are assigned by the app; vaultEntry strips file-supplied IDs.
  if (Number.isSafeInteger(state?.id) && state.id > 0) return String(state.id);
  // Legacy states without an app ID retain their complete wallet identity
  // before any four-byte fingerprint, which different wallets can share.
  return String(state?.result?.masterIdentity || state?.result?.rootXpub || state?.result?.xpub || state?.result?.masterFingerprint || "");
}

// The key methods this build offers. app.js sets them once at load, and a
// release build leaves out the preview-only ones. A key file or journal
// backup naming any other method is refused at import, so it cannot bring a
// hidden method back. Unset (the Node tests), every method passes.
let vaultModes = null;
export function setKeyVaultModes(modes) {
  vaultModes = Array.isArray(modes) ? modes.slice() : null;
}

function vaultEntry(entry, exporting = false) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry) || entry.isLab || !entry.fields || typeof entry.fields !== "object" || Array.isArray(entry.fields)) {
    throw new Error("The key file contains an invalid key.");
  }
  // A portable passphrase is exact text. Coercing an object or number on
  // restore would silently derive a different, otherwise valid wallet.
  if (Object.hasOwn(entry.fields, "pass") && typeof entry.fields.pass !== "string") throw new Error("A key input's passphrase must be text.");
  // Only source inputs/settings cross the import boundary. Encryption proves
  // file integrity, not that cached addresses or private outputs were derived
  // from these inputs. Never accept a serialized "verified" flag or identity.
  let copy = {};
  for (const field of [
    "name", "createdAt", "mode", "diceMethod", "cardMethod", "seedMethod",
    "seedZeroIndexed", "cardColemanSymbols", "entropyFormat", "globalSync",
    "globalSyncSource", "globalSyncBitCount", "seedAutocomplete",
    "passphraseBip39Words", "brainWalletOutput", "passphraseAutocomplete",
    "brainWalletTrim", "showCards", "showDiceFairness", "showNumberBaseCalculations",
    "targetWords", "diceCoinPositions", "lastWord", "dplusLastWord", "accountId", "coreMixSource", "fields",
  ]) {
    if (Object.prototype.hasOwnProperty.call(entry, field) && entry[field] !== undefined) copy[field] = JSON.parse(JSON.stringify(entry[field]));
  }
  const sourceBits = entry.globalSyncSourceBits;
  // A file's digest length or cached assessment does not establish source
  // entropy. Missing metadata must also stay unknown, not fall back to the
  // digest length in the sync status. Locally measured exports keep it.
  if (!exporting && copy.globalSync) copy.globalSyncSourceBits = "unknown";
  else if (sourceBits === null || sourceBits === "unknown" || Number.isFinite(sourceBits) && sourceBits >= 0) copy.globalSyncSourceBits = sourceBits;
  // Only the export path can read a runtime result. On import, cached
  // result.network is as untrusted as cached addresses and fingerprints.
  if (exporting && Number.isSafeInteger(entry.id) && entry.id > 0 && !entry.needsDerivation && KEY_NETWORKS.includes(entry.result?.network)) {
    copy.fields.network = entry.result.network;
  }
  if (!exporting && vaultModes && !vaultModes.includes(copy.mode ?? "dice")) throw new Error("The key file contains an invalid key.");
  // The core-wallet source picks how the transcript is parsed: only the two
  // sources the method knows may cross the boundary.
  if (!exporting && Object.hasOwn(copy, "coreMixSource") && copy.coreMixSource !== "dice" && copy.coreMixSource !== "cards") throw new Error("The key file contains an invalid key.");
  copy.name = String(copy.name || "Imported key").trim().replace(/\s+/g, " ").slice(0, 120) || "Imported key";
  copy.reveal = false;
  copy.result = null;
  copy.needsDerivation = true;
  copy.error = "";
  delete copy.errorSpec;
  return copy;
}

function vaultEntries(entries, label, exporting = false) {
  if (!Array.isArray(entries) || entries.length > KEY_VAULT_MAX_KEYS) throw new Error(`The key file has too many ${label}.`);
  return entries.map((entry) => vaultEntry(entry, exporting));
}

export function serializeKeyVault(keys, ignoredKeys = []) {
  return JSON.stringify({
    format: KEY_VAULT_FORMAT,
    version: KEY_VAULT_VERSION,
    keys: vaultEntries(keys, "keys", true),
    ignoredKeys: vaultEntries(ignoredKeys, "ignored keys", true),
  }, null, 2) + "\n";
}

export function parseKeyVault(text) {
  let document;
  try {
    document = JSON.parse(String(text ?? ""));
  } catch {
    throw new Error("This is not valid Key Manager JSON.");
  }
  if (!document || document.format !== KEY_VAULT_FORMAT || ![1, KEY_VAULT_VERSION].includes(document.version)) {
    throw new Error("This file is not a supported EntropyLab key file.");
  }
  return {
    keys: vaultEntries(document.keys, "keys"),
    ignoredKeys: vaultEntries(document.ignoredKeys || [], "ignored keys"),
  };
}
