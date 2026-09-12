// Portable Key Manager payloads. Encryption is supplied by the unlocked
// Entropy Journal so this module never generates salts, nonces, or key data.
export const KEY_VAULT_FORMAT = "entropylab-key-manager";
export const KEY_VAULT_VERSION = 2;
export const KEY_VAULT_MAX_KEYS = 100;

export function keyVaultIdentity(state) {
  return String(state?.result?.masterFingerprint || state?.result?.rootXpub || state?.result?.xpub || state?.id || "");
}

function vaultEntry(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry) || entry.isLab || !entry.fields || typeof entry.fields !== "object" || Array.isArray(entry.fields)) {
    throw new Error("The key file contains an invalid key.");
  }
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
    "targetWords", "diceCoinPositions", "lastWord", "dplusLastWord", "accountId", "fields",
  ]) {
    if (Object.prototype.hasOwnProperty.call(entry, field) && entry[field] !== undefined) copy[field] = JSON.parse(JSON.stringify(entry[field]));
  }
  copy.name = String(copy.name || "Imported key").trim().replace(/\s+/g, " ").slice(0, 120) || "Imported key";
  copy.reveal = false;
  copy.result = null;
  copy.needsDerivation = true;
  copy.error = "";
  delete copy.errorSpec;
  return copy;
}

function vaultEntries(entries, label) {
  if (!Array.isArray(entries) || entries.length > KEY_VAULT_MAX_KEYS) throw new Error(`The key file has too many ${label}.`);
  return entries.map(vaultEntry);
}

export function serializeKeyVault(keys, ignoredKeys = []) {
  return JSON.stringify({
    format: KEY_VAULT_FORMAT,
    version: KEY_VAULT_VERSION,
    keys: vaultEntries(keys, "keys"),
    ignoredKeys: vaultEntries(ignoredKeys, "ignored keys"),
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
