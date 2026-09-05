// Portable Key Manager payloads. Encryption is supplied by the unlocked
// Entropy Journal so this module never generates salts, nonces, or key data.
export const KEY_VAULT_FORMAT = "entropylab-key-manager";
export const KEY_VAULT_VERSION = 1;
export const KEY_VAULT_MAX_KEYS = 100;

export function keyVaultIdentity(state) {
  return String(state?.result?.masterFingerprint || state?.result?.rootXpub || state?.result?.xpub || state?.id || "");
}

function vaultEntry(entry) {
  if (!entry || typeof entry !== "object" || entry.isLab || !entry.fields || typeof entry.fields !== "object" || !entry.result || typeof entry.result !== "object") {
    throw new Error("The key file contains an invalid key.");
  }
  let copy = JSON.parse(JSON.stringify(entry));
  delete copy.isLab;
  copy.name = String(copy.name || "Imported key").trim().replace(/\s+/g, " ").slice(0, 120) || "Imported key";
  copy.reveal = false;
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
  if (!document || document.format !== KEY_VAULT_FORMAT || document.version !== KEY_VAULT_VERSION) {
    throw new Error("This file is not a supported EntropyLab key file.");
  }
  return {
    keys: vaultEntries(document.keys, "keys"),
    ignoredKeys: vaultEntries(document.ignoredKeys || [], "ignored keys"),
  };
}
