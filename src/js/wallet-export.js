
// Bitcoin Core wallet.dat export.
//
// Builds a complete descriptor-wallet database byte-by-byte in the exact
// format Bitcoin Core 28.x writes for `createwallet` + `importdescriptors`,
// using hodlSqliteWriter for the container. While "Show private recovery
// material" is off, every descriptor is watch-only (xpub) and the wallet is
// flagged disable-private-keys; while it is on, accounts with spending
// material additionally get walletdescriptorkey records (the account private
// key, DER-encoded) so the wallet can sign. The button label and filename
// always say which variant is being downloaded.
//
// Record format verified against Bitcoin Core v28.3.0 on regtest:
//   version / minversion / flags / bestblock / bestblock_nomerkle
//   walletdescriptor      <id>  -> public descriptor string, creation time,
//                                  next_index, range_start, range_end
//   walletdescriptorcache <id> <pos 0> -> branch xpub (74 bytes, no version)
//   walletdescriptorkey   <id> <pubkey> -> DER private key + key hash (private only)
//   activeexternalspk / activeinternalspk <type> -> descriptor id
//
// The module is pure byte transformation: no I/O, no network traffic, and no
// key derivation of its own (crypto is injected by the caller).
var hodlWalletExport = (() => {
  const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

  const RECORD_VERSION = 280300; // last client version seen by the reference files
  const RECORD_MINVERSION = 169900; // FEATURE_PRE_SPLIT_KEYPOOL; every Core with descriptor support accepts it
  const RANGE_END = 1000; // importdescriptors default active range

  // Wallet flags (walletutil.h): DESCRIPTORS | BLANK, plus DISABLE_PRIVATE_KEYS for watch-only.
  const FLAG_DISABLE_PRIVATE_KEYS = 1n << 32n;
  const FLAG_BLANK_WALLET = 1n << 33n;
  const FLAG_DESCRIPTORS = 1n << 34n;

  const DUMMY_LOCATOR_VERSION = 70016; // CBlockLocator::DUMMY_VERSION, little-endian in records

  const NETWORKS = {
    mainnet: {
      applicationId: 0xf9beb4d9, // network magic in natural byte order
      genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    },
    testnet: {
      applicationId: 0x0b110907,
      genesis: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
    },
    // Not offered by the UI; used by the test suite to validate files with a
    // regtest Bitcoin Core node.
    regtest: {
      applicationId: 0xfabfb5da,
      genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    },
  };

  // OutputType (wallet): pkh=0, sh(wpkh)=1, wpkh=2, tr=3.
  const OUTPUT_TYPES = { bip44: 0, bip49: 1, bip84: 2, bip86: 3 };

  // DER-encoded secp256k1 private key (Bitcoin Core CPrivKey form): static
  // template, insert the 32-byte secret and the 33-byte compressed pubkey.
  const DER_PREFIX = hex(
    "3081d3" + "020101" + "0420",
  );
  const DER_PARAMS = hex(
    "a08185" + "308182" + "020101" +
    "302c" + "06072a8648ce3d0101" +
    "022100" + "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f" +
    "3006" + "040100" + "040107" +
    "0421" + "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "022100" + "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" +
    "020101",
  );
  const DER_PUBKEY_PREFIX = hex("a124" + "0322" + "00");

  function hex(text) {
    const bytes = new Uint8Array(text.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
    return bytes;
  }

  const concat = (...parts) => {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  };

  const utf8 = (text) => new TextEncoder().encode(text);

  const u8 = (value) => Uint8Array.of(value & 0xff);
  const u32le = (value) => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
    return bytes;
  };
  const u64le = (value) => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
    return bytes;
  };

  // Bitcoin CompactSize (used by CDataStream, not to be confused with SQLite varints).
  const compactSize = (length) => {
    if (length < 0) throw new Error("compactSize: negative length");
    if (length < 253) return u8(length);
    if (length <= 0xffff) return concat(u8(253), u16le(length));
    if (length <= 0xffffffff) return concat(u8(254), u32le(length));
    return concat(u8(255), u64le(length));
  };
  const u16le = (value) => Uint8Array.of(value & 0xff, (value >>> 8) & 0xff);

  const streamString = (text) => {
    const bytes = utf8(text);
    return concat(compactSize(bytes.length), bytes);
  };

  const reverseHex = (hexText) => hex(hexText).reverse();

  // Descriptor bodies end in "/*)" for every descriptor this app produces, so
  // a digit+h before a path separator or bracket is always a hardened step.
  const toCompatForm = (body) => body.replace(/(\d)h(?=[/\]])/g, "$1'");

  const stripChecksum = (descriptor) => {
    const hash = descriptor.lastIndexOf("#");
    return hash >= 0 ? descriptor.slice(0, hash) : descriptor;
  };

  // SLIP-132 single-signature prefixes (plus generic xpub/xprv); Bitcoin has
  // no base58 "npub"/"nprv" extended keys (that spelling is Nostr's bech32).
  const EXTENDED_KEY_PATTERN = /((?:xpub|tpub|ypub|upub|zpub|vpub|xprv|tprv|yprv|uprv|zprv|vprv)[1-9A-HJ-NP-Za-km-z]{90,})/;
  const extractExtendedKey = (descriptor, label) => {
    const match = descriptor.match(EXTENDED_KEY_PATTERN);
    if (!match) throw new Error(`wallet.dat export: no extended key found in ${label} descriptor`);
    return match[1];
  };

  // One descriptor export unit per account branch: the watch-only descriptor
  // plus, when requested and available, its private key record material.
  const walletDescriptorUnits = (wallet, includePrivate) => {
    if (!wallet || wallet.kind !== "hd" || !Array.isArray(wallet.accounts)) return [];
    const units = [];
    for (const account of wallet.accounts) {
      if (!account?.receiveDescriptor || !account?.changeDescriptor) continue;
      const type = OUTPUT_TYPES[account.def?.id];
      if (type === undefined) continue;
      for (const branch of [0, 1]) {
        const descriptor = branch === 0 ? account.receiveDescriptor : account.changeDescriptor;
        const privateDescriptor = branch === 0 ? account.receiveDescriptorPriv : account.changeDescriptorPriv;
        units.push({
          type,
          internal: branch === 1,
          descriptor,
          privateDescriptor: includePrivate ? privateDescriptor : null,
        });
      }
    }
    return units;
  };

  const hasDescriptors = (wallet) => walletDescriptorUnits(wallet, false).length > 0;

  // Builds the exact key/value rows of the `main` table.
  // deps = { sha256, checksum, base58Decode, deriveBranchBody, publicKeyForPrivate }
  const buildWalletRecords = (wallet, includePrivate, deps, creationTime) => {
    const network = NETWORKS[wallet?.network];
    if (!network) throw new Error(`wallet.dat export: unknown network ${wallet?.network}`);
    const units = walletDescriptorUnits(wallet, includePrivate);
    if (!units.length) throw new Error("wallet.dat export: no descriptors to export");

    const records = [];
    const push = (key, value) => records.push([key, value]);

    push(streamString("version"), u32le(RECORD_VERSION));
    push(streamString("minversion"), u32le(RECORD_MINVERSION));
    // The wallet is only signing-capable if at least one descriptor got a
    // private key record; otherwise keep the disable-private-keys flag.
    const hasPrivateKeys = includePrivate && units.some((unit) => unit.privateDescriptor);
    const flags = FLAG_DESCRIPTORS | FLAG_BLANK_WALLET | (hasPrivateKeys ? 0n : FLAG_DISABLE_PRIVATE_KEYS);
    push(streamString("flags"), u64le(flags));
    // Fresh wallets sit on the genesis block: an empty locator for bestblock,
    // and a one-hash locator for bestblock_nomerkle.
    push(streamString("bestblock"), concat(u32le(DUMMY_LOCATOR_VERSION), compactSize(0)));
    push(streamString("bestblock_nomerkle"), concat(u32le(DUMMY_LOCATOR_VERSION), compactSize(1), reverseHex(network.genesis)));

    const seenActive = new Set();
    for (const unit of units) {
      const stored = unit.descriptor; // public (watch-only) form with checksum, exactly as Core stores it
      const body = stripChecksum(stored);
      const compatBody = toCompatForm(body);
      const compatDescriptor = `${compatBody}#${deps.checksum(compatBody)}`;
      const id = deps.sha256(utf8(compatDescriptor)); // DescriptorID: raw SHA-256 digest bytes
      if (id.length !== 32) throw new Error("wallet.dat export: sha256 must return 32 bytes");

      push(
        concat(streamString("walletdescriptor"), id),
        concat(streamString(stored), u64le(creationTime), u32le(0), u32le(0), u32le(RANGE_END)),
      );

      const xpub = extractExtendedKey(stored, "watch-only");
      const branchBody = deps.deriveBranchBody(xpub, unit.internal ? 1 : 0);
      if (branchBody.length !== 74) throw new Error("wallet.dat export: branch xpub body must be 74 bytes");
      push(
        concat(streamString("walletdescriptorcache"), id, u32le(0)),
        concat(compactSize(branchBody.length), branchBody),
      );

      if (unit.privateDescriptor) {
        const xprv = extractExtendedKey(unit.privateDescriptor, "spending");
        const raw = deps.base58Decode(xprv);
        if (raw.length !== 78 || raw[45] !== 0) throw new Error("wallet.dat export: unexpected extended private key payload");
        const secret = raw.slice(46, 78);
        const pubkey = deps.publicKeyForPrivate(secret);
        if (pubkey.length !== 33) throw new Error("wallet.dat export: public key must be 33 bytes");
        const der = concat(DER_PREFIX, secret, DER_PARAMS, DER_PUBKEY_PREFIX, pubkey);
        if (der.length !== 214) throw new Error("wallet.dat export: DER private key must be 214 bytes");
        const keyHash = deps.sha256(deps.sha256(concat(pubkey, der)));
        push(
          concat(streamString("walletdescriptorkey"), id, compactSize(pubkey.length), pubkey),
          concat(compactSize(der.length), der, keyHash),
        );
        // concat() copied the bytes into the record; wipe the intermediates.
        raw.fill(0);
        secret.fill(0);
        der.fill(0);
        keyHash.fill(0);
      }

      const activeKey = `${unit.internal}:${unit.type}`;
      if (seenActive.has(activeKey)) throw new Error("wallet.dat export: duplicate script type across accounts");
      seenActive.add(activeKey);
      push(
        concat(streamString(unit.internal ? "activeinternalspk" : "activeexternalspk"), u8(unit.type)),
        id,
      );
    }
    return records;
  };

  // The complete wallet.dat file bytes.
  const buildWalletDat = (wallet, includePrivate, deps, creationTime = Math.floor(Date.now() / 1000)) => {
    const records = buildWalletRecords(wallet, includePrivate, deps, creationTime);
    const network = NETWORKS[wallet.network];
    return hodlSqliteWriter.createDatabase({
      applicationId: network.applicationId,
      tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows: records }],
    });
  };

  // Name the file after the wallet's master fingerprint (XFP) so exports are
  // unique and identifiable when a user keeps wallets for several seeds; the
  // reveal state suffix still says which variant the file contains. Falls
  // back to the plain name when the wallet has no fingerprint.
  const walletDatFilename = (wallet, includePrivate = false) => {
    const base = includePrivate ? "private-wallet-secrets" : "watch-only-wallet";
    const fingerprint = typeof wallet?.masterFingerprint === "string" && /^[0-9a-fA-F]{8}$/.test(wallet.masterFingerprint)
      ? wallet.masterFingerprint.toLowerCase()
      : null;
    return fingerprint ? `entropylab-${fingerprint}-${base}.dat` : `${base}.dat`;
  };

  const walletDatButtonLabel = (includePrivate = false) => {
    const t = globalThis.hodlT;
    return includePrivate
      ? (t ? t("walletdat.downloadPrivate") : "Download wallet.dat with secrets (xprvs)")
      : (t ? t("walletdat.downloadWatch") : "Download watch-only wallet.dat");
  };

  return {
    walletDescriptorUnits,
    hasDescriptors,
    buildWalletRecords,
    buildWalletDat,
    walletDatFilename,
    walletDatButtonLabel,
  };
})();
