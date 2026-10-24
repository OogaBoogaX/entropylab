
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
//   walletdescriptorcache <id> <pos 0> -> parent xpub of the wildcard
//                                  (74 bytes, no version): the branch child
//                                  of the account key, or the descriptor
//                                  root key itself for hardened-branch
//                                  descriptors
//   walletdescriptorkey   <id> <pubkey> -> DER private key + key hash (private only)
//   activeexternalspk / activeinternalspk <type> -> descriptor id
//
// The module is pure byte transformation: no I/O, no network traffic, and no
// key derivation of its own (crypto is injected by the caller).
var hodlWalletExport = (() => {
  const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

  const RECORD_VERSION = 280300; // last client version seen by the reference files
  const RECORD_MINVERSION = 169900; // FEATURE_PRE_SPLIT_KEYPOOL; every Core with descriptor support accepts it
  const RANGE_END = 1000; // Core's default lookahead, retained beyond the displayed window
  const MAX_ADDRESS_INDEX = 0x7fffffff;

  // Wallet flags (walletutil.h): DESCRIPTORS | BLANK, plus DISABLE_PRIVATE_KEYS for watch-only.
  const FLAG_DISABLE_PRIVATE_KEYS = 1n << 32n;
  const FLAG_BLANK_WALLET = 1n << 33n;
  const FLAG_DESCRIPTORS = 1n << 34n;

  const DUMMY_LOCATOR_VERSION = 70016; // CBlockLocator::DUMMY_VERSION, little-endian in records

  // Bitcoin Core keeps the chain identity in two places: the SQLite
  // application_id (the network magic, read big-endian) and the
  // bestblock_nomerkle locator (the chain's genesis hash). All four picker
  // networks are listed — signet and regtest are collapsed to the testnet
  // key/address family by the tools, but their wallet.dat metadata is
  // chain-specific (issue #329). The signet row is the default signet;
  // Core derives a different network magic for custom signet challenges,
  // which this export does not support.
  const NETWORKS = {
    mainnet: {
      applicationId: 0xf9beb4d9, // network magic in natural byte order
      genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    },
    testnet: {
      applicationId: 0x0b110907,
      genesis: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
    },
    signet: {
      applicationId: 0x0a03cf40,
      genesis: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    },
    regtest: {
      applicationId: 0xfabfb5da,
      genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    },
  };

  // OutputType (wallet): pkh=0, sh(wpkh)=1, wpkh=2, tr=3.
  // Multisig wrappers land on the same enum: sh(multi)=legacy, sh(wsh)=p2sh-segwit,
  // wsh=bech32, tr(sortedmulti_a)=bech32m.
  const OUTPUT_TYPES = { bip44: 0, bip49: 1, bip84: 2, bip86: 3 };
  const MSIG_OUTPUT_TYPES = { p2sh: 0, "p2sh-p2wsh": 1, p2wsh: 2, p2tr: 3 };

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

  // Strict like coders.js' hex.decode (this IIFE predates the module graph):
  // a malformed template must throw here, never zero-fill into a DER record.
  function hex(text) {
    if (typeof text !== "string" || text.length % 2 || /[^0-9a-f]/i.test(text)) throw new Error("Invalid hexadecimal string");
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

  // Core's compat form renders every hardened step with ' and re-encodes key
  // material untouched. Every descriptor this exporter emits carries its
  // hardened steps only inside the [fingerprint/path] key origin (a hardened
  // branch step moves into the origin; an address-hardened account has no
  // public descriptor at all), so rewriting the origin is exactly right. A
  // body-wide substitution is not: base58 contains both digits and "h", and
  // the account xpub sits directly before a "/", so it corrupts any xpub
  // ending in <digit>h (about 1 in 375 account keys) and produces a
  // DescriptorID that disagrees with the one Core recomputes at load
  // (DBErrors::CORRUPT). The fingerprint is hex, so a hardened marker inside
  // the origin is always a path step; the guard accepts h, H and ' alike,
  // and Core's compat form renders every one of them as '. The same
  // re-rendering prints the fingerprint and a hex Taproot internal key with
  // HexStr — lowercase — so both are lowercased here and nowhere else:
  // base58 is case-sensitive, and an xpub can contain hex-looking runs.
  const toCompatForm = (body) =>
    body
      .replace(/\[[0-9a-fA-F]{8}(?:\/\d+[h'H]?)*\]/g, (origin) =>
        origin.slice(0, 9).toLowerCase() + origin.slice(9).replace(/\d+[h'H](?=[/\]])/g, (step) => `${step.slice(0, -1)}'`))
      .replace(/tr\([0-9a-fA-F]{64},/g, (nums) => `tr(${nums.slice(3, 67).toLowerCase()},`);

  const stripChecksum = (descriptor) => {
    const hash = descriptor.lastIndexOf("#");
    return hash >= 0 ? descriptor.slice(0, hash) : descriptor;
  };

  // SLIP-132 single-signature prefixes (plus generic xpub/xprv); Bitcoin has
  // no base58 "npub"/"nprv" extended keys (that spelling is Nostr's bech32).
  const EXTENDED_KEY_PATTERN = /((?:xpub|tpub|ypub|upub|zpub|vpub|xprv|tprv|yprv|uprv|zprv|vprv)[1-9A-HJ-NP-Za-km-z]{90,})/;
  const EXTENDED_PUB_GLOBAL = /((?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,})/g;
  const PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;
  const extractExtendedKey = (descriptor, label) => {
    const match = descriptor.match(EXTENDED_KEY_PATTERN);
    if (!match) throw new Error(`wallet.dat export: no extended key found in ${label} descriptor`);
    return match[1];
  };
  const extractExtendedPrivateKey = (descriptor) => {
    const match = descriptor.match(PRIVATE_KEY);
    if (!match) throw new Error("wallet.dat export: no extended private key found in spending descriptor");
    return match[0];
  };
  const extractExtendedPubs = (descriptor) => {
    EXTENDED_PUB_GLOBAL.lastIndex = 0;
    const keys = [];
    let match;
    while ((match = EXTENDED_PUB_GLOBAL.exec(descriptor))) keys.push(match[1]);
    return keys;
  };

  // Path between a descriptor's extended key and the next comma or closing
  // paren, reduced to the step above the wildcard: { branch, hardened } for
  // "…/0/*" style tails, { branch: null } when the key is already at the
  // branch level ("…/*"). Stops at "," so a sortedmulti with N keys still
  // parses; a two-step tail (BIP45 "…/0/0/*") is refused. `occurrence`
  // picks which copy of a repeated key to read: one extended key may fill two
  // co-signer slots with different paths ("xpubA/0/*,xpubA/5/0/*"), and
  // reading the first copy for both caches the wrong parent for the second.
  const descriptorKeyTail = (descriptor, extendedKey, occurrence = 0) => {
    const body = stripChecksum(descriptor);
    let at = body.indexOf(extendedKey);
    for (let seen = 0; seen < occurrence && at >= 0; seen++) at = body.indexOf(extendedKey, at + extendedKey.length);
    if (at < 0) throw new Error("wallet.dat export: extended key not in descriptor");
    const after = body.slice(at + extendedKey.length);
    if (/^\/\*(?=[,)]|$)/.test(after)) return { branch: null, hardened: false };
    const branch = after.match(/^\/(\d+)(['hH]?)\/\*(?=[,)]|$)/);
    if (!branch || Number(branch[1]) >= 0x80000000) throw new Error("wallet.dat export: unsupported descriptor path shape");
    return { branch: Number(branch[1]), hardened: Boolean(branch[2]) };
  };
  // How many earlier slots in `keys` hold the same extended key as slot `index`.
  const keyOccurrence = (keys, index) => keys.slice(0, index).filter((key) => key === keys[index]).length;

  // Core numbers every pubkey provider, including a constant Taproot
  // internal key that is not an xpub. The supported tr(NUMS,sortedmulti_a)
  // shape puts NUMS at key_exp_index 0, so co-signer caches belong at 1..n.
  // Native / nested / legacy wrappers have no extra provider and stay 0..n-1.
  const cacheKeyExpIndex = (descriptor, xpubIndex) => {
    const body = stripChecksum(descriptor);
    return /^tr\([0-9a-fA-F]{64},/.test(body) ? xpubIndex + 1 : xpubIndex;
  };

  // One descriptor export unit per account branch: the watch-only descriptor
  // plus, when requested and available, its private key record material.
  const branchRangeFromRows = (rows) => {
    const indexes = Array.isArray(rows)
      ? rows.map((row) => row?.index).filter((index) => Number.isSafeInteger(index) && index >= 0 && index <= MAX_ADDRESS_INDEX)
      : [];
    const rangeStart = indexes.length ? Math.min(...indexes) : 0;
    const displayedEnd = indexes.length ? Math.max(...indexes) : 0;
    const rangeEnd = indexes.length ? Math.min(MAX_ADDRESS_INDEX, displayedEnd + RANGE_END) : RANGE_END;
    const nextIndex = indexes.length ? Math.min(MAX_ADDRESS_INDEX, displayedEnd + 1) : 0;
    return { nextIndex, rangeStart, rangeEnd };
  };

  const msigDescriptorUnits = (wallet) => {
    const type = MSIG_OUTPUT_TYPES[wallet.script];
    if (type === undefined) return [];
    const units = [];
    // Export the branches this wallet derived, not a fixed {0,1}: a custom
    // window can start at 1, and filing branch 1 as change leaves Core with
    // no external chain at all.
    const byBranch = new Map();
    const addBranch = (entry) => {
      if (!entry || !Number.isSafeInteger(entry.branch) || byBranch.has(entry.branch)) return;
      byBranch.set(entry.branch, entry);
    };
    if (Array.isArray(wallet.addressBranches)) for (const entry of wallet.addressBranches) addBranch(entry);
    const windowStart = wallet.branchStart ?? 0;
    if (windowStart <= 0) addBranch({ branch: 0, publicDescriptor: wallet.receiveDescriptor, rows: wallet.receive });
    if (windowStart <= 1) addBranch({ branch: 1, publicDescriptor: wallet.changeDescriptor, rows: wallet.change });
    for (const entry of [...byBranch.values()].sort((a, b) => a.branch - b.branch)) {
      const branch = entry.branch;
      const descriptor = entry.publicDescriptor ?? (branch === 0 ? wallet.receiveDescriptor : branch === 1 ? wallet.changeDescriptor : null);
      if (!descriptor) continue;
      const rows = Array.isArray(entry.rows) ? entry.rows : branch === 0 ? wallet.receive : branch === 1 ? wallet.change : [];
      units.push({
        type,
        internal: windowStart === 0 && branch === 1,
        descriptor,
        privateDescriptor: null,
        multiKey: true,
        ...branchRangeFromRows(rows),
        // Fresh Core wallet: first getnewaddress is receive index 0, matching
        // the MS Station copy. Displayed EntropyLab rows are not spent here.
        nextIndex: 0,
        rangeStart: 0,
      });
    }
    return markActiveUnits(units);
  };

  // Core stores one active descriptor per (internal, type). A window with two
  // external branches can keep both descriptors, but only the first may be
  // active; buildWalletRecords must not refuse the export over it.
  const markActiveUnits = (units) => {
    const seen = new Set();
    for (const unit of units) {
      const key = `${unit.internal}:${unit.type}`;
      if (seen.has(key)) unit.active = false;
      else { seen.add(key); unit.active = true; }
    }
    return units;
  };

  const walletDescriptorUnits = (wallet, includePrivate) => {
    if (wallet?.kind === "msig") return msigDescriptorUnits(wallet);
    if (!wallet || wallet.kind !== "hd" || !Array.isArray(wallet.accounts)) return [];
    const units = [];
    for (const account of wallet.accounts) {
      const type = OUTPUT_TYPES[account.def?.id];
      if (type === undefined) continue;
      // Export the branches the account actually derived. A custom window can
      // start at 1, so [0, 1] would drop the last branch and file branch 1 as
      // change — Core then watches neither receive chain (audit follow-up).
      // Core's `internal` is the change chain: branch 1 of the default 0/1
      // window only.
      //
      // addressBranches may carry rows only (the legacy receive/change
      // descriptors still describe the branch), so take the union by branch
      // number rather than letting a rows-only list hide a legacy descriptor.
      const byBranch = new Map();
      const addBranch = (entry) => {
        if (!entry || !Number.isSafeInteger(entry.branch) || byBranch.has(entry.branch)) return;
        byBranch.set(entry.branch, entry);
      };
      if (Array.isArray(account.addressBranches)) for (const entry of account.addressBranches) addBranch(entry);
      // A legacy descriptor below the window start belongs to a branch this
      // account did not derive (the window can begin at 1 or higher).
      const windowStart = account.branchStart ?? 0;
      if (windowStart <= 0) addBranch({ branch: 0, publicDescriptor: account.receiveDescriptor, rows: account.receive });
      if (windowStart <= 1) addBranch({ branch: 1, publicDescriptor: account.changeDescriptor, rows: account.change });
      const branches = [...byBranch.values()].sort((a, b) => a.branch - b.branch), accountUnits = [];
      for (const entry of branches) {
        const branch = entry.branch;
        const descriptor = entry.publicDescriptor ?? (branch === 0 ? account.receiveDescriptor : branch === 1 ? account.changeDescriptor : null);
        if (!descriptor) continue;
        const privateDescriptor = entry.privateDescriptor
          ?? (branch === 0 ? account.receiveDescriptorPriv : branch === 1 ? account.changeDescriptorPriv : null);
        const rows = Array.isArray(entry.rows) ? entry.rows : branch === 0 ? account.receive : branch === 1 ? account.change : [];
        accountUnits.push({
          type,
          internal: (account.branchStart ?? 0) === 0 && branch === 1,
          descriptor,
          privateDescriptor: includePrivate ? privateDescriptor : null,
          ...branchRangeFromRows(rows),
        });
      }
      // Only the first branch of each (internal, type) can be active; the
      // rest are stored descriptors. Per account, so two accounts sharing a
      // type still reach buildWalletRecords' duplicate check.
      units.push(...markActiveUnits(accountUnits));
    }
    return units;
  };

  const hasDescriptors = (wallet) => walletDescriptorUnits(wallet, false).length > 0;

  // Whether any private descriptor material actually exists — independent of
  // the reveal toggle, so the secrets label/filename can never claim material
  // the file does not contain (issue #366).
  const hasPrivateDescriptors = (wallet) => walletDescriptorUnits(wallet, true).some((unit) => unit.privateDescriptor);

  // Descriptor tails the wallet.dat writer can place: a wildcard at the branch
  // level ("…/*") or one branch step above it ("…/0/*"). A BIP 45 two-step
  // tail ("…/0/0/*") is refused by descriptorKeyTail, so the control would
  // otherwise render and only fail on click. Every co-signer is read, as the
  // writer reads them: a deep tail on any key, not only the first, refuses.
  const tailsSupported = (wallet, branches = null) => {
    const units = walletDescriptorUnits(wallet, false);
    if (!units.length) return false;
    try {
      for (const unit of units) {
        const keys = unit.multiKey ? extractExtendedPubs(unit.descriptor) : [extractExtendedKey(unit.descriptor, "key")];
        if (!keys.length) return false;
        for (const [index, key] of keys.entries()) {
          const tail = descriptorKeyTail(unit.descriptor, key, keyOccurrence(keys, index));
          if (tail.hardened) return false;
          if (branches && !branches.includes(tail.branch)) return false;
        }
      }
      return true;
    } catch {
      return false;
    }
  };
  // The wallet.dat control must not render for a wallet the shape guard
  // would refuse only on click. The gating path has no crypto injected, so
  // the guard runs on the descriptor text alone: the checksum and
  // Base58Check key checks stay on the export path, which carries deps.
  const walletDatSupported = (wallet) => {
    if (!tailsSupported(wallet)) return false;
    try {
      for (const unit of walletDescriptorUnits(wallet, false)) {
        assertDescriptorShape(unit.descriptor, "watch-only", null, unit.type, Boolean(unit.multiKey));
      }
      return true;
    } catch {
      return false;
    }
  };
  // The BIP 388 builder rewrites only "/0/*" and "/1/*".
  const bip388Supported = (wallet) => tailsSupported(wallet, [0, 1]);

  // Defense-in-depth: the descriptor shapes this writer can place in a
  // wallet.dat are exactly one known script wrapper around extended keys it
  // can read. The app only ever hands over descriptors it derived itself,
  // but a bare extended key, a nested wrapper, or a multisig co-signer that
  // does not parse must fail closed here instead of becoming a wallet.dat
  // Bitcoin Core refuses to load — or one that watches a different policy
  // than the app showed. Errors name wrappers only, never key material.
  const KEY_ORIGIN_PATTERN = String.raw`(?:\[[0-9a-fA-F]{8}(?:/\d+[h'H]?)*\])?`;
  const KEY_BODY_PATTERN = "([xyztuvYZUV](?:pub|prv)[1-9A-HJ-NP-Za-km-z]{90,})";
  const KEY_PATH_PATTERN = String.raw`(?:/\d+[h'H]?)*(?:/\*)?`;
  const KEY_EXPRESSION_PATTERN = KEY_ORIGIN_PATTERN + KEY_BODY_PATTERN + KEY_PATH_PATTERN;
  const SINGLE_SIG_SHAPES = [
    `^pkh\\(${KEY_EXPRESSION_PATTERN}\\)$`,
    `^sh\\(wpkh\\(${KEY_EXPRESSION_PATTERN}\\)\\)$`,
    `^wpkh\\(${KEY_EXPRESSION_PATTERN}\\)$`,
    `^tr\\(${KEY_EXPRESSION_PATTERN}\\)$`,
  ].map((source) => new RegExp(source));
  // Bitcoin Core's ParseMulti refuses a threshold outside 1..n and caps the
  // key count by script type: at most 20 keys in wsh, at most 15 in sh (the
  // 520-byte push limit). Taproot's multi_a has no CHECKMULTISIG limit —
  // Core caps it at MAX_PUBKEYS_PER_MULTI_A = 999 — but 20 is kept here
  // deliberately: it fails closed, and the app never builds a wider policy.
  const MULTISIG_SHAPES = [
    { source: String.raw`^sh\((?:sorted)?multi\((\d+),(.*)\)\)$`, maxKeys: 15 },
    { source: String.raw`^wsh\((?:sorted)?multi\((\d+),(.*)\)\)$`, maxKeys: 20 },
    { source: String.raw`^sh\(wsh\((?:sorted)?multi\((\d+),(.*)\)\)\)$`, maxKeys: 20 },
    { source: String.raw`^tr\([0-9a-fA-F]{64},(?:sorted)?multi_a\((\d+),(.*)\)\)$`, maxKeys: 20 },
  ].map(({ source, maxKeys }) => ({ pattern: new RegExp(source), maxKeys }));
  const KEY_LIST_ITEM_PATTERN = new RegExp(`^${KEY_EXPRESSION_PATTERN}$`);
  const UNSUPPORTED_DESCRIPTOR_SHAPE = "wallet.dat export: unsupported descriptor shape (supported: pkh(KEY), sh(wpkh(KEY)), wpkh(KEY), tr(KEY), sh/wsh/sh(wsh()) of multi/sortedmulti, tr(NUMS,sortedmulti_a))";
  const INVALID_EXTENDED_KEY = "wallet.dat export: descriptor key is not a valid extended key";
  const INVALID_MULTISIG_THRESHOLD = "wallet.dat export: multisig threshold must be between 1 and the number of keys, and the key count within the script type's limit";
  const INVALID_PATH_STEP = "wallet.dat export: descriptor path step must be 0 or [1-9][0-9]* (no leading zeros)";
  const INVALID_PATH_STEP_MAGNITUDE = "wallet.dat export: unsupported descriptor path shape (a step of 2^31 or more)";
  const SCRIPT_TYPE_MISMATCH = "wallet.dat export: descriptor script type does not match the wallet's declared output type";
  const WALLET_KIND_MISMATCH = "wallet.dat export: descriptor family does not match the wallet kind (HD accounts carry single-signature descriptors, multisig wallets multisig descriptors)";
  const INVALID_TAPROOT_NUMS = "wallet.dat export: Taproot internal key must be the BIP 341 NUMS point";
  // BIP 341's NUMS point H, the only Taproot internal key the app writes.
  // The module cannot check the curve validity of an arbitrary x-only key,
  // so anything but H is refused; the comparison is case-insensitive because
  // the descriptor may spell the hex in either case.
  const TAPROOT_NUMS_POINT = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
  // The OutputType (wallet.h) each supported wrapper produces, mirroring
  // OUTPUT_TYPES / MSIG_OUTPUT_TYPES: pkh and sh(multi) are legacy (0),
  // sh(wpkh()) and sh(wsh()) p2sh-segwit (1), wpkh() and wsh() bech32 (2),
  // tr() bech32m (3). The guard refuses a descriptor whose wrapper
  // disagrees with the type the wallet declared — the wallet.dat would
  // watch a different policy than the app showed.
  const wrapperOutputType = (body) =>
    body.startsWith("pkh(") || body.startsWith("sh(multi(") || body.startsWith("sh(sortedmulti(") ? 0 :
    body.startsWith("sh(wpkh(") || body.startsWith("sh(wsh(") ? 1 :
    body.startsWith("wpkh(") || body.startsWith("wsh(") ? 2 :
    body.startsWith("tr(") ? 3 : null;

  // Throws unless the descriptor is exactly one of the supported shapes with
  // a self-consistent checksum (when one is present), Base58Check-valid
  // extended keys, path steps Core can parse, the wrapper producing the
  // output type the wallet declared, the descriptor family matching the
  // wallet kind, and — for the Taproot multisig shape — BIP 341's NUMS
  // point as the internal key; the path after each key is placed by
  // descriptorKeyTail. deps carries the checksum and Base58Check
  // implementations; without it (the button-gating path, which injects no
  // crypto) the checksum and key-length checks are skipped and only the
  // descriptor text is validated.
  const assertDescriptorShape = (descriptor, label, deps, type, multisig) => {
    const hash = descriptor.lastIndexOf("#");
    const body = hash >= 0 ? descriptor.slice(0, hash) : descriptor;
    if (hash >= 0 && deps && deps.checksum(body) !== descriptor.slice(hash + 1)) {
      throw new Error(`wallet.dat export: invalid descriptor checksum in ${label} descriptor`);
    }
    // A path step with a leading zero ("/084h", "/00/*") parses in Core
    // (ParseUInt32) but its compat form prints the parsed uint32 without the
    // zeros, so the stored DescriptorID would disagree with the one Core
    // recomputes at load. The app never writes such a step; refuse it. A
    // step is 0 or [1-9][0-9]*, and "/" never appears outside a path.
    if (/\/0\d/.test(body)) throw new Error(INVALID_PATH_STEP);
    // Core's ParseKeyPath refuses any step numbered 2^31 or more, hardened
    // or not ("Path value too large"), in a key origin or a key path alike;
    // "/" never appears outside a path, so every /<digits> run is a step.
    for (const step of body.matchAll(/\/(\d+)/g)) {
      if (Number(step[1]) >= 2147483648) throw new Error(INVALID_PATH_STEP_MAGNITUDE);
    }
    const keys = [];
    let matched = SINGLE_SIG_SHAPES.some((shape) => {
      const key = body.match(shape);
      if (key) keys.push(key[1]);
      return Boolean(key);
    });
    const singleSig = matched;
    if (!matched) {
      matched = MULTISIG_SHAPES.some(({ pattern, maxKeys }) => {
        const list = body.match(pattern);
        if (!list) return false;
        const threshold = Number(list[1]);
        const items = list[2].split(",");
        // A leading zero ("01") is refused too: Core recomputes the
        // DescriptorID from its own spelling, so the stored ID would not match.
        if (!/^[1-9]\d*$/.test(list[1]) || !(threshold >= 1 && threshold <= items.length) || items.length > maxKeys) {
          throw new Error(INVALID_MULTISIG_THRESHOLD);
        }
        for (const item of items) {
          const key = item.match(KEY_LIST_ITEM_PATTERN);
          if (!key) throw new Error(INVALID_EXTENDED_KEY);
          keys.push(key[1]);
        }
        return true;
      });
    }
    if (!matched) throw new Error(UNSUPPORTED_DESCRIPTOR_SHAPE);
    // The descriptor family must match the wallet kind: an HD account is
    // single-signature, a multisig wallet is not. A wsh(sortedmulti(...)) on
    // a bip84 account passes the wrapper check below (wsh is bech32, like
    // wpkh) but would watch a different policy than the app showed — and the
    // writer would cache only its first key; a wpkh(...) on a multisig
    // wallet is the same swap in reverse.
    if (singleSig === Boolean(multisig)) throw new Error(WALLET_KIND_MISMATCH);
    // The wrapper must produce the output type the wallet declared: a p2wsh
    // multisig exporting an sh(multi(...)) descriptor, or a bip84 account
    // exporting pkh(...), would be filed under an activeexternalspk type
    // that watches a different policy than the app showed.
    if (wrapperOutputType(body) !== type) throw new Error(SCRIPT_TYPE_MISMATCH);
    // The supported Taproot multisig shape puts BIP 341's NUMS point H at
    // key_exp_index 0; the module cannot check the curve validity of an
    // arbitrary x-only key, and the app only ever writes H.
    const nums = body.match(/^tr\(([0-9a-fA-F]{64}),/);
    if (nums && nums[1].toLowerCase() !== TAPROOT_NUMS_POINT) throw new Error(INVALID_TAPROOT_NUMS);
    // The Base58Check decodes need deps; the gating path (no crypto
    // injected) stops at the text checks above.
    if (!deps) return;
    for (const key of keys) {
      let raw = null;
      try {
        raw = deps.base58Decode(key);
      } catch {
        raw = null;
      }
      try {
        if (!raw || raw.length !== 78) throw new Error(INVALID_EXTENDED_KEY);
      } finally {
        // The decode is validation-only and may carry a private key: wipe
        // the bytes whether the check threw or not.
        if (raw) raw.fill(0);
      }
    }
  };

  // The 74-byte serialized node (no version bytes), as Core's descriptor
  // cache stores it.
  const extendedKeyBody = (extendedKey, deps) => {
    const raw = deps.base58Decode(extendedKey);
    if (raw.length !== 78) throw new Error("wallet.dat export: unexpected extended key payload");
    return raw.slice(4);
  };

  // The records one descriptor unit contributes to the `main` table:
  // walletdescriptor, one walletdescriptorcache per pubkey provider, an
  // optional walletdescriptorkey for spending material, and (unless
  // unit.active === false) the activeexternalspk/activeinternalspk pointer.
  // Exported for the Core Wallet tab, which appends units to an existing
  // wallet and resolves active-record conflicts itself.
  // deps = { sha256, checksum, base58Decode, deriveBranchBody, publicKeyForPrivate }
  const descriptorUnitRecords = (unit, deps, creationTime) => {
    const records = [];
    const push = (key, value) => records.push([key, value]);

      // Every unit's watch-only descriptor is stored in canonical form:
      // Bitcoin Core's descriptor parser accepts only xpub/tpub, so a
      // SLIP-132 prefix (ypub/zpub/…) on a single-sig descriptor must be
      // re-versioned too, not only a multisig's — or the wallet.dat fails
      // to load. The DescriptorID below is computed from this stored form.
      let stored = unit.descriptor;
      if (typeof deps.canonicalizeDescriptor === "function") stored = deps.canonicalizeDescriptor(stored);
      // A watch-only export must never carry private key material: any
      // extended private key in a stored descriptor, single-sig or multisig,
      // is refused (spending material travels only in walletdescriptorkey).
      if (PRIVATE_KEY.test(stored)) throw new Error("wallet.dat export: watch-only descriptor refused an extended private key");
      // Core's wallet loader parses the stored descriptor with
      // require_checksum = true, so a descriptor handed over without one is
      // stored with the module's own checksum appended: the stored string and
      // the DescriptorID below are then both exactly what Core computes.
      if (stored.lastIndexOf("#") < 0) stored = `${stored}#${deps.checksum(stored)}`;
      const body = stripChecksum(stored);
      const compatBody = toCompatForm(body);
      const compatDescriptor = `${compatBody}#${deps.checksum(compatBody)}`;
      const id = deps.sha256(utf8(compatDescriptor)); // DescriptorID: raw SHA-256 digest bytes
      if (id.length !== 32) throw new Error("wallet.dat export: sha256 must return 32 bytes");

      push(
        concat(streamString("walletdescriptor"), id),
        concat(streamString(stored), u64le(creationTime), u32le(unit.nextIndex), u32le(unit.rangeStart), u32le(unit.rangeEnd)),
      );

      const pubs = unit.multiKey ? extractExtendedPubs(stored) : [extractExtendedKey(stored, "watch-only")];
      if (!pubs.length) throw new Error("wallet.dat export: no extended key found in watch-only descriptor");
      if (pubs.some((key) => !/^[xt]pub/.test(key))) {
        throw new Error("wallet.dat export: descriptors need the Base58Check codec to rewrite SLIP-132 keys as xpub/tpub");
      }
      pubs.forEach((xpub, index) => {
        const tail = descriptorKeyTail(stored, xpub, keyOccurrence(pubs, index));
        if (tail.hardened) throw new Error("wallet.dat export: hardened step after a public key");
        // Core caches the parent key of the wildcard: the branch child for
        // account-level descriptors ("…xpub/0/*"), or the descriptor root key
        // itself when a hardened branch already moved the key to branch level
        // ("…xpubBranch/*") — BIP32PubkeyProvider with an empty path caches
        // its root key. Caching the wrong parent makes Core watch a different
        // subtree than the descriptor's. Multisig writes one parent per
        // co-signer at that key's Core key_exp_index (0..n-1, or 1..n when a
        // Taproot NUMS internal key occupies 0).
        const branchBody = tail.branch === null ? extendedKeyBody(xpub, deps) : deps.deriveBranchBody(xpub, tail.branch);
        if (branchBody.length !== 74) throw new Error("wallet.dat export: branch xpub body must be 74 bytes");
        push(
          concat(streamString("walletdescriptorcache"), id, u32le(cacheKeyExpIndex(stored, index))),
          concat(compactSize(branchBody.length), branchBody),
        );
      });

      if (unit.privateDescriptor) {
        let raw = null;
        let secret = null;
        let der = null;
        let keyHash = null;
        let hashInput = null;
        try {
          let xprv = extractExtendedPrivateKey(unit.privateDescriptor);
          // The key record must map the stored descriptor's root pubkey, or
          // Core's GetExtKey finds no key for it and the wallet cannot sign.
          // A hardened branch step means the stored root is the branch key, so
          // derive the branch xprv; otherwise the account key signs as itself.
          const privateTail = descriptorKeyTail(unit.privateDescriptor, xprv);
          if (privateTail.hardened) xprv = deps.deriveExtendedPrivateChild(xprv, 0x80000000 + privateTail.branch);
          raw = deps.base58Decode(xprv);
          if (raw.length !== 78 || raw[45] !== 0) throw new Error("wallet.dat export: unexpected extended private key payload");
          secret = raw.slice(46, 78);
          const pubkey = deps.publicKeyForPrivate(secret);
          if (pubkey.length !== 33) throw new Error("wallet.dat export: public key must be 33 bytes");
          der = concat(DER_PREFIX, secret, DER_PARAMS, DER_PUBKEY_PREFIX, pubkey);
          if (der.length !== 214) throw new Error("wallet.dat export: DER private key must be 214 bytes");
          hashInput = concat(pubkey, der);
          const innerHash = deps.sha256(hashInput);
          try {
            keyHash = deps.sha256(innerHash);
          } finally {
            innerHash.fill(0);
          }
          hashInput.fill(0);
          hashInput = null;
          push(
            concat(streamString("walletdescriptorkey"), id, compactSize(pubkey.length), pubkey),
            concat(compactSize(der.length), der, keyHash),
          );
        } finally {
          // concat() copied the bytes into the record; wipe every intermediate
          // this block owns, whether the record was built or a check threw.
          if (raw) raw.fill(0);
          if (secret) secret.fill(0);
          if (der) der.fill(0);
          if (keyHash) keyHash.fill(0);
          if (hashInput) hashInput.fill(0);
        }
      }

      if (unit.active !== false) {
        push(
          concat(streamString(unit.internal ? "activeinternalspk" : "activeexternalspk"), u8(unit.type)),
          id,
        );
      }
    return records;
  };

  // Builds the exact key/value rows of the `main` table.
  // deps = { sha256, checksum, base58Decode, deriveBranchBody, publicKeyForPrivate,
  //           canonicalizeDescriptor? } — the optional canonicalizer re-versions
  //           SLIP-132 prefixes to the xpub/tpub Core parses; without it such
  //           keys are refused.
  const buildWalletRecords = (wallet, includePrivate, deps, creationTime) => {
    const network = NETWORKS[wallet?.network];
    if (!network) throw new Error(`wallet.dat export: unknown network ${wallet?.network}`);
    const units = walletDescriptorUnits(wallet, includePrivate);
    if (!units.length) throw new Error("wallet.dat export: no descriptors to export");

    // Fail closed before any record is written: every descriptor, public and
    // private, must be exactly one of the shapes this writer can place, and
    // its wrapper must produce the output type the wallet declared.
    for (const unit of units) {
      assertDescriptorShape(unit.descriptor, "watch-only", deps, unit.type, Boolean(unit.multiKey));
      if (unit.privateDescriptor) assertDescriptorShape(unit.privateDescriptor, "spending", deps, unit.type, Boolean(unit.multiKey));
    }

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
      if (unit.active !== false) {
        const activeKey = `${unit.internal}:${unit.type}`;
        if (seenActive.has(activeKey)) throw new Error("wallet.dat export: duplicate script type across accounts");
        seenActive.add(activeKey);
      }
      records.push(...descriptorUnitRecords(unit, deps, creationTime));
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
    if (wallet?.kind === "msig") {
      const policy = Number.isSafeInteger(wallet.m) && Number.isSafeInteger(wallet.n)
        ? `msig-${wallet.m}of${wallet.n}`
        : "msig";
      return `entropylab-${policy}-watch-only-wallet.dat`;
    }
    const base = includePrivate ? "private-wallet-secrets" : "watch-only-wallet";
    const fingerprint = typeof wallet?.masterFingerprint === "string" && /^[0-9a-fA-F]{8}$/.test(wallet.masterFingerprint)
      ? wallet.masterFingerprint.toLowerCase()
      : null;
    return fingerprint ? `entropylab-${fingerprint}-${base}.dat` : `${base}.dat`;
  };

  const walletDatButtonLabel = (includePrivate = false) => {
    const t = globalThis.hodlT;
    return includePrivate
      ? (t ? t("Download wallet.dat with secrets (xprvs)") : "Download wallet.dat with secrets (xprvs)")
      : (t ? t("Download watch-only wallet.dat") : "Download watch-only wallet.dat");
  };

  return {
    walletDescriptorUnits,
    assertDescriptorShape,
    hasDescriptors,
    hasPrivateDescriptors,
    walletDatSupported,
    bip388Supported,
    descriptorUnitRecords,
    buildWalletRecords,
    buildWalletDat,
    walletDatFilename,
    walletDatButtonLabel,
    // Shared with the Core Wallet tab's verifier and add-descriptor path.
    NETWORKS,
    toCompatForm,
    descriptorKeyTail,
    extendedKeyBody,
    cacheKeyExpIndex,
    assertDescriptorShape,
    FLAG_DISABLE_PRIVATE_KEYS,
  };
})();
