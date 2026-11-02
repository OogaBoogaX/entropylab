
// Bitcoin Core wallet.dat inspection, verification, and extension.
//
// Reads a descriptor-wallet database (the SQLite container Bitcoin Core 23+
// writes) into a decoded document, re-checks every claim in it — descriptor
// checksums, DescriptorIDs, cached branch parents, private-key records,
// network magic against the sync locator — and appends new descriptor units
// through the same record builder the wallet.dat export uses
// (hodlWalletExport.descriptorUnitRecords), so a file the editor writes is
// byte-shaped exactly like one Core loads.
//
// Scope is deliberate: SQLite descriptor wallets only. A legacy Berkeley DB
// wallet fails the container magic check and is reported as unsupported.
// Unknown record types (transactions, scripts, address book entries a used
// wallet accumulates) are preserved byte-for-byte and displayed raw; the
// editor never drops what it does not decode.
//
// The module is pure byte transformation: no I/O, no network traffic, and no
// key derivation of its own (crypto is injected by the caller as deps).
var hodlCoreWallet = (() => {
  const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";
  const RANGE_END = 1000; // Core's default lookahead, same as the export

  // Wallet flags (walletutil.h), matching the export's bit assignments.
  const KNOWN_FLAGS = [
    [1n << 0n, "avoid reuse"],
    [1n << 32n, "disable private keys"],
    [1n << 33n, "blank"],
    [1n << 34n, "descriptors"],
    [1n << 35n, "external signer"],
  ];

  const PRIVATE_KEY = /\b(?:[xyztuv]prv|[YZUV]prv)[1-9A-HJ-NP-Za-km-z]{90,}/;

  // --- what the report may show before "Reveal private data" ----------------
  // The file can come from anywhere, so the report shows a value from it with
  // reveal off only when the reader can tell the value is public; everything
  // else is private DOM until revealed (#1347). Fixed-width integers
  // (versions, flags, times, indexes) stay public.

  // A descriptor is public when the reader can read it with Core's grammar
  // (descriptor.cpp, miniscript.h) and finds only public keys in it: each
  // function where Core allows it, taking Core's arguments in Core's order —
  // a key, a script, a threshold from 1 to its count, a lock time from 1 to
  // 2^31 - 1 — plus an 8-character checksum. A key is an extended public key
  // (a path only after one: steps below 2^31, one <a;b> multipath, a final
  // wildcard) or a hex public key (02/03 compressed; 04 uncompressed only
  // outside segwit), with an optional [8-hex fingerprint/steps] origin. An
  // xprv, a WIF, a raw 32-byte hex key (an x-only key cannot be told from
  // one), raw()/addr()/hash bodies, musig() or anything else makes it
  // private. A bare key (an xpub with or without a path) is public too, as
  // pasted into the add field. Rounds 13 and 14 read each token by its
  // neighbours and reviewers kept finding chunks that passed (GLM:
  // "fingerprints" in a row; Astra: digit chunks as numbers, then numbers
  // where wpkh() takes a key), so the reader now follows the grammar itself.
  // Public forms still carry free bytes by nature (a path step, an xpub's
  // chain code, a pubkey's x): the rule vouches that a value is in a form
  // Core reads as public, not that a crafted file left those bytes alone.
  const ANYWHERE = ["top", "sh", "wsh", "tr"];
  const MINISCRIPT = ["wsh", "tr"];
  // Where each function may sit: at the top, in sh(), in wsh(), or in a tr()
  // leaf (the last two also inside miniscript fragments).
  const DESCRIPTOR_PLACES = new Map([
    ["sh", ["top"]], ["wsh", ["top", "sh"]], ["wpkh", ["top", "sh"]], ["combo", ["top"]],
    ["tr", ["top"]], ["rawtr", ["top"]], ["pk", ANYWHERE], ["pkh", ANYWHERE],
    ["multi", ["top", "sh", "wsh"]], ["sortedmulti", ["top", "sh", "wsh"]], ["multi_a", ["tr"]], ["sortedmulti_a", ["tr"]],
    ["pk_k", MINISCRIPT], ["pk_h", MINISCRIPT], ["older", MINISCRIPT], ["after", MINISCRIPT],
    ["andor", MINISCRIPT], ["and_v", MINISCRIPT], ["and_b", MINISCRIPT], ["and_n", MINISCRIPT],
    ["or_b", MINISCRIPT], ["or_c", MINISCRIPT], ["or_d", MINISCRIPT], ["or_i", MINISCRIPT], ["thresh", MINISCRIPT],
  ]);
  // Not miniscript fragments: never inside one, never after wrappers.
  const OUTER_ONLY = new Set(["sortedmulti", "sortedmulti_a"]);
  const FRAGMENT_PAIRS = new Set(["and_v", "and_b", "and_n", "or_b", "or_c", "or_d", "or_i"]);
  const COUNTED_KEYS = new Set(["multi", "sortedmulti", "multi_a", "sortedmulti_a"]);
  const NUMBER = /0|[1-9]\d{0,9}/y;
  const PATH_STEP = /(?:0|[1-9]\d{0,9})[h']?/y;
  const FINGERPRINT = /[0-9a-fA-F]{8}/y;
  const EXTENDED_PUBLIC = /(?:xpub|ypub|zpub|tpub|upub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{100,108}/y;
  const COMPRESSED_PUBLIC = /0[23][0-9a-fA-F]{64}/y;
  const UNCOMPRESSED_PUBLIC = /04[0-9a-fA-F]{128}/y;
  const WRAPPERS = /[asctdvjnlu]{1,8}:/y;
  const CONSTANT = /[01](?=[,)}]|$)/y;
  const FUNCTION_NAME = /[a-z_]+(?=\()/y;
  const NOT_PUBLIC = Symbol("not public");
  // An extended key is public only when it decodes as one: Base58Check with a
  // valid checksum, 78 bytes, a public version (xpub, ypub, zpub, tpub, upub,
  // vpub, Ypub, Zpub, Upub, Vpub) and a compressed-key prefix. Two WIFs after
  // "xpub" have the shape but not the checksum (K3.1, round 15). Without a
  // decoder no extended key is vouched for.
  const PUBLIC_VERSIONS = new Set([0x0488b21e, 0x049d7cb2, 0x04b24746, 0x043587cf, 0x044a5262, 0x045f1cf6, 0x0295b43f, 0x02aa7ed3, 0x024289ef, 0x02575483]);
  const extendedKeyIsPublic = (text, decode) => {
    if (typeof decode !== "function") return false;
    let raw = null;
    try {
      raw = decode(text);
      if (!(raw instanceof Uint8Array) || raw.length !== 78) return false;
      const version = ((raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]) >>> 0;
      return PUBLIC_VERSIONS.has(version) && (raw[45] === 0x02 || raw[45] === 0x03);
    } catch {
      return false;
    } finally {
      try { raw?.fill(0); } catch {}
    }
  };

  // Throws unless the whole body is a public descriptor or a bare key.
  const readPublicDescriptor = (body, decode) => {
    let at = 0;
    const fail = () => {
      throw NOT_PUBLIC;
    };
    const take = (pattern) => {
      pattern.lastIndex = at;
      const match = pattern.exec(body);
      if (match) at = pattern.lastIndex;
      return match ? match[0] : null;
    };
    const need = (pattern) => take(pattern) ?? fail();
    const skip = (char) => {
      if (body[at] !== char) return false;
      at += 1;
      return true;
    };
    const expect = (char) => skip(char) || fail();
    const step = () => {
      if (Number.parseInt(need(PATH_STEP), 10) > 0x7fffffff) fail();
    };
    const key = (uncompressed) => {
      if (skip("[")) {
        need(FINGERPRINT);
        while (skip("/")) step();
        expect("]");
      }
      const extended = take(EXTENDED_PUBLIC);
      if (extended !== null) {
        if (!extendedKeyIsPublic(extended, decode)) fail();
        let multipath = false;
        while (skip("/")) {
          if (skip("*")) {
            take(/[h']/y);
            return;
          }
          if (skip("<")) {
            if (multipath) fail();
            multipath = true;
            step();
            do {
              expect(";");
              step();
            } while (body[at] === ";");
            expect(">");
          } else {
            step();
          }
        }
        return;
      }
      if (uncompressed && take(UNCOMPRESSED_PUBLIC) !== null) return;
      need(COMPRESSED_PUBLIC);
    };
    // A threshold, then its items: at least one, and no fewer than it.
    const counted = (item) => {
      const threshold = Number(need(NUMBER));
      let count = 0;
      while (skip(",")) {
        item();
        count += 1;
      }
      if (threshold < 1 || threshold > count) fail();
    };
    const script = (place, inner = false) => {
      const miniscript = MINISCRIPT.includes(place);
      if (miniscript && take(WRAPPERS) !== null) inner = true;
      if (miniscript && take(CONSTANT) !== null) return;
      const name = need(FUNCTION_NAME);
      const places = DESCRIPTOR_PLACES.get(name);
      if (!places || !places.includes(place) || (inner && OUTER_ONLY.has(name))) fail();
      const uncompressed = (place === "top" || place === "sh") && name !== "wpkh";
      expect("(");
      if (name === "sh" || name === "wsh") script(name);
      else if (name === "tr") {
        key(false);
        if (skip(",")) tree();
      } else if (COUNTED_KEYS.has(name)) counted(() => key(uncompressed));
      else if (name === "thresh") counted(() => script(place, true));
      else if (name === "older" || name === "after") {
        const time = Number(need(NUMBER));
        if (time < 1 || time > 0x7fffffff) fail();
      } else if (name === "andor" || FRAGMENT_PAIRS.has(name)) {
        script(place, true);
        expect(",");
        script(place, true);
        if (name === "andor") {
          expect(",");
          script(place, true);
        }
      } else key(uncompressed);
      expect(")");
    };
    const tree = () => {
      if (!skip("{")) return script("tr");
      tree();
      expect(",");
      tree();
      expect("}");
    };
    FUNCTION_NAME.lastIndex = 0;
    if (FUNCTION_NAME.test(body)) script("top");
    else key(true);
    if (at !== body.length) fail();
  };
  const isDescriptorFunction = (name) => DESCRIPTOR_PLACES.has(name);
  // decode: a Base58Check decoder that verifies the checksum (the app's
  // base58checkDecode); without one, no extended key counts as public.
  const descriptorIsPublic = (text, decode) => {
    if (typeof text !== "string") return false;
    if (text === "") return true; // an empty field holds nothing
    const hash = text.indexOf("#");
    if (hash >= 0 && !/^[0-9a-z]{8}$/.test(text.slice(hash + 1))) return false;
    try {
      readPublicDescriptor(hash < 0 ? text : text.slice(0, hash), decode);
      return true;
    } catch {
      return false; // not Core's grammar with public keys, or nested too deep to read
    }
  };

  // Record type names Bitcoin Core writes (walletdb.cpp DBKeys). Any other
  // name is whatever the file put in the record key, so it is private.
  const CORE_RECORD_NAMES = new Set([
    "acentry", "activeexternalspk", "activeinternalspk", "bestblock", "bestblock_nomerkle", "ckey", "cscript",
    "defaultkey", "destdata", "flags", "hdchain", "key", "keymeta", "lockedutxo", "minversion", "mkey", "name",
    "orderposnext", "pool", "purpose", "settings", "tx", "version", "walletdescriptor", "walletdescriptorcache",
    "walletdescriptorckey", "walletdescriptorcryptedkey", "walletdescriptorkey", "walletdescriptorlhcache",
    "watchmeta", "watchs", "wkey",
  ]);
  const recordNamePublic = (name) => typeof name === "string" && CORE_RECORD_NAMES.has(name);
  // How the verification lines name a record: never by a name the file chose.
  const recordLabel = (name) => (recordNamePublic(name) ? name : "a record of unrecognized type");

  // A block-locator hash is public when it is the network's genesis block or,
  // off regtest, meets the network's proof-of-work limit (Core's powLimit:
  // 32 zero bits on mainnet and testnet, 00000377ae… on signet). A 32-byte
  // secret meets the mainnet limit by chance about one time in four billion
  // (Astra, round 13: the old 20-bit rule passed one in a million); regtest
  // has no limit to read.
  const POW_LIMITS = {
    mainnet: "00000000ffff0000000000000000000000000000000000000000000000000000",
    testnet: "00000000ffff0000000000000000000000000000000000000000000000000000",
    signet: "00000377ae000000000000000000000000000000000000000000000000000000",
  };
  const locatorHashPublic = (network, hash) => {
    const genesis = hodlWalletExport.NETWORKS[network]?.genesis;
    if (!genesis || typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return false;
    return hash === genesis || (Object.hasOwn(POW_LIMITS, network) && hash <= POW_LIMITS[network]);
  };
  const EXTENDED_PRV_GLOBAL = /((?:xprv|tprv|yprv|uprv|zprv|vprv)[1-9A-HJ-NP-Za-km-z]{90,})/g;
  const EXTENDED_PUB_GLOBAL = /((?:xpub|tpub|ypub|upub|zpub|vpub|Ypub|Zpub|Upub|Vpub)[1-9A-HJ-NP-Za-km-z]{90,})/g;

  const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const bytesEqual = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((byte, i) => byte === b[i]);

  const utf8 = (text) => new TextEncoder().encode(text);
  const decodeText = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);

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
  const u16le = (value) => Uint8Array.of(value & 0xff, (value >>> 8) & 0xff);
  const u32be = (value) => Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
  const compactSize = (length) => {
    if (length < 253) return u8(length);
    if (length <= 0xffff) return concat(u8(253), u16le(length));
    if (length <= 0xffffffff) return concat(u8(254), u32le(length));
    throw new Error("compactSize: length out of range");
  };
  const concat = (...parts) => {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  };
  const streamString = (text) => concat(compactSize(utf8(text).length), utf8(text));

  // --- Bitcoin-serialization readers (CDataStream shapes) ---------------------

  const readCompactSize = (bytes, offset) => {
    if (offset >= bytes.length) throw new Error("truncated CompactSize");
    const first = bytes[offset];
    if (first < 253) return { value: first, next: offset + 1 };
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    if (first === 253) {
      if (offset + 3 > bytes.length) throw new Error("truncated CompactSize");
      return { value: view.getUint16(offset + 1, true), next: offset + 3 };
    }
    if (first === 254) {
      if (offset + 5 > bytes.length) throw new Error("truncated CompactSize");
      return { value: view.getUint32(offset + 1, true), next: offset + 5 };
    }
    if (offset + 9 > bytes.length) throw new Error("truncated CompactSize");
    const wide = view.getBigUint64(offset + 1, true);
    if (wide > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CompactSize too large");
    return { value: Number(wide), next: offset + 9 };
  };

  const readStreamString = (bytes, offset) => {
    const length = readCompactSize(bytes, offset);
    if (length.next + length.value > bytes.length) throw new Error("truncated string");
    return { text: decodeText(bytes.slice(length.next, length.next + length.value)), next: length.next + length.value };
  };

  const readU32le = (bytes, offset) => {
    if (offset + 4 > bytes.length) throw new Error("truncated u32");
    return { value: new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getUint32(offset, true), next: offset + 4 };
  };
  const readU64le = (bytes, offset) => {
    if (offset + 8 > bytes.length) throw new Error("truncated u64");
    return { value: new DataView(bytes.buffer, bytes.byteOffset, bytes.length).getBigUint64(offset, true), next: offset + 8 };
  };

  // --- record decoding --------------------------------------------------------

  // A record key is a serialized string name followed by a type-specific
  // tail; a record value follows the shapes documented in wallet-export.js.
  const decodeKeyName = (key) => {
    try {
      const name = readStreamString(key, 0);
      return { name: name.text, tail: key.slice(name.next) };
    } catch {
      return { name: null, tail: new Uint8Array(0) };
    }
  };

  const decodeLocator = (value) => {
    const version = readU32le(value, 0);
    const count = readCompactSize(value, version.next);
    const hashes = [];
    let offset = count.next;
    for (let i = 0; i < count.value; i++) {
      if (offset + 32 > value.length) throw new Error("truncated block locator");
      hashes.push(bytesToHex(value.slice(offset, offset + 32).reverse())); // display byte order
      offset += 32;
    }
    if (offset !== value.length) throw new Error("trailing bytes after block locator");
    return { version: version.value, hashes };
  };

  const decodeDescriptorValue = (value) => {
    const descriptor = readStreamString(value, 0);
    const creationTime = readU64le(value, descriptor.next);
    const nextIndex = readU32le(value, creationTime.next);
    const rangeStart = readU32le(value, nextIndex.next);
    const rangeEnd = readU32le(value, rangeStart.next);
    if (rangeEnd.next !== value.length) throw new Error("trailing bytes after walletdescriptor value");
    return {
      descriptor: descriptor.text,
      creationTime: Number(creationTime.value),
      nextIndex: nextIndex.value,
      rangeStart: rangeStart.value,
      rangeEnd: rangeEnd.value,
    };
  };

  const decodeCacheValue = (value) => {
    const length = readCompactSize(value, 0);
    if (length.next + length.value !== value.length) throw new Error("walletdescriptorcache value length mismatch");
    return { body: value.slice(length.next) };
  };

  const decodeDescriptorKeyValue = (value) => {
    const length = readCompactSize(value, 0);
    if (length.next + length.value + 32 !== value.length) throw new Error("walletdescriptorkey value length mismatch");
    return { der: value.slice(length.next, length.next + length.value), keyHash: value.slice(length.next + length.value) };
  };

  const networkForApplicationId = (applicationId) => {
    for (const [name, network] of Object.entries(hodlWalletExport.NETWORKS)) {
      if (network.applicationId === applicationId) return name;
    }
    return null;
  };

  // The OutputType a descriptor's wrapper produces, from its parsed function
  // chain; null when the shape is outside the ones the export knows.
  const descriptorOutputType = (functions) => {
    // A multisig inside a wrapper takes the wrapper's type (sh(multi) is
    // legacy, wsh(sortedmulti) is bech32), so the multi function is dropped.
    const chain = functions.filter((name) => !/^(?:sorted)?multi(?:_a)?$/.test(name)).join(":");
    if (chain === "pkh" || (chain === "sh" && functions.length > 1)) return 0;
    if (chain === "sh:wpkh" || chain === "sh:wsh") return 1;
    if (chain === "wpkh" || chain === "wsh") return 2;
    if (chain === "tr") return 3;
    return null;
  };

  const flagNames = (flags) => {
    const names = [];
    let rest = flags;
    for (const [bit, name] of KNOWN_FLAGS) {
      if ((flags & bit) !== 0n) { names.push(name); rest &= ~bit; }
    }
    if (rest !== 0n) names.push(`unknown bits 0x${rest.toString(16)}`);
    return names;
  };

  // The leading chain of descriptor functions ("wpkh", "sh(wsh",
  // "tr"…) for display; parsing stops at the first key expression.
  const descriptorFunctions = (descriptor) => {
    const body = descriptor.split("#")[0];
    const names = [];
    let index = 0;
    let match;
    const opener = /^([a-z_]+)\(/;
    while ((match = opener.exec(body.slice(index)))) {
      names.push(match[1]);
      index += match[0].length;
    }
    return names;
  };

  // Parses a wallet.dat file into the editable document. Throws on anything
  // that is not an SQLite descriptor wallet; per-record decode failures are
  // collected as problem records instead so one corrupt record cannot hide
  // the rest of the wallet.
  const parseWalletDat = (bytes) => {
    const db = hodlSqliteReader.readDatabase(bytes);
    const table = db.schema.find((entry) => entry.type === "table" && entry.name === "main");
    if (!table) throw new Error("Not a Bitcoin Core wallet: the database has no `main` table.");
    const rawRows = db.readTable("main").map((columns) => {
      if (columns.length !== 2 || !(columns[0] instanceof Uint8Array) || !(columns[1] instanceof Uint8Array)) {
        throw new Error("Not a Bitcoin Core wallet: the `main` table is not key/value BLOBs.");
      }
      return [columns[0], columns[1]];
    });

    const doc = {
      pageSize: db.pageSize,
      applicationId: db.applicationId,
      userVersion: db.userVersion,
      readVersion: db.readVersion, // 2 = WAL journal mode
      network: networkForApplicationId(db.applicationId),
      rows: rawRows,
      records: [],
      descriptors: [],
      others: [],
      meta: {},
    };
    const byDescriptorId = new Map();

    rawRows.forEach(([key, value], index) => {
      const { name, tail } = decodeKeyName(key);
      const record = { index, name, key, value, error: null };
      try {
        switch (name) {
          case "version":
            if (tail.length) throw new Error("unexpected key tail");
            doc.meta.version = readU32le(value, 0).value;
            break;
          case "minversion":
            if (tail.length) throw new Error("unexpected key tail");
            doc.meta.minversion = readU32le(value, 0).value;
            break;
          case "flags":
            if (tail.length) throw new Error("unexpected key tail");
            doc.meta.flags = readU64le(value, 0).value;
            break;
          case "bestblock":
            if (tail.length) throw new Error("unexpected key tail");
            doc.meta.bestBlock = decodeLocator(value);
            break;
          case "bestblock_nomerkle":
            if (tail.length) throw new Error("unexpected key tail");
            doc.meta.bestBlockNoMerkle = decodeLocator(value);
            break;
          case "walletdescriptor": {
            if (tail.length !== 32) throw new Error("walletdescriptor key must end in a 32-byte id");
            const decoded = decodeDescriptorValue(value);
            const entry = {
              id: bytesToHex(tail),
              ...decoded,
              functions: descriptorFunctions(decoded.descriptor),
              caches: [],
              keys: [],
              active: null,
              actives: [],
            };
            byDescriptorId.set(entry.id, entry);
            doc.descriptors.push(entry);
            break;
          }
          case "walletdescriptorcache": {
            if (tail.length !== 36) throw new Error("walletdescriptorcache key must end in id + key index");
            const keyIndex = readU32le(tail, 32).value;
            record.cacheFor = bytesToHex(tail.slice(0, 32));
            record.cacheKeyIndex = keyIndex;
            record.cacheBody = decodeCacheValue(value).body;
            break;
          }
          case "walletdescriptorkey": {
            const pubkeyLength = readCompactSize(tail, 32);
            if (pubkeyLength.next + pubkeyLength.value !== tail.length) throw new Error("walletdescriptorkey key length mismatch");
            record.keyFor = bytesToHex(tail.slice(0, 32));
            record.keyPubkey = tail.slice(pubkeyLength.next);
            record.keyMaterial = decodeDescriptorKeyValue(value);
            break;
          }
          case "activeexternalspk":
          case "activeinternalspk": {
            if (tail.length !== 1) throw new Error("active spk key must end in a one-byte output type");
            if (value.length !== 32) throw new Error("active spk value must be a 32-byte descriptor id");
            const active = { internal: name === "activeinternalspk", type: tail[0], id: bytesToHex(value) };
            (doc.meta.actives ??= []).push(active);
            break;
          }
          default:
            record.other = true;
        }
      } catch (error) {
        record.error = error.message || String(error);
        record.other = true;
      }
      doc.records.push(record);
      if (record.other) doc.others.push(record);
    });

    // Attach caches and key records to their descriptors (record order is
    // rowid order, which need not group them).
    for (const record of doc.records) {
      if (record.cacheFor) {
        const entry = byDescriptorId.get(record.cacheFor);
        if (entry) entry.caches.push({ keyExpIndex: record.cacheKeyIndex, body: record.cacheBody });
        else record.orphan = true;
      }
      if (record.keyFor) {
        const entry = byDescriptorId.get(record.keyFor);
        if (entry) entry.keys.push({ pubkey: record.keyPubkey, der: record.keyMaterial.der, keyHash: record.keyMaterial.keyHash });
        else record.orphan = true;
      }
    }
    for (const active of doc.meta.actives ?? []) {
      const entry = byDescriptorId.get(active.id);
      // Every pointer is kept: Core files both chains, so a descriptor
      // named twice must have each record checked, not only the last.
      if (entry) {
        entry.active ??= active;
        entry.actives.push(active);
      }
    }
    return doc;
  };

  // --- verification -----------------------------------------------------------
  // deps = { sha256, checksum, base58Decode, deriveBranchBody, publicKeyForPrivate }
  // Returns [{ tone: "ok" | "warn" | "bad", label, detail }].

  const check = (tone, label, detail) => ({ tone, label, detail });

  const verifyWalletDoc = (doc, deps) => {
    const checks = [];
    const NETWORKS = hodlWalletExport.NETWORKS;

    if (doc.network) {
      checks.push(check("ok", "Network magic", `${doc.network} (application_id 0x${doc.applicationId.toString(16).padStart(8, "0")})`));
    } else {
      checks.push(check("bad", "Network magic", `application_id 0x${doc.applicationId.toString(16).padStart(8, "0")} is not a Bitcoin network`));
    }
    if (doc.readVersion === 2) {
      checks.push(check("warn", "Journal mode", "WAL-mode database: changes still in the -wal sidecar file are not in this copy"));
    }

    const { version, minversion, flags } = doc.meta;
    if (version === undefined) checks.push(check("bad", "Client version", "no version record"));
    else if (minversion === undefined) checks.push(check("warn", "Client version", `version ${version}, no minversion record`));
    else if (version < minversion) checks.push(check("bad", "Client version", `version ${version} is below minversion ${minversion} — no Core release would write this`));
    else checks.push(check("ok", "Client version", `version ${version}, minversion ${minversion}`));

    if (flags === undefined) {
      checks.push(check("bad", "Wallet flags", "no flags record"));
    } else {
      const names = flagNames(flags);
      const hasDescriptors = (flags & (1n << 34n)) !== 0n;
      checks.push(hasDescriptors
        ? check("ok", "Wallet flags", names.join(", ") || "none")
        : check("bad", "Wallet flags", `descriptors flag not set (${names.join(", ") || "none"}) — not a descriptor wallet`));
    }

    if (doc.meta.bestBlockNoMerkle && doc.network) {
      const genesis = NETWORKS[doc.network].genesis;
      const hashes = doc.meta.bestBlockNoMerkle.hashes;
      if (!hashes.length) checks.push(check("warn", "Chain sync", "empty bestblock_nomerkle locator"));
      else if (hashes[hashes.length - 1] === genesis) checks.push(check("ok", "Chain sync", hashes.length === 1 ? "fresh wallet sitting on the genesis block" : `synced; locator ends at the ${doc.network} genesis block`));
      else checks.push(check("bad", "Chain sync", `locator does not end at the ${doc.network} genesis block — the file mixes chains`));
    }

    const seenKeys = new Set();
    let duplicates = 0;
    for (const [key] of doc.rows) {
      const hex = bytesToHex(key);
      if (seenKeys.has(hex)) duplicates++;
      seenKeys.add(hex);
    }
    if (duplicates) checks.push(check("bad", "Record keys", `${duplicates} duplicate key(s) — Core would reject the database`));

    for (const record of doc.records) {
      if (record.error) checks.push(check("bad", "Undecodable record", `${record.name == null ? "(no name)" : recordLabel(record.name)}: ${record.error}`));
      if (record.orphan) checks.push(check("bad", "Orphan record", `${recordLabel(record.name)} names a descriptor id that has no walletdescriptor record`));
    }

    const byId = new Map(doc.descriptors.map((entry) => [entry.id, entry]));
    if (byId.size !== doc.descriptors.length) {
      checks.push(check("bad", "Descriptor ids", `${doc.descriptors.length - byId.size} duplicate walletdescriptor id(s) — Core resolves one id to one descriptor`));
    }
    const activeKeys = new Set();
    for (const active of doc.meta.actives ?? []) {
      const activeKey = `${active.internal}:${active.type}`;
      if (activeKeys.has(activeKey)) checks.push(check("bad", "Active scriptPubKey", `more than one ${active.internal ? "internal" : "external"} record for type ${active.type}`));
      activeKeys.add(activeKey);
      if (byId.has(active.id)) continue;
      checks.push(check("bad", "Active scriptPubKey", `${active.internal ? "internal" : "external"} type ${active.type} points at a missing descriptor`));
    }

    for (const [index, entry] of doc.descriptors.entries()) {
      const text = entry.descriptor;
      const hash = text.lastIndexOf("#");
      let checksumOk = false;
      if (hash >= 0) {
        try {
          checksumOk = deps.checksum(text.slice(0, hash)) === text.slice(hash + 1);
        } catch {
          checksumOk = false;
        }
      }
      // The report shows a descriptor with reveal off only in a public form
      // under a checksum that matches (Core writes one; a free suffix could
      // carry eight characters of anything, DeepSeek round 13). Any other
      // descriptor is named by its place in the report, never by its text,
      // because these lines show while the descriptor itself is redacted.
      if (checksumOk && descriptorIsPublic(text, deps.base58Decode)) entry.shownPublic = true;
      const label = entry.shownPublic !== true ? `#${index + 1}` : text.length > 24 ? `${text.slice(0, 21)}…` : text;
      if (hash < 0) {
        checks.push(check("bad", `Descriptor ${label}`, "no checksum suffix"));
      } else {
        const body = text.slice(0, hash);
        checks.push(checksumOk
          ? check("ok", `Descriptor checksum`, `${label} checksum matches`)
          : check("bad", `Descriptor checksum`, `${label} checksum mismatch`));
        // DescriptorID: sha256 of the compat form (' instead of h) with its
        // checksum — the id Core recomputes at load (DBErrors::CORRUPT on a
        // mismatch).
        let id = null;
        try {
          const compatBody = hodlWalletExport.toCompatForm(body);
          // The descriptor can carry a key (a crafted file): the UTF-8 copy
          // hashed here is zeroed once hashed.
          const idBytes = utf8(`${compatBody}#${deps.checksum(compatBody)}`);
          // Zeroed on every exit, a hash that throws included (K3.1, round 15).
          try {
            id = bytesToHex(deps.sha256(idBytes));
          } finally {
            idBytes.fill(0);
          }
        } catch {
          id = null; // the descriptor has a character Core's charset lacks
        }
        checks.push(id === null
          ? check("bad", `Descriptor id`, `${label} id cannot be recomputed from its text`)
          : id === entry.id
            ? (entry.idVerified = true, check("ok", `Descriptor id`, `${label} id matches its recomputed DescriptorID`))
            : check("bad", `Descriptor id`, `${label} record key is not the DescriptorID Core would compute`));
      }

      if (!(entry.rangeStart <= entry.rangeEnd && entry.nextIndex >= entry.rangeStart && entry.nextIndex <= entry.rangeEnd + 1)) {
        checks.push(check("bad", `Descriptor range`, `${label} range [${entry.rangeStart}, ${entry.rangeEnd}] with next index ${entry.nextIndex} is incoherent`));
      }

      // The active record's chain and output type must name this descriptor:
      // Core files it under that (internal, type) key, so a swapped value
      // would make it watch a chain or script type it does not describe.
      // A descriptor watches one chain of one type, so a second pointer at it
      // always files it somewhere it does not describe.
      const actives = entry.actives ?? [];
      if (actives.length > 1) {
        checks.push(check("bad", `Active scriptPubKey`, `${label} is named by ${actives.length} active records — a descriptor is the active one for a single chain and type`));
      }
      for (const active of actives) {
        const expectedType = descriptorOutputType(entry.functions);
        if (expectedType !== null && active.type !== expectedType) {
          checks.push(check("bad", `Active scriptPubKey`, `${label} is marked type ${active.type} but its wrapper is type ${expectedType}`));
        }
        const change = /\/1['hH]?\/\*\)/.test(entry.descriptor);
        if (active.internal !== change) {
          checks.push(check("bad", `Active scriptPubKey`, `${label} is filed as ${active.internal ? "internal" : "external"} but its branch is ${change ? "change" : "receive"}`));
        }
      }

      // Every pubkey provider must have a cached parent: the branch child of
      // the account key (or the root key itself for a hardened branch), at
      // Core's key_exp_index.
      EXTENDED_PUB_GLOBAL.lastIndex = 0;
      const pubs = [];
      let match;
      while ((match = EXTENDED_PUB_GLOBAL.exec(text))) pubs.push(match[1]);
      // Core decodes extended keys with the chain's own prefixes (xpub on
      // mainnet, tpub on every test chain); any other version fails at load.
      if (doc.network && pubs.length) {
        const prefix = doc.network === "mainnet" ? "xpub" : "tpub";
        const foreign = pubs.filter((key) => !key.startsWith(prefix)).length;
        checks.push(foreign
          ? check("bad", `Descriptor network`, `${label} has ${foreign} extended key(s) that are not ${prefix} — Bitcoin Core would not load it on ${doc.network}`)
          : check("ok", `Descriptor network`, `${label} keys are ${prefix}, matching ${doc.network}`));
      }
      pubs.forEach((xpub, index) => {
        let expected = null;
        try {
          const body = text.split("#")[0];
          const tail = hodlWalletExport.descriptorKeyTail(body, xpub, pubs.slice(0, index).filter((key) => key === xpub).length);
          expected = tail.branch === null
            ? hodlWalletExport.extendedKeyBody(xpub, deps)
            : deps.deriveBranchBody(xpub, tail.branch);
        } catch {
          expected = null; // shape the export does not support either; reported as unverifiable below
        }
        const keyExpIndex = hodlWalletExport.cacheKeyExpIndex(text.split("#")[0], index);
        const cache = entry.caches.find((candidate) => candidate.keyExpIndex === keyExpIndex);
        if (!cache) {
          checks.push(check("bad", `Descriptor cache`, `${label} has no cache record for provider ${keyExpIndex} — Core cannot derive its addresses`));
        } else if (cache.body.length !== 74) {
          checks.push(check("bad", `Descriptor cache`, `${label} cache ${keyExpIndex} is ${cache.body.length} bytes, not a 74-byte serialized node`));
        } else if (expected && !bytesEqual(cache.body, expected)) {
          checks.push(check("bad", `Descriptor cache`, `${label} cache ${keyExpIndex} is not the descriptor's wildcard parent — Core would watch the wrong subtree`));
        } else if (expected) {
          // The report shows a cache body as public only on this verdict.
          cache.verified = true;
          checks.push(check("ok", `Descriptor cache`, `${label} cache ${keyExpIndex} matches the recomputed wildcard parent`));
        } else {
          checks.push(check("warn", `Descriptor cache`, `${label} cache ${keyExpIndex} is present but its descriptor shape is outside what this tool re-derives`));
        }
      });

      for (const keyRecord of entry.keys) {
        // Bitcoin Core CPrivKey DER form: 3081d3 020101 0420 <32-byte secret> …
        const secret = keyRecord.der.slice(8, 40);
        try {
          if (keyRecord.der.length !== 214 || keyRecord.der[0] !== 0x30 || keyRecord.der[6] !== 0x04 || keyRecord.der[7] !== 0x20) {
            checks.push(check("bad", `Private key record`, `${label} key record is not the expected DER private key`));
            continue;
          }
          let pubkey;
          try {
            pubkey = deps.publicKeyForPrivate(secret);
          } catch {
            checks.push(check("bad", `Private key record`, `${label} key record secret is not a valid secp256k1 private key`));
            continue;
          }
          const preimage = concat(keyRecord.pubkey, keyRecord.der);
          const hash = deps.sha256(deps.sha256(preimage));
          preimage.fill(0);
          if (!bytesEqual(pubkey, keyRecord.pubkey)) {
            checks.push(check("bad", `Private key record`, `${label} private key does not match its record pubkey`));
          } else if (!bytesEqual(hash, keyRecord.keyHash)) {
            checks.push(check("bad", `Private key record`, `${label} key record hash mismatch`));
          } else {
            // The report shows a key record's pubkey as public only on this verdict.
            keyRecord.verified = true;
            checks.push(check("ok", `Private key record`, `${label} private key matches its pubkey and record hash`));
          }
        } finally {
          secret.fill(0); // best-effort: the copy, not the parsed record
        }
      }
    }
    return checks;
  };

  // --- extension --------------------------------------------------------------

  // Turns a pasted descriptor into an export unit. Watch-only descriptors are
  // canonicalized (SLIP-132 rewritten to xpub/tpub, checksum appended); a
  // descriptor carrying an extended private key is stored neutered plus a
  // walletdescriptorkey record, exactly like the export's private path.
  // deps adds canonicalizeDescriptor and neuterExtendedKey to the record deps.
  const unitFromDescriptor = (text, { internal = false, active = false } = {}, deps) => {
    const trimmed = String(text ?? "").trim();
    if (!trimmed) throw new Error("Paste a descriptor first.");
    if (!trimmed.includes("*")) throw new Error("Only ranged descriptors (with a /* wildcard) can go into a wallet.");
    if (typeof deps.canonicalizeDescriptor !== "function") throw new Error("Descriptor canonicalization is unavailable.");
    if (typeof deps.neuterExtendedKey !== "function") throw new Error("Extended-key neutering is unavailable.");

    let privateText = null;
    let publicText = trimmed;
    if (PRIVATE_KEY.test(trimmed)) {
      const privateCount = (trimmed.match(EXTENDED_PRV_GLOBAL) || []).length;
      if (privateCount > 1) throw new Error("Multisig descriptors with private keys are not supported; import the watch-only form.");
      // The pasted checksum covers the private body; validate it, then drop
      // it — canonicalization appends the checksum of the neutered form.
      const hash = trimmed.lastIndexOf("#");
      if (hash >= 0 && deps.checksum(trimmed.slice(0, hash)) !== trimmed.slice(hash + 1)) {
        throw new Error("Descriptor checksum does not match.");
      }
      privateText = trimmed;
      publicText = (hash >= 0 ? trimmed.slice(0, hash) : trimmed).replace(EXTENDED_PRV_GLOBAL, (key) => deps.neuterExtendedKey(key));
    }
    const stored = deps.canonicalizeDescriptor(publicText);
    const body = stored.split("#")[0];

    // OutputType (wallet): pkh=0, sh(wpkh)=1, wpkh=2, tr=3; multisig wrappers
    // land on the same enum (see the export's OUTPUT_TYPES tables).
    let type;
    if (/^pkh\(/.test(body)) type = 0;
    else if (/^sh\(wpkh\(/.test(body)) type = 1;
    else if (/^wpkh\(/.test(body)) type = 2;
    else if (/^tr\(/.test(body)) type = 3;
    else if (/^sh\(wsh\(/.test(body)) type = 1;
    else if (/^wsh\(/.test(body)) type = 2;
    else if (/^sh\(/.test(body) || /^multi\(/.test(body)) type = 0;
    else throw new Error("Unsupported descriptor function for a Core wallet (pkh, sh, wpkh, wsh, tr, multi).");

    EXTENDED_PUB_GLOBAL.lastIndex = 0;
    // A multisig *wrapper* with one key is still a multisig shape (Core's
    // wallet kind); the record builder must read it through the multi path
    // even though there is only one provider.
    const multiKey = /\b(?:sortedmulti|multi|multi_a)\(/.test(body)
      || (body.match(EXTENDED_PUB_GLOBAL) || []).length > 1;
    // The export's own shape guard: it refuses what Core would parse
    // differently than the stored text (a leading-zero path step, a step at
    // 2^31 or deeper) and every wrapper the record builder cannot place.
    hodlWalletExport.assertDescriptorShape(stored, "watch-only", deps, type, multiKey);
    if (privateText) hodlWalletExport.assertDescriptorShape(privateText, "spending", deps, type, multiKey);
    return {
      type,
      internal,
      active,
      descriptor: stored,
      privateDescriptor: privateText,
      multiKey,
      nextIndex: 0,
      rangeStart: 0,
      rangeEnd: RANGE_END,
    };
  };

  // The rows of the wallet with one more descriptor unit in it. Mirrors what
  // Core's importdescriptors does: a duplicate descriptor id is an error, an
  // active unit replaces the previous active record for its output type, and
  // private material cannot go into a disable-private-keys wallet.
  const appendDescriptorRows = (doc, unit, deps, creationTime) => {
    const rows = [...doc.rows];
    if (unit.privateDescriptor && doc.meta.flags !== undefined && (doc.meta.flags & hodlWalletExport.FLAG_DISABLE_PRIVATE_KEYS) !== 0n) {
      throw new Error("This wallet is flagged disable-private-keys; Bitcoin Core would refuse a private descriptor here too.");
    }
    if (unit.privateDescriptor && isEncrypted(doc)) {
      throw new Error("This wallet is encrypted; the added private descriptor would sit in the file unencrypted. Add its watch-only form instead.");
    }
    // Core decodes extended keys with the chain's own prefixes (xpub/xprv on
    // mainnet, tpub/tprv on every test chain): a foreign key fails at load.
    if (!doc.network) throw new Error("This wallet's network is unknown, so no descriptor key can be checked against it.");
    const [pub, prv] = doc.network === "mainnet" ? ["xpub", "xprv"] : ["tpub", "tprv"];
    const keys = [...(unit.descriptor.match(EXTENDED_PUB_GLOBAL) ?? []), ...(unit.privateDescriptor?.match(EXTENDED_PRV_GLOBAL) ?? [])];
    if (keys.some((key) => !key.startsWith(pub) && !key.startsWith(prv))) {
      throw new Error(`That descriptor's keys are not ${pub}/${prv}, the ${doc.network} network's; Bitcoin Core would not load the wallet.`);
    }
    const unitRows = hodlWalletExport.descriptorUnitRecords(unit, deps, creationTime);
    const descriptorKey = bytesToHex(unitRows[0][0]);
    if (rows.some(([key]) => bytesToHex(key) === descriptorKey)) {
      throw new Error("That descriptor is already in this wallet.");
    }
    let kept = rows;
    if (unit.active) {
      // unitRows ends with the new active record; drop any existing active
      // record for the same (internal, output type) so it does not duplicate.
      const prefix = streamString(unit.internal ? "activeinternalspk" : "activeexternalspk");
      const activeKey = concat(prefix, u8(unit.type));
      const activeHex = bytesToHex(activeKey);
      kept = rows.filter(([key]) => bytesToHex(key) !== activeHex);
    }
    return [...kept, ...unitRows];
  };

  // Rebuilds the database from (possibly extended) rows, keeping the chain
  // identity in the application id.
  const buildWalletDat = (doc, rows = doc.rows) =>
    hodlSqliteWriter.createDatabase({
      applicationId: doc.applicationId,
      tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows }],
    });

  // --- Key Station import -----------------------------------------------------
  //
  // A signing wallet.dat carries, per private descriptor, the raw secret of
  // the extended key embedded in that descriptor's neutered public form. The
  // embedded key itself publishes the node's whole public bookkeeping — depth,
  // parent fingerprint, child number, chain code, pubkey — so the extended
  // private key can be reassembled exactly, without inventing anything: for a
  // wallet Core generated, the node is the BIP32 root (the stored secret is
  // the 32-byte key Core fed to CExtKey::SetSeed); for an imported account
  // descriptor, it is the account xprv. Both shapes are Key Station inputs.
  //
  // The contract is proof, not trust: the secret is imported only when
  // pubkey(secret) == key record pubkey == the embedded extended key's own
  // pubkey field, from a single-key descriptor of a known script type, and the
  // node sits at BIP32 depth 0 (root) or 3 (account). Anything else is
  // refused with a reason, never guessed at.
  //
  // deps: { base58Decode, base58Encode, publicKeyForPrivate, hash160 }
  const XPRV_VERSION = { mainnet: 0x0488ade4, testnet: 0x04358394 }; // xprv / tprv
  const IMPORT_SCRIPTS = { pkh: "bip44", "sh:wpkh": "bip49", wpkh: "bip84", tr: "bip86" };

  const isEncrypted = (doc) => doc.records.some((record) => record.name === "walletdescriptorcryptedkey");

  const IMPORT_PURPOSE = { bip44: 44, bip49: 49, bip84: 84, bip86: 86 };

  // Key Station derives at its own standard path. Import only when that path
  // is exactly the one the descriptor watches, otherwise the fingerprint
  // would still match while every derived address differs.
  //   depth 0 (key is the master): /<purpose>h/<coin>h/0h/<0|1>/* and, if
  //     an origin is present, [<8-hex master fingerprint>] only.
  //   depth 3 (key is an account): /<0|1>/* and, if an origin is present,
  //     [<8-hex>/<purpose>h/<coin>h/<account>h] with purpose and coin matching.
  // Returns { branch, account, originFingerprint }, or null when the path is
  // not importable. The origin's fingerprint is the descriptor's claim about
  // the master; an account key cannot prove it, so it is reported, not checked.
  const importBranch = (entry, pub, script, depth, family) => {
    const body = entry.descriptor.split("#")[0];
    const at = body.indexOf(pub);
    if (at < 0) return null;
    const prefix = body.slice(0, at), tail = body.slice(at + pub.length);
    const coin = family === "mainnet" ? "0" : "1";
    const origin = /\[([^\]]*)\]$/.exec(prefix)?.[1] ?? null;
    let account = 0;
    if (origin !== null) {
      const parts = origin.split("/");
      if (!/^[0-9a-fA-F]{8}$/.test(parts[0])) return null;
      if (depth === 0 && parts.length !== 1) return null;
      if (depth === 3) {
        if (parts.length !== 4 || !parts.slice(1).every((step) => /^\d+['hH]$/.test(step))) return null;
        if (Number(parts[1].slice(0, -1)) !== IMPORT_PURPOSE[script]) return null;
        if (Number(parts[2].slice(0, -1)) !== Number(coin)) return null;
        account = Number(parts[3].slice(0, -1));
      }
    }
    const match = depth === 0
      ? new RegExp(`^/${IMPORT_PURPOSE[script]}['hH]/${coin}['hH]/0['hH]/([01])/\\*\\)`).exec(tail)
      : /^\/([01])\/\*\)/.exec(tail);
    if (!match) return null;
    return { branch: match[1], account, originFingerprint: origin === null ? null : origin.split("/")[0].toLowerCase() };
  };

  const stationImports = (doc, deps) => {
    const none = (reason) => ({ reason, skipped: 0, imports: [] });
    if (isEncrypted(doc)) return none("encrypted");
    const signers = doc.descriptors.filter((entry) => entry.keys.length);
    if (!signers.length) return none("no-private-keys");
    // The four chains share two extended-key families: mainnet xprv/xpub, and
    // tprv/tpub for every test chain (same split as hodlWalletExport).
    const family = doc.network === "mainnet" ? "mainnet" : doc.network && hodlWalletExport.NETWORKS[doc.network] ? "testnet" : null;
    if (!family) return none("unknown-network");
    const version = XPRV_VERSION[family];

    // One import per (node, script type); a Core-generated wallet collapses
    // to a single root item because every descriptor names the same node.
    const items = new Map();
    let skipped = 0;
    for (const entry of signers) {
      const script = IMPORT_SCRIPTS[entry.functions.join(":")];
      EXTENDED_PUB_GLOBAL.lastIndex = 0;
      const pubs = entry.descriptor.match(EXTENDED_PUB_GLOBAL) || [];
      // tr(NUMS, …) is a script-path output: the account key is a leaf, so a
      // key-path BIP86 derivation would produce different addresses.
      const scriptPath = script === "bip86" && /^tr\([0-9a-fA-F]{64},/.test(entry.descriptor.split("#")[0]);
      if (!script || pubs.length !== 1 || scriptPath) {
        skipped += entry.keys.length;
        continue;
      }
      let raw;
      try {
        raw = deps.base58Decode(pubs[0]);
      } catch {
        skipped += entry.keys.length;
        continue;
      }
      if (raw.length !== 78) {
        skipped += entry.keys.length;
        continue;
      }
      const depth = raw[4];
      if (depth !== 0 && depth !== 3) {
        skipped += entry.keys.length;
        continue;
      }
      // The branch, and that the descriptor's path is the one Key Station
      // derives (the node is proven above, the path is not).
      const path = importBranch(entry, pubs[0], script, depth, family);
      if (!path) {
        skipped += entry.keys.length;
        continue;
      }
      for (const keyRecord of entry.keys) {
        // Bitcoin Core CPrivKey DER form, checked before the secret is read.
        const der = keyRecord.der;
        if (der.length !== 214 || der[0] !== 0x30 || der[6] !== 0x04 || der[7] !== 0x20) {
          skipped++;
          continue;
        }
        const secret = der.slice(8, 40);
        let body = null;
        try {
          // The two-way node check: the secret's pubkey is the record's pubkey,
          // and that pubkey is the embedded extended key's own.
          let secretPubkey;
          try {
            secretPubkey = deps.publicKeyForPrivate(secret);
          } catch {
            skipped++;
            continue;
          }
          if (!bytesEqual(secretPubkey, keyRecord.pubkey) || !bytesEqual(keyRecord.pubkey, raw.slice(45, 78))) {
            skipped++;
            continue;
          }
          body = concat(u32be(version), raw.slice(4, 45), u8(0), secret);
          const xprv = deps.base58Encode(body);
          // Root items ignore the script (a root derives every type); account
          // items keep one import per (account key, script type).
          const key = depth === 0 ? `0::${bytesToHex(raw.slice(4))}` : `3:${script}:${bytesToHex(raw.slice(4))}`;
          const item = items.get(key) ?? {
            xprv,
            fingerprint: bytesToHex(deps.hash160(secretPubkey).subarray(0, 4)),
            kind: depth === 0 ? "root" : "account",
            script: depth === 0 ? null : script,
            // The wallet's own chain (regtest renders bcrt1…, not just the
            // tprv family) and what the origin names.
            network: doc.network,
            account: path.account,
            originFingerprint: path.originFingerprint,
            internal: false,
            external: false,
          };
          if (path.branch === "1") item.internal = true;
          else item.external = true;
          if (!items.has(key)) items.set(key, item);
        } finally {
          // Best-effort: the copies of the secret and the xprv bytes.
          secret.fill(0);
          body?.fill(0);
        }
      }
    }
    const imports = [...items.values()];
    return { reason: imports.length ? null : "unsupported-key-records", skipped, imports };
  };

  return {
    parseWalletDat,
    verifyWalletDoc,
    unitFromDescriptor,
    appendDescriptorRows,
    buildWalletDat,
    stationImports,
    flagNames,
    descriptorFunctions,
    bytesToHex,
    descriptorIsPublic,
    isDescriptorFunction,
    recordNamePublic,
    locatorHashPublic,
  };
})();
