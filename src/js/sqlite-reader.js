
// Minimal SQLite 3 database file reader.
//
// Reads back the format hodlSqliteWriter produces — the container Bitcoin
// Core uses for descriptor-wallet wallet.dat files. It supports exactly what
// reading such files needs and nothing more:
//
//   - 512..65536-byte pages, UTF-8, rollback-journal or WAL read versions
//     (a WAL-mode file is readable but may miss un-checkpointed changes;
//     the caller surfaces that).
//   - Table b-trees of any depth (interior pages recurse), with overflow
//     page chains for records too large to sit inline on a leaf page.
//   - Record decoding for every serial type SQLite writes (null, integers,
//     float, 0/1 constants, BLOB, TEXT).
//
// Index b-trees are not walked (the `main` table's rows are read from its
// own b-tree; sqlite_autoindex only duplicates them). Freelist pages are
// ignored. The reader performs no I/O and no network traffic; every
// structural violation throws instead of guessing.
var hodlSqliteReader = (() => {
  const MAGIC = "SQLite format 3\0";
  // Wallet records are a few hundred bytes; a pathological file must not
  // make the page allocate unbounded memory while decoding.
  const MAX_RECORD_BYTES = 64 * 1024 * 1024;
  const TABLE_INTERIOR = 0x05;
  const TABLE_LEAF = 0x0d;

  const utf8 = (text) => new TextEncoder().encode(text);
  const decodeText = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);

  const concat = (...parts) => {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  };

  // SQLite 64-bit varint: up to eight 7-bit groups with the high bit marking
  // continuation; a ninth byte carries the final 8 bits.
  const readVarint = (bytes, offset) => {
    let value = 0n;
    for (let i = 0; i < 9; i++) {
      if (offset + i >= bytes.length) throw new Error("sqlite read: truncated varint");
      const byte = bytes[offset + i];
      if (i === 8) return { value: (value << 8n) | BigInt(byte), next: offset + 9 };
      value = (value << 7n) | BigInt(byte & 0x7f);
      if ((byte & 0x80) === 0) return { value, next: offset + i + 1 };
    }
    throw new Error("sqlite read: unreachable varint state");
  };

  // --- record (row) decoding ------------------------------------------------
  // Serial types: 0 NULL, 1..4/5/6 signed ints of 1/2/3/4/6/8 bytes, 7 float,
  // 8 = integer 0, 9 = integer 1, 12+2n BLOB of n bytes, 13+2n TEXT of n bytes.

  const SERIAL_SIZES = { 0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0 };

  const decodeRecord = (payload) => {
    const header = readVarint(payload, 0);
    const headerLength = Number(header.value);
    if (headerLength > payload.length) throw new Error("sqlite read: record header overruns payload");
    const types = [];
    let offset = header.next;
    while (offset < headerLength) {
      const type = readVarint(payload, offset);
      types.push(type.value);
      offset = type.next;
    }
    if (offset !== headerLength) throw new Error("sqlite read: record header length mismatch");
    const values = [];
    let body = headerLength;
    for (const typeValue of types) {
      const type = Number(typeValue);
      if (type >= 12) {
        const length = (type - (type % 2 === 0 ? 12 : 13)) / 2;
        if (body + length > payload.length) throw new Error("sqlite read: record body overruns payload");
        const raw = payload.slice(body, body + length);
        values.push(type % 2 === 0 ? raw : decodeText(raw));
        body += length;
        continue;
      }
      const size = SERIAL_SIZES[type];
      if (size === undefined) throw new Error(`sqlite read: reserved serial type ${type}`);
      if (body + size > payload.length) throw new Error("sqlite read: record body overruns payload");
      if (type === 7) {
        values.push(new DataView(payload.buffer, payload.byteOffset + body, 8).getFloat64(0, false));
      } else if (type === 8) {
        values.push(0);
      } else if (type === 9) {
        values.push(1);
      } else if (type === 0) {
        values.push(null);
      } else {
        let v = 0n;
        for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(payload[body + i]);
        const signed = BigInt.asIntN(size * 8, v);
        // Numbers when they round-trip exactly, BigInt past 2^53.
        values.push(signed >= -9007199254740991n && signed <= 9007199254740991n ? Number(signed) : signed);
      }
      body += size;
    }
    return values;
  };

  // --- page and b-tree walking ----------------------------------------------

  const readDatabase = (bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new Error("sqlite read: expected a byte array");
    if (bytes.length < 512) throw new Error("sqlite read: file too small for a database header");
    const magic = utf8(MAGIC);
    if (!magic.every((byte, index) => bytes[index] === byte)) {
      throw new Error("sqlite read: not an SQLite 3 database (bad magic)");
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    const rawPageSize = view.getUint16(16, false);
    const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) !== 0) {
      throw new Error(`sqlite read: unsupported page size ${rawPageSize}`);
    }
    if (bytes.length % pageSize !== 0) throw new Error("sqlite read: file length is not a whole number of pages");
    const writeVersion = bytes[18];
    const readVersion = bytes[19];
    if (![1, 2].includes(writeVersion) || ![1, 2].includes(readVersion)) {
      throw new Error(`sqlite read: unsupported file format versions ${writeVersion}/${readVersion}`);
    }
    const reserved = bytes[20];
    if (bytes[21] !== 64 || bytes[22] !== 32 || bytes[23] !== 32) {
      throw new Error("sqlite read: unexpected payload fractions (corrupt header)");
    }
    const pageCount = bytes.length / pageSize;
    const headerPageCount = view.getUint32(28, false);
    if (headerPageCount > pageCount) throw new Error("sqlite read: header page count exceeds the file");
    const usable = pageSize - reserved;
    if (usable < 480) throw new Error("sqlite read: too much reserved space per page");

    const applicationId = view.getUint32(68, false);
    const userVersion = view.getUint32(60, false);

    const pageAt = (number) => {
      if (!Number.isSafeInteger(number) || number < 1 || number > pageCount) {
        throw new Error(`sqlite read: page ${number} is outside the file`);
      }
      return bytes.subarray((number - 1) * pageSize, number * pageSize);
    };

    // A cell payload beyond maxLocal spills: what stays on the leaf is
    // minLocal + (payload - minLocal) mod (usable - 4), clamped to minLocal,
    // followed by a 4-byte pointer to the first overflow page. Each overflow
    // page starts with the next page number and carries usable - 4 bytes.
    const maxLocal = usable - 35;
    const minLocal = Math.floor(((usable - 12) * 32) / 255) - 23;

    const readOverflow = (firstPage, needed, visited) => {
      const chunks = [];
      let page = firstPage;
      let remaining = needed;
      while (remaining > 0) {
        if (page === 0) throw new Error("sqlite read: overflow chain ended early");
        if (visited.has(page)) throw new Error("sqlite read: overflow chain loops");
        visited.add(page);
        const data = pageAt(page);
        page = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, false);
        const piece = data.subarray(4, 4 + Math.min(remaining, usable - 4));
        chunks.push(piece);
        remaining -= piece.length;
      }
      return concat(...chunks);
    };

    const tableLeafCell = (page, offset, visited) => {
      const payloadLength = readVarint(page, offset);
      const rowid = readVarint(page, payloadLength.next);
      const length = Number(payloadLength.value);
      if (length > MAX_RECORD_BYTES) throw new Error(`sqlite read: record payload ${length} exceeds the safety limit`);
      let payload;
      if (length <= maxLocal) {
        payload = page.slice(rowid.next, rowid.next + length);
      } else {
        let local = minLocal + ((length - minLocal) % (usable - 4));
        if (local > maxLocal) local = minLocal;
        const overflowAt = rowid.next + local;
        if (overflowAt + 4 > page.length) throw new Error("sqlite read: truncated overflow pointer");
        const firstOverflow = new DataView(page.buffer, page.byteOffset + overflowAt, 4).getUint32(0, false);
        payload = concat(page.slice(rowid.next, overflowAt), readOverflow(firstOverflow, length - local, visited));
      }
      if (payload.length !== length) throw new Error("sqlite read: record payload came up short");
      return { rowid: rowid.value, payload };
    };

    // In-order walk of a table b-tree; the visited set guards against the
    // page-reference cycles a corrupt file could contain.
    const walkTable = (rootPage) => {
      const rows = [];
      const visited = new Set();
      const stack = [rootPage];
      // Interior pages list their children left-to-right followed by the
      // rightmost pointer; pushing reversed onto a stack visits in order.
      while (stack.length) {
        const number = stack.pop();
        if (visited.has(number)) throw new Error("sqlite read: b-tree page visited twice (corrupt tree)");
        visited.add(number);
        const page = pageAt(number);
        const start = number === 1 ? 100 : 0;
        const type = page[start];
        const cellCount = new DataView(page.buffer, page.byteOffset + start + 3, 2).getUint16(0, false);
        const pointerBase = start + (type === TABLE_INTERIOR ? 12 : 8);
        if (pointerBase + 2 * cellCount > page.length) throw new Error("sqlite read: cell pointer array overruns the page");
        const pointers = [];
        for (let i = 0; i < cellCount; i++) {
          pointers.push(new DataView(page.buffer, page.byteOffset + pointerBase + 2 * i, 2).getUint16(0, false));
        }
        if (type === TABLE_LEAF) {
          for (const pointer of pointers) rows.push(tableLeafCell(page, pointer, visited));
        } else if (type === TABLE_INTERIOR) {
          const rightmost = new DataView(page.buffer, page.byteOffset + start + 8, 4).getUint32(0, false);
          stack.push(rightmost);
          for (let i = pointers.length - 1; i >= 0; i--) {
            const child = new DataView(page.buffer, page.byteOffset + pointers[i], 4).getUint32(0, false);
            stack.push(child);
          }
        } else {
          throw new Error(`sqlite read: unexpected page type 0x${type.toString(16)} on page ${number}`);
        }
      }
      return rows;
    };

    const schema = walkTable(1).map(({ payload }) => {
      const [type, name, tableName, rootPage, sql] = decodeRecord(payload);
      return { type, name, tableName, rootPage: Number(rootPage), sql };
    });

    const readTable = (name) => {
      const entry = schema.find((row) => row.type === "table" && row.name === name);
      if (!entry) throw new Error(`sqlite read: no table named ${name}`);
      return walkTable(entry.rootPage).map(({ payload }) => decodeRecord(payload));
    };

    return {
      pageSize,
      pageCount,
      applicationId,
      userVersion,
      writeVersion,
      readVersion, // 2 = WAL: the main file may lag the -wal sidecar
      schema,
      readTable,
    };
  };

  return { readDatabase, decodeRecord, readVarint, MAX_RECORD_BYTES };
})();
