
// Minimal SQLite 3 database file writer.
//
// Produces a complete, standards-compliant SQLite database file in memory —
// the format Bitcoin Core uses for descriptor wallet wallet.dat files. It
// supports exactly what such files need and nothing more:
//
//   - 4096-byte pages, UTF-8, rollback-journal mode (write/read version 1).
//   - Tables whose rows are given as JS values (null, integer, TEXT, BLOB).
//   - An automatic index for a BLOB PRIMARY KEY, like SQLite creates for
//     CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL).
//   - Multi-page table and index b-trees (leaf pages plus one interior
//     level), with cells laid out exactly the way sqlite3 expects.
//
// Deliberate limits (all far beyond wallet record sizes): records never
// overflow to overflow pages (a single cell payload must fit a page), and a
// single interior level must be enough. Violating either throws instead of
// writing a corrupt file. The writer performs no I/O and no network traffic.
var hodlSqliteWriter = (() => {
  const PAGE_SIZE = 4096;
  const SQLITE_VERSION_NUMBER = 3038005; // matches the SQLite bundled with Bitcoin Core 28.x

  // --- byte helpers -------------------------------------------------------

  const utf8 = (text) => new TextEncoder().encode(text);

  const concat = (...parts) => {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { out.set(part, offset); offset += part.length; }
    return out;
  };

  const u32be = (value) => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value >>> 0, false);
    return bytes;
  };

  const u16be = (value) => Uint8Array.of((value >>> 8) & 0xff, value & 0xff);

  // SQLite 64-bit varint: up to eight 7-bit groups with the high bit marking
  // continuation; a ninth byte carries the final 8 bits when needed.
  const varint = (value) => {
    let v = BigInt(value);
    if (v < 0n) v = BigInt.asUintN(64, v);
    if (v > 0xffffffffffffffffn) throw new Error("sqlite varint out of range");
    if (v <= 0x7fn) return Uint8Array.of(Number(v));
    if (v > 0xffffffffffffffn) {
      const bytes = new Uint8Array(9);
      bytes[8] = Number(v & 0xffn);
      v >>= 8n;
      for (let i = 7; i >= 0; i--) { bytes[i] = Number(v & 0x7fn) | 0x80; v >>= 7n; }
      return bytes;
    }
    const chunks = [];
    while (v > 0x7fn) { chunks.unshift(Number(v & 0x7fn)); v >>= 7n; }
    chunks.unshift(Number(v));
    return Uint8Array.from(chunks.map((chunk, index) => (index < chunks.length - 1 ? chunk | 0x80 : chunk)));
  };

  // --- record (row) encoding ----------------------------------------------
  // Serial types: 0 NULL, 1..4/6 signed ints of 1/2/3/4/8 bytes, 8 = integer
  // 0, 9 = integer 1, 12+2n BLOB of n bytes, 13+2n TEXT of n bytes.

  const serialColumn = (value) => {
    if (value === null || value === undefined) return { type: 0n, bytes: new Uint8Array(0) };
    if (typeof value === "number" || typeof value === "bigint") {
      const v = BigInt(value);
      if (v === 0n) return { type: 8n, bytes: new Uint8Array(0) };
      if (v === 1n) return { type: 9n, bytes: new Uint8Array(0) };
      for (const [type, bits] of [[1n, 8], [2n, 16], [3n, 24], [4n, 32], [6n, 64]]) {
        const min = -(1n << BigInt(bits - 1));
        const max = (1n << BigInt(bits - 1)) - 1n;
        if (v >= min && v <= max) {
          const bytes = new Uint8Array(bits / 8);
          let rest = BigInt.asUintN(bits, v);
          for (let i = bits / 8 - 1; i >= 0; i--) { bytes[i] = Number(rest & 0xffn); rest >>= 8n; }
          return { type, bytes };
        }
      }
      throw new Error("sqlite integer out of range");
    }
    if (typeof value === "string") {
      const bytes = utf8(value);
      return { type: 13n + 2n * BigInt(bytes.length), bytes };
    }
    if (value instanceof Uint8Array) return { type: 12n + 2n * BigInt(value.length), bytes: value };
    throw new Error(`unsupported sqlite column value: ${typeof value}`);
  };

  const encodeRecord = (values) => {
    const columns = values.map(serialColumn);
    let typeBytes = 0;
    for (const column of columns) typeBytes += varint(column.type).length;
    // The header starts with a varint of the header length, which includes
    // that varint itself; grow it until the size is self-consistent.
    let lengthSize = 1;
    while (varint(BigInt(typeBytes + lengthSize)).length !== lengthSize) lengthSize++;
    const header = concat(varint(BigInt(typeBytes + lengthSize)), ...columns.map((column) => varint(column.type)));
    return concat(header, ...columns.map((column) => column.bytes));
  };

  // --- b-tree assembly ------------------------------------------------------

  const TABLE_LEAF = 0x0d;
  const TABLE_INTERIOR = 0x05;
  const INDEX_LEAF = 0x0a;
  const INDEX_INTERIOR = 0x02;

  // A cell payload beyond these sizes would need overflow pages, which this
  // writer intentionally does not support (wallet records are ~500 bytes max).
  const maxInlinePayload = (isIndex) =>
    isIndex ? Math.floor(((PAGE_SIZE - 12) * 64) / 255) - 23 : PAGE_SIZE - 35;

  const tableLeafCell = (rowid, record) => concat(varint(record.length), varint(rowid), record);
  const indexLeafCell = (record) => concat(varint(record.length), record);
  const tableInteriorCell = (childPage, rowid) => concat(u32be(childPage), varint(rowid));
  const indexInteriorCell = (childPage, record) => concat(u32be(childPage), varint(record.length), record);

  const bytewiseCompare = (a, b) => {
    const length = Math.min(a.length, b.length);
    for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  };

  // Packs sorted cells into leaf pages, then (if needed) one interior level.
  // Table interior cells carry only a rowid bound; index interior cells carry
  // a full divider record, which SQLite MOVES out of the leaf (an index b-tree
  // holds every record exactly once across leaf and interior pages).
  const buildBTree = ({ cells, isIndex }) => {
    const limit = maxInlinePayload(isIndex);
    for (const cell of cells) {
      if (cell.payload.length > limit) {
        throw new Error(`sqlite cell payload ${cell.payload.length} exceeds inline limit ${limit}`);
      }
    }
    const leafHeader = 8;
    const leaves = [];
    let current = [];
    let used = leafHeader;
    for (const cell of cells) {
      const encoded = isIndex ? indexLeafCell(cell.payload) : tableLeafCell(cell.rowid, cell.payload);
      const need = encoded.length + 2;
      if (current.length > 0 && used + need > PAGE_SIZE) {
        leaves.push(current);
        current = [];
        used = leafHeader;
      }
      current.push({ cell, encoded });
      used += need;
    }
    leaves.push(current);
    if (leaves.length > 200) throw new Error("sqlite writer: too many leaf pages for one interior level");

    let interior = null;
    if (leaves.length > 1) {
      const headerSize = 12;
      let usedInterior = headerSize;
      const interiorCells = [];
      for (let i = 0; i < leaves.length - 1; i++) {
        let key;
        if (isIndex) {
          // The divider record is promoted out of the leaf into the parent.
          if (leaves[i].length < 2) throw new Error("sqlite writer: index leaf too small to divide");
          key = { payload: leaves[i].pop().cell.payload };
          usedInterior += 4 + varint(key.payload.length).length + key.payload.length + 2;
        } else {
          key = { rowid: leaves[i][leaves[i].length - 1].cell.rowid };
          usedInterior += 4 + varint(key.rowid).length + 2;
        }
        if (usedInterior > PAGE_SIZE) throw new Error("sqlite writer: interior page overflow");
        interiorCells.push({ key });
      }
      interior = interiorCells;
    }
    return { leaves, interior, isIndex };
  };

  // --- page rendering -------------------------------------------------------

  const renderPage = ({ type, cells, rightmost, firstPage }) => {
    const page = new Uint8Array(PAGE_SIZE);
    const start = firstPage ? 100 : 0;
    const interior = type === TABLE_INTERIOR || type === INDEX_INTERIOR;
    const headerSize = interior ? 12 : 8;
    let contentOffset = PAGE_SIZE;
    const pointers = [];
    for (const cell of cells) {
      contentOffset -= cell.encoded.length;
      page.set(cell.encoded, contentOffset);
      pointers.push(contentOffset);
    }
    page[start] = type;
    page.set(u16be(0), start + 1); // first freeblock
    page.set(u16be(cells.length), start + 3);
    page.set(u16be(contentOffset === PAGE_SIZE ? 0 : contentOffset), start + 5);
    page[start + 7] = 0; // fragmented free bytes
    if (interior) page.set(u32be(rightmost), start + 8);
    let pointerOffset = start + headerSize;
    for (const pointer of pointers) {
      page.set(u16be(pointer), pointerOffset);
      pointerOffset += 2;
    }
    return page;
  };

  const writeHeader = (page, { pageCount, applicationId }) => {
    page.set(utf8("SQLite format 3\0"), 0);
    page.set(u16be(PAGE_SIZE), 16);
    page[18] = 1; // file format write version: rollback journal
    page[19] = 1; // file format read version
    page[20] = 0; // reserved space per page
    page[21] = 64; // max payload fraction
    page[22] = 32; // min payload fraction
    page[23] = 32; // leaf payload fraction
    page.set(u32be(1), 24); // file change counter
    page.set(u32be(pageCount), 28); // database size in pages
    page.set(u32be(0), 32); // first freelist trunk page
    page.set(u32be(0), 36); // freelist page count
    page.set(u32be(1), 40); // schema cookie
    page.set(u32be(4), 44); // schema format
    page.set(u32be(0), 48); // default page cache size
    page.set(u32be(0), 52); // largest root page (unused without auto-vacuum)
    page.set(u32be(1), 56); // text encoding: UTF-8
    page.set(u32be(0), 60); // user version
    page.set(u32be(0), 64); // incremental vacuum
    page.set(u32be(applicationId >>> 0), 68); // application id (network magic for Core wallets)
    // 72..92 reserved, zero
    page.set(u32be(1), 92); // version-valid-for
    page.set(u32be(SQLITE_VERSION_NUMBER), 96);
  };

  // Creates a complete SQLite database file.
  //
  // tables: [{
  //   name: "main",
  //   sql: "CREATE TABLE ...",            // stored verbatim in sqlite_master
  //   primaryKey: 0,                      // column index of a BLOB PRIMARY KEY
  //                                       // (gets a sqlite_autoindex_<name>_1);
  //                                       // omit for a plain rowid table
  //   rows: [[col, col, ...], ...],       // values: null | integer | string | Uint8Array
  // }]
  const createDatabase = ({ applicationId = 0, tables = [] }) => {
    if (!tables.length) throw new Error("sqlite writer: no tables");
    for (const table of tables) {
      if (!table.rows.length) throw new Error(`sqlite writer: table ${table.name} has no rows`);
    }

    // Logical b-trees first; page numbers assigned afterwards.
    const plans = tables.map((table) => {
      const rows = table.rows.map((columns, index) => ({ rowid: index + 1, columns }));
      const cells = rows.map(({ rowid, columns }) => ({ rowid, payload: encodeRecord(columns) }));
      const tree = buildBTree({
        cells,
        isIndex: false,
      });
      let indexTree = null;
      if (table.primaryKey !== undefined && table.primaryKey !== null) {
        const indexCells = rows
          .map(({ rowid, columns }) => ({ rowid, key: columns[table.primaryKey], payload: encodeRecord([columns[table.primaryKey], rowid]) }))
          .sort((a, b) => bytewiseCompare(a.key, b.key) || (a.rowid - b.rowid));
        indexTree = buildBTree({
          cells: indexCells,
          isIndex: true,
        });
      }
      return { table, tree, indexTree };
    });

    // Page 1 is sqlite_master. Then for each table: root page first, then its
    // leaf pages, then the same for the table's automatic index.
    const pages = new Map(); // pageNumber -> page descriptor
    let nextPage = 2;
    const assign = (tree, interiorType, leafType) => {
      const rootPage = nextPage++;
      if (!tree.interior) {
        pages.set(rootPage, { type: leafType, cells: tree.leaves[0] });
        return rootPage;
      }
      // Root at rootPage, leaves at rootPage+1 .. rootPage+leafCount.
      const leafPages = tree.leaves.map((leaf, i) => rootPage + 1 + i);
      const interiorCells = tree.interior.map((cell, i) => ({
        encoded: tree.isIndex
          ? indexInteriorCell(leafPages[i], cell.key.payload)
          : tableInteriorCell(leafPages[i], cell.key.rowid),
      }));
      pages.set(rootPage, { type: interiorType, cells: interiorCells, rightmost: leafPages[leafPages.length - 1] });
      tree.leaves.forEach((leaf, i) => pages.set(leafPages[i], { type: leafType, cells: leaf }));
      nextPage += tree.leaves.length;
      return rootPage;
    };

    const masterRows = [];
    for (const plan of plans) {
      const rootPage = assign(plan.tree, TABLE_INTERIOR, TABLE_LEAF);
      masterRows.push(["table", plan.table.name, plan.table.name, rootPage, plan.table.sql]);
      if (plan.indexTree) {
        const indexRoot = assign(plan.indexTree, INDEX_INTERIOR, INDEX_LEAF);
        masterRows.push(["index", `sqlite_autoindex_${plan.table.name}_1`, plan.table.name, indexRoot, null]);
      }
    }

    const masterCells = masterRows.map((columns, index) => ({ rowid: index + 1, encoded: tableLeafCell(index + 1, encodeRecord(columns)) }));
    pages.set(1, { type: TABLE_LEAF, cells: masterCells, firstPage: true });

    const pageCount = nextPage - 1;
    const database = new Uint8Array(pageCount * PAGE_SIZE);
    for (const [number, descriptor] of pages) {
      database.set(renderPage(descriptor), (number - 1) * PAGE_SIZE);
    }
    writeHeader(database.subarray(0, PAGE_SIZE), { pageCount, applicationId });
    return database;
  };

  return { createDatabase, encodeRecord, varint, bytewiseCompare, PAGE_SIZE };
})();
