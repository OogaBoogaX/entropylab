// Tests for src/js/sqlite-reader.js using Node's built-in test runner.
// Round-trip tests build databases with src/js/sqlite-writer.js and read them
// back; database-level cross-checks (including overflow pages and WAL mode,
// which the writer deliberately does not produce) create files with Python's
// sqlite3 module (the real SQLite C library) and compare the reader's rows
// against it. Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const readerSrc = read("src/js/sqlite-reader.js");
const writerSrc = read("src/js/sqlite-writer.js");

const loadModules = () =>
  new Function(`${writerSrc}\n${readerSrc}\nreturn { writer: hodlSqliteWriter, reader: hodlSqliteReader };`)();

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => new Uint8Array(Buffer.from(text, "hex"));

const PYTHON_SQLITE = (() => {
  const probe = spawnSync("python3", ["-c", "import sqlite3"], { stdio: "pipe" });
  return probe.status === 0;
})();

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

const makeDb = (rows, applicationId = 0xf9beb4d9) =>
  loadModules().writer.createDatabase({
    applicationId,
    tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows }],
  });

const readMainHex = (db) =>
  loadModules().reader.readDatabase(db).readTable("main").map(([key, value]) => [hex(key), hex(value)]);

test("never generates network traffic", () => {
  assert.doesNotMatch(readerSrc, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

test("the build inlines the reader next to the writer", () => {
  const build = read("scripts/build.mjs");
  const template = read("src/index.html");
  assert.match(build, /sqlite-reader\.js/);
  assert.match(build, /JS_SQLITE_READER/);
  assert.match(template, /\/\*@@JS_SQLITE_READER@@\*\//);
});

test("round-trips a wallet-shaped database", () => {
  const rows = [
    [fromHex("0776657273696f6e"), fromHex("ec460400")],
    [fromHex("0a6d696e76657273696f6e"), fromHex("ac970200")],
    [fromHex("05666c616769"), fromHex("0000000007000000")],
  ];
  const db = makeDb(rows);
  const read = loadModules().reader.readDatabase(db);
  assert.equal(read.pageSize, 4096);
  assert.equal(read.applicationId, 0xf9beb4d9);
  assert.equal(read.userVersion, 0);
  assert.equal(read.readVersion, 1);
  assert.deepEqual(
    read.schema.map(({ type, name }) => [type, name]),
    [["table", "main"], ["index", "sqlite_autoindex_main_1"]],
  );
  assert.deepEqual(
    read.readTable("main").map(([key, value]) => [hex(key), hex(value)]),
    rows.map(([key, value]) => [hex(key), hex(value)]),
  );
});

test("round-trips a multi-page b-tree with an interior level", () => {
  const rows = [];
  for (let i = 0; i < 500; i++) {
    const key = new Uint8Array(40);
    key[0] = 7;
    new DataView(key.buffer).setUint32(36, i, false);
    const value = new Uint8Array(120).fill(i & 0xff);
    rows.push([key, value]);
  }
  const db = makeDb(rows);
  assert.ok(db.length > 4096 * 3, "fixture must span several pages");
  assert.deepEqual(readMainHex(db), rows.map(([key, value]) => [hex(key), hex(value)]));
});

test("decodes every serial type the writer cannot produce", { skip: !PYTHON_SQLITE }, () => {
  // nulls, negative and wide integers, floats, empty and non-ASCII text.
  const dir = mkdtempSync(join(tmpdir(), "entropylab-sqliteread-"));
  const file = join(dir, "types.db");
  try {
    execFileSync("python3", [
      "-c",
      `
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("CREATE TABLE t(a, b, c, d, e, f)")
con.execute("INSERT INTO t VALUES (NULL, -1, 4611686018427387904, 1.5, '', 'héllo')")
con.commit(); con.close()
`,
      file,
    ]);
    const db = new Uint8Array(readFileSync(file));
    const rows = loadModules().reader.readDatabase(db).readTable("t");
    assert.equal(rows.length, 1);
    const [a, b, c, d, e, f] = rows[0];
    assert.equal(a, null);
    assert.equal(b, -1);
    assert.equal(c, 2n ** 62n);
    assert.equal(d, 1.5);
    assert.equal(e, "");
    assert.equal(f, "héllo");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("follows overflow page chains for large records", { skip: !PYTHON_SQLITE }, () => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-sqliteread-"));
  const file = join(dir, "overflow.db");
  const payload = "ab".repeat(20000); // 40 KB blob: many overflow pages
  try {
    execFileSync("python3", [
      "-c",
      `
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
con.execute("INSERT INTO main VALUES (x'03626967', x'" + "ab" * 20000 + "')")
con.commit(); con.close()
`,
      file,
    ]);
    const db = new Uint8Array(readFileSync(file));
    const rows = readMainHex(db);
    assert.deepEqual(rows, [["03626967", payload]]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reads a WAL-mode database and reports the journal mode", { skip: !PYTHON_SQLITE }, () => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-sqliteread-"));
  const file = join(dir, "wal.db");
  try {
    execFileSync("python3", [
      "-c",
      `
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
con.execute("PRAGMA journal_mode=WAL")
con.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
con.execute("INSERT INTO main VALUES (x'0776657273696f6e', x'ec460400')")
con.commit()
con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
con.close()
`,
      file,
    ]);
    const db = new Uint8Array(readFileSync(file));
    const read = loadModules().reader.readDatabase(db);
    assert.equal(read.readVersion, 2);
    assert.deepEqual(readMainHex(db), [["0776657273696f6e", "ec460400"]]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reader output matches the real SQLite library row for row", { skip: !PYTHON_SQLITE }, () => {
  const rows = [];
  for (let i = 0; i < 80; i++) {
    const key = new Uint8Array([5, 105, 110, 100, 101, 120, i]);
    rows.push([key, new Uint8Array(200).fill(i)]);
  }
  const db = makeDb(rows, 0x0b110907);
  const dir = mkdtempSync(join(tmpdir(), "entropylab-sqliteread-"));
  const file = join(dir, "check.db");
  writeFileSync(file, db);
  try {
    const out = execFileSync(
      "python3",
      [
        "-c",
        `
import sqlite3, json, sys
con = sqlite3.connect(sys.argv[1])
result = {
  "integrity": con.execute("PRAGMA integrity_check").fetchone()[0],
  "app_id": con.execute("PRAGMA application_id").fetchone()[0] & 0xFFFFFFFF,
  "rows": [[k.hex(), v.hex()] for k, v in con.execute("SELECT key, value FROM main")],
}
con.close()
print(json.dumps(result))
`,
        file,
      ],
      { encoding: "utf8", maxBuffer: 1 << 26 },
    );
    const report = JSON.parse(out);
    assert.equal(report.integrity, "ok");
    const read = loadModules().reader.readDatabase(db);
    assert.equal(read.applicationId, report.app_id);
    assert.deepEqual(readMainHex(db), report.rows);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rejects files that are not SQLite databases", () => {
  const { reader } = loadModules();
  assert.throws(() => reader.readDatabase(new Uint8Array(100)), /too small/);
  // Berkeley DB hash magic (legacy wallet.dat) must not parse as SQLite.
  const bdb = new Uint8Array(4096);
  bdb.set(fromHex("00053162"), 12);
  assert.throws(() => reader.readDatabase(bdb), /bad magic/);
  const truncated = makeDb([[fromHex("036b6579"), fromHex("0178")]]).slice(0, 5000);
  assert.throws(() => reader.readDatabase(truncated), /whole number of pages/);
});

test("rejects structural corruption instead of guessing", () => {
  const { reader } = loadModules();
  const db = makeDb([[fromHex("036b6579"), fromHex("0178")]]);
  // Point the main table's root at a page beyond the file.
  const corrupt = new Uint8Array(db);
  // sqlite_master row sits on page 1; flip the schema cookie path instead:
  // corrupt the page-1 b-tree header type byte (offset 100).
  corrupt[100] = 0x06;
  assert.throws(() => reader.readDatabase(corrupt), /unexpected page type/);
  // A bogus page size is refused outright.
  const badPageSize = new Uint8Array(db);
  badPageSize[16] = 0x00;
  badPageSize[17] = 0x03;
  assert.throws(() => reader.readDatabase(badPageSize), /page size/);
});
