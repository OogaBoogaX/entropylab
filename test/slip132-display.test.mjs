// SLIP-132 export families follow the selected path and imported key prefix.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const app = readFileSync(join(root, "..", "src/js/app.js"), "utf8");

function loadSlice(name) {
  const start = app.indexOf(`function ${name}(`);
  assert.ok(start >= 0, name);
  let paren = 0, body = -1;
  for (let index = start; index < app.length; index++) {
    if (app[index] === "(") paren++;
    else if (app[index] === ")") {
      paren--;
      if (paren === 0) {
        body = app.indexOf("{", index);
        break;
      }
    }
  }
  let depth = 0;
  for (let index = body; index < app.length; index++) {
    if (app[index] === "{") depth++;
    else if (app[index] === "}" && --depth === 0) return app.slice(start, index + 1);
  }
  throw new Error(`Could not extract ${name}`);
}

const { hodlAccountExportFamily } = new Function(`${loadSlice("hodlAccountExportFamily")}; return { hodlAccountExportFamily };`)();

test("derived SLIP family follows path/script match and never invents Taproot", () => {
  assert.equal(hodlAccountExportFamily({ id: "bip44", purpose: 44 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 49 }), "y");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }), "z");
  assert.equal(hodlAccountExportFamily({ id: "bip86", purpose: 86 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 48 }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 84 }), "x");
});

test("imported generic xprv is not rewrapped unless the pasted prefix already matches", () => {
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "x" }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "z" }), "z");
  assert.equal(hodlAccountExportFamily({ id: "bip49", purpose: 49 }, { imported: true, importedFamily: "y" }), "y");
  assert.equal(hodlAccountExportFamily({ id: "bip84", purpose: 84 }, { imported: true, importedFamily: "y" }), "x");
  assert.equal(hodlAccountExportFamily({ id: "bip86", purpose: 86 }, { imported: true, importedFamily: "z" }), "x");
});
