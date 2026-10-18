import { test } from "node:test";
import assert from "node:assert/strict";
import { workspaceItemCounts, syncWorkspaceCounts } from "../src/js/workspace-counts.js";
import { MiniDocument } from "./mini-dom.mjs";

test("counts retained generated results, excluding benches and cleared slots", () => {
  const result = {};
  const keys = [{ isLab: true, result }, { result }, { result: null }];
  const multisigs = [{ isLab: true }, { result }, { result }];
  const children = [{ isLab: true }, { result }];
  const addresses = [{ isLab: true }, { keys: {} }, { keys: null }];
  const matches = [{}, {}];
  assert.deepEqual(workspaceItemCounts({ keys, multisigs, children, addresses, matches }), {
    calc: 1, msig: 2, bip85: 1, sp: 1, vanity: 2,
  });
  keys.push({ result });
  assert.equal(workspaceItemCounts({ keys }).calc, 2);
  keys.splice(1, 1);
  assert.equal(workspaceItemCounts({ keys }).calc, 1);
  keys.at(-1).result = null;
  assert.equal(workspaceItemCounts({ keys }).calc, 0);
  assert.deepEqual(workspaceItemCounts({}), { calc: 0, msig: 0, bip85: 0, sp: 0, vanity: 0 });
});

test("counting reads result presence, never key material or match contents", () => {
  const secret = new Proxy({}, { get() { throw new Error("secret inspected"); } });
  const counts = workspaceItemCounts({ keys: [{ result: secret }], multisigs: [{ result: secret }], children: [{ result: secret }], addresses: [{ keys: secret }], matches: [secret] });
  assert.deepEqual(Object.values(counts), [1, 1, 1, 1, 1]);
});

test("badges reuse nodes, clear zero counts, and preserve tab identity and selection", () => {
  const document = new MiniDocument();
  document.body.innerHTML = '<div id="workspace-tabs"><button data-workspace="calc" aria-label="Keys" role="tab" aria-selected="true"><span>Keys</span><span>K</span></button><button data-workspace="psbt" aria-label="PSBT" role="tab"></button></div>';
  const root = document.getElementById("workspace-tabs");
  const button = root.querySelector('[data-workspace="calc"]');
  const describe = (n) => `description:${n}`;
  syncWorkspaceCounts(root, { calc: 12 }, describe);
  const badge = button.querySelector('[data-workspace-count]');
  assert.ok(badge);
  assert.equal(badge.textContent, "12");
  assert.equal(badge.hidden, false);
  assert.equal(badge.getAttribute("aria-hidden"), "true");
  assert.equal(button.getAttribute("aria-description"), "description:12");
  assert.equal(button.getAttribute("aria-label"), "Keys");
  assert.equal(button.getAttribute("aria-selected"), "true");
  assert.equal(root.querySelector('[data-workspace="psbt"]').children.length, 0);
  syncWorkspaceCounts(root, { calc: 1 }, (n) => `translated:${n}`);
  assert.equal(button.querySelector('[data-workspace-count]'), badge);
  assert.equal(badge.textContent, "1");
  assert.equal(button.getAttribute("aria-description"), "translated:1");
  syncWorkspaceCounts(root, { calc: 0 }, describe);
  assert.equal(badge.hidden, true);
  assert.equal(badge.textContent, "");
  assert.equal(button.hasAttribute("aria-description"), false);
  assert.equal(button.children.length, 3);
});
