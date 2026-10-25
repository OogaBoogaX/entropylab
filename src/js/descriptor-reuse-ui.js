// "Check a descriptor for key reuse" (issue #164), beside the PSBT
// Inspector: paste a watch-only descriptor, press Check, and read whether a
// public key repeats across its keys and multipath branches. The derivation
// and the comparison live in descriptor-reuse.js; this module only wires the
// controls and renders the verdict. Informational: nothing is refused or
// changed because of reuse. Unreleased: app.js calls it from a preview build
// only, and a release build strips the markup (docs/PREVIEW.md).
import { tHtml } from "./i18n.js";
import { checkDescriptorKeyReuse } from "./descriptor-reuse.js";

// The first collisions are listed; the rest are counted.
export const DESCRIPTOR_REUSE_SHOWN = 5;

// The verdict for one checkDescriptorKeyReuse result, as note markup. Paths
// come from the module (an xpub prefix and numeric steps) and are escaped as
// placeholder values all the same.
export function descriptorReuseHtml(result) {
  if (!result.collisionCount) {
    return `<p class="edge-note is-public" data-reuse-verdict="clean">${tHtml("No duplicate derived keys detected in the first 20 addresses of each branch.")}</p>`;
  }
  const shown = result.collisions.slice(0, DESCRIPTOR_REUSE_SHOWN);
  const items = shown.map(({ first, second }) => `<li data-reuse-collision>${tHtml("Key {a} at {pathA} and key {b} at {pathB}", { a: first.slot + 1, pathA: first.path, b: second.slot + 1, pathB: second.path })}</li>`).join("");
  const more = result.collisionCount > shown.length ? `<p>${tHtml("…and {count} more.", { count: result.collisionCount - shown.length })}</p>` : "";
  return `<div class="edge-note is-private" data-reuse-verdict="reuse"><p><strong>${tHtml("Potential key reuse: this descriptor derives the same public key in more than one place")}</strong></p><ul>${items}</ul>${more}</div>`;
}

// onChange runs after every edit and check, so the page can refresh
// controls that depend on this section holding text (Clear Inspectors).
export function initDescriptorReuseCheck(doc = document, { onChange = () => {} } = {}) {
  const text = doc.getElementById("descriptor-reuse-text");
  const go = doc.getElementById("descriptor-reuse-go");
  const out = doc.getElementById("descriptor-reuse-out");
  const error = doc.getElementById("descriptor-reuse-error");
  if (!text || !go || !out || !error) return;
  // An edit retires the verdict: it described the text before the edit.
  text.addEventListener("input", () => {
    out.innerHTML = "";
    error.textContent = "";
    onChange();
  });
  go.addEventListener("click", () => {
    out.innerHTML = "";
    error.textContent = "";
    let result;
    try {
      result = checkDescriptorKeyReuse(text.value, { indexes: 20 });
    } catch (failure) {
      // The module's messages never repeat the descriptor or a key.
      error.textContent = String(failure?.message ?? failure);
      onChange();
      return;
    }
    out.innerHTML = descriptorReuseHtml(result);
    onChange();
  });
}
