// Only committed results count: a station bench or cleared slot is not an item.
// Inspecting presence never reads or makes another copy of secret material.
export function workspaceItemCounts({ keys = [], multisigs = [], children = [], addresses = [], matches = [] }) {
  const results = (items) => items.filter((state) => !state.isLab && state.result).length;
  return {
    calc: results(keys),
    msig: results(multisigs),
    bip85: results(children),
    sp: addresses.filter((state) => !state.isLab && state.keys).length,
    vanity: matches.length,
  };
}

export function syncWorkspaceCounts(root, counts, describe) {
  if (!root) return;
  for (const button of root.querySelectorAll("[data-workspace]")) {
    const id = button.dataset.workspace;
    if (!Object.hasOwn(counts, id)) continue;
    let badge = button.querySelector("[data-workspace-count]");
    if (!badge) {
      badge = button.ownerDocument.createElement("span");
      badge.className = "workspace-tab-count";
      badge.dataset.workspaceCount = id;
      badge.dataset.i18nSkip = "";
      badge.setAttribute("aria-hidden", "true");
      button.appendChild(badge);
    }
    const count = counts[id];
    badge.hidden = count === 0;
    badge.textContent = count ? String(count) : "";
    if (count) button.setAttribute("aria-description", describe(count));
    else button.removeAttribute("aria-description");
  }
}
