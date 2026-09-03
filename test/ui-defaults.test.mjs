import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { transformSync } from "esbuild";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const template = read("src/index.html");
const appSource = read("src/js/app.js");
// These source invariants predate the readable application source and match
// its compact syntax. Normalize formatting without renaming identifiers.
const app = transformSync(appSource, {
  format: "esm",
  minifySyntax: true,
  minifyWhitespace: true,
  target: "es2022",
}).code;
// Keep a compact representation that preserves literal text and control flow
// for the handful of assertions where syntax minification is intentionally
// not part of the invariant.
const appWhitespace = transformSync(appSource, {
  format: "esm",
  minifyWhitespace: true,
  target: "es2022",
  charset: "utf8",
}).code;
const css = read("src/css/styles.css");
const online = read("src/js/online.js");
const en = JSON.parse(read("src/locales/en.json"));

test("top status banner omits the entropy RNG message", () => {
  assert.doesNotMatch(`${template}\n${app}`, /No entropy RNG/);
  assert.match(template, /<div class="kicker">Run Offline · Bring your own entropy<\/div>/);
});

test("optional BIP39 passphrase placeholders explain that blank means none", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="pass"[^>]*placeholder="Enter a BIP39 passphrase, or leave blank for none"/);
    assert.match(markup, /id="psbt-pass"[^>]*placeholder="Enter a BIP39 passphrase, or leave blank for none"/);
    assert.doesNotMatch(markup, /placeholder="Leave blank unless you set one"/);
  }
});

test("every enabled button uses orange and black momentary press feedback", () => {
  assert.match(css, /button:not\(:disabled\):active \{[\s\S]*?background: var\(--selection-accent\) !important;[\s\S]*?color: var\(--selection-fg\) !important;[\s\S]*?border-color: var\(--selection-accent\) !important;/);
  assert.match(css, /button:not\(:disabled\):active \* \{ color: inherit !important; \}/);
  assert.equal(/--selection-accent: #ff9900;/.test(css), true);
  assert.equal(/--selection-fg: #000000;/.test(css), true);
});

test("wallet coin type indexes enable and default to mainnet", () => {
  for (const id of ["network", "msig-network"]) {
    const mainnetCoinType = new RegExp(
      `<input id="${id}" type="(?:text|number)"[^>]*inputmode="numeric" value="0${id === "network" ? "'" : ""}"`,
    );
    assert.match(template, mainnetCoinType);
    assert.match(appWhitespace, mainnetCoinType);
  }
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /id="network-help">Coin type index (?:·|\\xB7) Mainnet (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="msig-network-help">Coin type index (?:·|\\xB7) Mainnet (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    // The PSBT tools dropped their own network selects: they read the header
    // picker's choice directly. Only the SP station keeps a select.
    assert.doesNotMatch(markup, /id="psbt-network"/);
    assert.doesNotMatch(markup, /id="psbted-network"/);
    assert.match(markup, /<select id="sp-network"><option value="mainnet" selected(?:="selected")?>Bitcoin mainnet<\/option>/);
  }
  assert.match(appSource, /function hodlReadCoinType\(input = document\.getElementById\("network"\), mark = true\)/);
  assert.match(appSource, /function hodlNetworkFromCoinType\(coinType\)/);
  assert.match(appSource, /Number\(coinType\) === 1 \? "testnet" : "mainnet"/);
  // New keys, the lab reset, and new multisigs default to the header picker's
  // network, which always boots mainnet.
  assert.match(app, /var hodlNetworkChoice="mainnet",hodlNetworkDefault="mainnet"/);
  assert.match(app, /coinType:`\$\{hodlDefaultCoinType\(\)\}'`,coinTypeHarden:!0,network:hodlNetworkDefault/);
  assert.match(app, /coinType:String\(hodlDefaultCoinType\(\)\),coinTypeHarden:!0,network:hodlNetworkDefault/);
});

test("the header network picker sets the network every tool defaults to", () => {
  for (const markup of [template, appWhitespace]) {
    // The control rides the fixed header's action row, between the GitHub
    // link and the theme toggle, and ships in the mainnet state.
    const header = markup.indexOf('<div class="site-header no-print">');
    const wrapper = markup.indexOf('<div class="wrap">');
    const picker = markup.indexOf('id="network-picker"');
    assert.ok(header >= 0 && header < picker && picker < wrapper, "the network picker must sit inside the header");
    const controls = markup.indexOf('class="download-controls"');
    const download = markup.indexOf("download-html");
    assert.ok(
      controls >= 0 && controls < picker && download < picker,
      "the picker belongs inside the header controls, after the download button",
    );
    assert.match(markup, /id="network-picker" data-network="mainnet"/);
    assert.match(markup, /id="network-picker-button"[^>]*aria-haspopup="menu"[^>]*aria-expanded="false"[^>]*aria-controls="network-picker-menu"/);
    assert.match(markup, /aria-label="Bitcoin network: Bitcoin\. Change the network the tools derive and check for"/);
    // The Bitcoin Core icon's coin — orange disc, white B — beside the name.
    assert.match(markup, /<circle class="network-picker-coin" cx="12" cy="12" r="12"\/>/);
    assert.match(markup, /<path class="network-picker-b" fill-rule="evenodd"/);
    assert.match(markup, /id="network-picker-label"[^>]*>Bitcoin</);
    assert.match(markup, /id="network-picker-menu" role="menu" aria-label="Bitcoin network"[^>]* hidden/);
    // Bitcoin Core's four networks, each carrying its coin beside the name.
    assert.match(markup, /role="menuitemradio" aria-checked="true" data-network="mainnet"/);
    assert.match(markup, /role="menuitemradio" aria-checked="false" data-network="testnet"/);
    assert.match(markup, /role="menuitemradio" aria-checked="false" data-network="signet"/);
    assert.match(markup, /role="menuitemradio" aria-checked="false" data-network="regtest"/);
    assert.equal(markup.match(/class="network-picker-option-coin"/g).length, 4);
    // Each option names the checks and defaults it switches.
    assert.match(markup, /<strong[^>]*>Bitcoin<\/strong>/);
    assert.match(markup, /<strong[^>]*>Testnet<\/strong>/);
    assert.match(markup, /<strong[^>]*>Signet<\/strong>/);
    assert.match(markup, /<strong[^>]*>Regtest<\/strong>/);
    assert.match(markup, /xpub\/ypub\/zpub · WIF 5\/K\/L · coin type 0'/);
    assert.match(markup, /tpub\/upub\/vpub · WIF 9\/c · coin type 1'/);
    // Signet and regtest derive with the testnet formats; the options say so.
    assert.match(markup, /Signed practice coins, no value · same formats as testnet/);
    assert.match(markup, /Local sandbox coins · derived here with the testnet formats/);
    // And the menu says plainly that no connection is ever made.
    assert.match(markup, /This page never connects to any network/);
  }
  assert.match(appSource, /var hodlNetworkDefault = "mainnet"/);
  assert.match(appSource, /return hodlNetworkDefault === "testnet" \? 1 : 0/);
  // The picker tracks Bitcoin Core's four networks, but the tools stay
  // binary: signet and regtest share the testnet versions.
  assert.match(appSource, /var hodlNetworkChoice = "mainnet"/);
  assert.match(appSource, /hodlNetworkChoice = \["testnet", "signet", "regtest"\]\.includes\(network\) \? network : "mainnet"/);
  assert.match(appSource, /hodlNetworkDefault = hodlNetworkChoice === "mainnet" \? "mainnet" : "testnet"/);
  // The option names and the button's accessible name come from the locale
  // catalogs so the whole header follows the selected language.
  assert.match(appSource, /let key = \["mainnet", "testnet", "signet", "regtest"\]\.includes\(hodlNetworkChoice\) \? hodlNetworkChoice : "mainnet"/);
  assert.match(appSource, /let name = hodlT\(`networkPicker\.name\.\$\{key\}`\)/);
  assert.match(appSource, /button\.setAttribute\("aria-label", hodlT\("networkPicker\.buttonAria", \{ network: name \}\)\)/);
  assert.match(appSource, /option\.dataset\.network === hodlNetworkChoice/);
  assert.match(appSource, /function hodlApplyNetworkDefault\(network\)/);
  assert.match(appSource, /function hodlInitNetworkPicker\(\)/);
  // The pick reaches every tool's own network control through the control's
  // ordinary events, so each dependent check follows: the singlesig and
  // multisig coin-type indexes, and the SP station's mainnet/testnet select.
  // The PSBT tools have no select: the inspectors read hodlNetworkDefault at
  // render time and the editor re-renders on the document event.
  assert.match(appSource, /coinType\.value = `\$\{hodlDefaultCoinType\(\)\}\$\{hardened \? "'" : ""\}`/);
  assert.match(appSource, /coinType\.dispatchEvent\(new Event\("input", \{ bubbles: true \}\)\)/);
  assert.match(appSource, /msigCoinType\.dispatchEvent\(new Event\("input", \{ bubbles: true \}\)\)/);
  assert.match(appSource, /for \(let id of \["sp-network"\]\)/);
  assert.match(appSource, /hodlSyncSelect\(select, hodlNetworkDefault\)/);
  assert.match(appSource, /select\.dispatchEvent\(new Event\("change", \{ bubbles: true \}\)\)/);
  assert.match(appSource, /document\.dispatchEvent\(new CustomEvent\("hodl:network-default"\)\)/);
  assert.match(appSource, /let network = hodlNetworkDefault,/);
  // The choice is never stored: every load opens on mainnet again.
  assert.doesNotMatch(appSource, /localStorage\.setItem\([^)]*network/i);
  // The coin takes the Bitcoin Core network colours — yellow mainnet, green
  // testnet, purple signet, grey regtest — on the button and on each option.
  assert.match(css, /--bitcoin: #f7931a;/);
  assert.match(css, /--testnet: #22c55e;/);
  assert.match(css, /--signet: #a855f7;/);
  assert.match(css, /\.network-picker-coin \{ fill: var\(--bitcoin\); \}/);
  assert.match(css, /\.network-picker\[data-network="testnet"\] \.network-picker-coin \{ fill: var\(--testnet\); \}/);
  assert.match(css, /\.network-picker\[data-network="signet"\] \.network-picker-coin \{ fill: var\(--signet\); \}/);
  assert.match(css, /\.network-picker\[data-network="regtest"\] \.network-picker-coin \{ fill: var\(--faint\); \}/);
  assert.match(css, /\.network-picker-option-coin \{ fill: var\(--bitcoin\); \}/);
  assert.match(css, /\.network-picker-option\[data-network="testnet"\] \.network-picker-option-coin \{ fill: var\(--testnet\); \}/);
  assert.match(css, /\.network-picker-option\[data-network="signet"\] \.network-picker-option-coin \{ fill: var\(--signet\); \}/);
  assert.match(css, /\.network-picker-option\[data-network="regtest"\] \.network-picker-option-coin \{ fill: var\(--faint\); \}/);
  assert.match(css, /\.network-picker-b \{ fill: #ffffff; \}/);
  assert.match(css, /\.network-picker-button \{[^}]*min-height: 40px;[^}]*background: var\(--surface-2\)/s);
  // The button lives at the bar's right edge, so the menu opens leftward
  // from its right edge rather than past the viewport.
  assert.match(css, /\.network-picker-menu \{[^}]*position: absolute;[^}]*right: 0;[^}]*background: var\(--surface-2\)/s);
  // The coin carries the network on its own, so it is sized with the download
  // and GitHub marks either side of it rather than the 16px its SVG ships.
  assert.match(css, /\.network-picker-glyph \{[^}]*width: 18px; height: 18px; \}/);
  // Narrow screens drop the label and chevron and square the control off
  // against the 40px theme toggle, keeping it in the control row: it holds its
  // place among the header buttons instead of hanging out of the bar.
  const narrow = css.slice(css.indexOf("@media (max-width: 719px)"));
  assert.match(narrow, /\.network-picker-label, \.network-picker-chevron \{ display: none; \}/);
  assert.match(narrow, /\.network-picker \{ flex: 0 0 40px; \}/);
  assert.match(narrow, /\.network-picker-button \{ width: 40px; padding: 0; justify-content: center; \}/);
  // It must not leave the flow: absolute positioning hung it below the bar.
  assert.doesNotMatch(narrow, /\.network-picker \{[^}]*position: absolute/s);
  // The row keeps its 40px touch targets rather than shrinking to a chip.
  assert.doesNotMatch(narrow, /\.network-picker-button \{[^}]*min-height: 0/s);
});

test("advanced derivation fields use the shared responsive settings grid", () => {
  assert.match(template, /<div class="field network-field"><label for="network">Network<\/label>[\s\S]*?<input id="network"[^>]*>/);
  assert.match(app, /<div class="field network-field"><label for="network">Network<\/label>[\s\S]*?<input id="network"[^>]*>/);
  assert.match(css, /\.derivation-advanced-fields \{ display: grid; gap: var\(--space-component\); \}/);
  assert.match(css, /@media \(max-width: 520px\) \{[\s\S]*?\.key-settings-row \{ grid-template-columns: minmax\(0, 1fr\); \}/);
});

test("key and multisig derivation use an indexed address window with an estimate and progress", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="address-start"[^>]*value="0"/);
    assert.match(markup, /id="address-range"[^>]*value="1"/);
    assert.match(markup, /id="msig-address-start"[^>]*value="0"/);
    assert.match(markup, /id="msig-address-range"[^>]*value="5"/);
    assert.match(markup, /id="address-start-help">First receive index to derive (?:·|\\xB7) Unhardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="address-range-help">Derives 1 receive address (?:·|\\xB7) Max 10,000/);
    assert.match(markup, /id="msig-address-start-help">First receive and change index to derive (?:·|\\xB7) Unhardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="msig-address-range-help">Derives 5 receive and 5 change addresses (?:·|\\xB7) Max 10,000/);
    assert.match(markup, /id="derive-progress"[^>]*role="progressbar"/);
    assert.match(markup, /id="msig-derive-progress"[^>]*role="progressbar"/);
    assert.doesNotMatch(markup, /id="(?:msig-)?count"/);
    assert.match(markup, /id="derivation-path"[\s\S]*id="address-estimate"[\s\S]*id="go"/);
    assert.match(markup, /id="msig-address-range"[\s\S]*id="msig-address-estimate"[\s\S]*id="msig-go"/);
  }
  assert.match(appSource, /function hodlReadAddressWindow\(prefix = "", mark = true\)/);
  assert.match(appSource, /function hodlSyncAddressRangeLimit\(prefix = ""\)/);
  assert.match(appSource, /Math\.min\(hodlMaxAddressRange, hodlMaxAddressIndex - start \+ 1\)/);
  assert.match(appSource, /if \(\/\^\\d\+\$\/\.test\(rangeRaw\)[^\n]*range > maximum\) rangeInput\.value = String\(maximum\)/);
  assert.match(appSource, /Max \$\{maximum\.toLocaleString\(\)\}/);
  assert.match(appSource, /for \(let index = startIndex; index < startIndex \+ count; index\+\+\)/);
  assert.match(appSource, /function hodlInitAddressBenchmark\(\)/);
  assert.match(appSource, /requestIdleCallback\(run, \{ timeout: 750 \}\)/);
  assert.match(appSource, /var hodlAddressVirtualThreshold = 24, hodlAddressVirtualRowHeight = 34, hodlAddressVirtualOverscan = 6/);
  assert.match(appSource, /function hodlBindAddressVirtualization\(configs = \[\]\)/);
  assert.match(appSource, /requestAnimationFrame\(render\)/);
  assert.match(appSource, /aria-rowcount="\$\{rows\.length \+ 1\}"/);
  assert.doesNotMatch(appSource, /hodlBindAddressPagination|address-page-button|>Previous<|>Next</);
  assert.match(css, /\.wallet-table \{[\s\S]*?max-height: 252px;[\s\S]*?overflow: auto;/);
  assert.match(css, /\.wallet-table \{[\s\S]*?overscroll-behavior: contain;/);
  assert.match(css, /\.wallet-table tbody tr:not\(\.address-virtual-spacer\) \{ height: 34px; \}/);
  assert.match(css, /\.derive-progress-bar \{[\s\S]*?background: linear-gradient/);
  assert.match(appSource, /function hodlCreateDerivationTracker\(progress, control\)/);
  assert.match(appSource, /label\.innerHTML = `\$\{hodlCopiedIconMarkup\(\)\}<span>\$\{hodlT\("action.done"\)\}<\/span>`/);
  assert.match(appSource, /async function hodlAddressRowsWithProgress/);
  assert.match(css, /\.derive-progress\.is-complete \{[^}]*var\(--ok\)/);
  assert.match(css, /\.derive-progress \{[\s\S]*?border: 0;/);
  assert.match(css, /\.btn\.primary\[data-derivation-state="running"\][\s\S]*?background: var\(--danger\)/);
  assert.doesNotMatch(css, /derive-progress-slide|animation: derive-progress/);
  assert.match(appSource, /button\.textContent = hodlT\("action.stop"\)/);
  assert.match(appSource, /button\.style\.width = `\$\{width\}px`/);
  assert.match(appSource, /button\.style\.removeProperty\("width"\)/);
  assert.match(appSource, /class HodlDerivationCancelledError extends Error/);
  assert.match(appSource, /function hodlStopDerivation\(kind\)/);
  assert.match(appSource, /hodlHandleDerivationButton\("key", hodlCalculateKey\)/);
  assert.match(appSource, /hodlHandleDerivationButton\("msig", hodlBuildMsig\)/);
});

test("key and multisig derivation select one or two address branches", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="branch-start"[^>]*value="0"/);
    assert.match(markup, /id="branch-start-harden"[^>]*type="checkbox"/);
    assert.match(markup, /id="branch-range"[^>]*max="2"[^>]*value="1"/);
    assert.match(markup, /id="msig-branch-start"[^>]*value="0"/);
    assert.match(markup, /id="msig-branch-start-harden"[^>]*type="checkbox"/);
    assert.match(markup, /id="msig-branch-range"[^>]*max="2"[^>]*value="2"/);
    assert.match(markup, /0 is Receive (?:·|\xB7) 1 is Change/);
  }
  assert.match(appSource, /function hodlReadBranchWindow\(prefix = "", mark = true\)/);
  assert.match(appSource, /function hodlAddressBranchLabel\(branch\)/);
  assert.match(appSource, /branch: Boolean\(fields\.branchHarden\)/);
  assert.match(appSource, /hodlPathComponent\(chain, branchHardened\)/);
  assert.match(appSource, /Hardened address branches cannot be derived from the supplied multisig extended public keys/);
  assert.match(appSource, /branch === 0 \? "Receive" : branch === 1 \? "Change" : `Custom branch \$\{branch\}`/);
  assert.match(appSource, /progress\.setTotal\(count \* branchRange\)/);
  assert.match(appSource, /hodlAddressBranchTables\(branches, hasPrivate, "hd"\)/);
  assert.match(appSource, /hodlAddressBranchTables\(branches, false, "msig"\)/);
});

test("a running derivation yields off the main thread, survives hidden tabs, and cancels on edits", () => {
  assert.match(appSource, /function hodlDerivationPause\(\)/);
  assert.match(appSource, /requestAnimationFrame\(finish\)/);
  assert.match(appSource, /setTimeout\(finish, 100\)/);
  assert.match(appSource, /return hodlDerivationPause\(\)\.then\(\(\) => \{/);
  assert.match(appSource, /function hodlInvalidateLiveKeyResult\(\) \{[\s\S]*?hodlStopDerivation\("key"\)[\s\S]*?\}/);
  assert.match(appSource, /function hodlInvalidateMsig\(\) \{[\s\S]*?hodlStopDerivation\("msig"\)[\s\S]*?\}/);
  assert.match(appSource, /function hodlSyncDeriveButton\(\) \{[\s\S]*?hodlActiveDerivation\.kind === "key"[\s\S]*?button\.disabled = true;/);
  assert.match(appSource, /function hodlSyncMsigDeriveButton\(\) \{[\s\S]*?hodlActiveDerivation\.kind === "msig"[\s\S]*?button\.disabled = true;/);
  assert.equal(appSource.match(/hodlT\("error\.msig\.deriveBusy"\)/g)?.length, 2);
});

test("entropy progress messages sit directly below their inputs and above keypads", () => {
  assert.match(app, /<textarea id="dice"[^>]*><\/textarea><\/div>\s*\$\{hodlSeedMetaRowMarkup\("dice-meta",!0\)\}\s*\$\{dicePad\}/);
  assert.match(appSource, /<textarea id="\$\{inputId\}"[^>]*><\/textarea><\/div>\s*\$\{hodlSeedMetaRowMarkup\("cards-meta"\)\}/);
  assert.match(app, /<textarea id="\$\{inputId\}"[\s\S]*?<\/textarea><\/div>\s*\$\{hodlSeedMetaRowMarkup\("entropy-meta",!0\)\}\s*\$\{base64Keyboard\}\s*\$\{entropyPad\}/);
  assert.match(app, /<textarea id="seed"[^>]*><\/textarea><\/div><p class="muted" id="seed-meta"[^>]*><\/p>\$\{hodlSeedKeyboardMarkup\(\)\}/);
  assert.match(app, /<textarea id="key"[^>]*><\/textarea><\/div><p class="muted" id="private-key-meta"[^>]*><\/p>/);
});

test("seed phrase calculations and copy controls precede every numbered word grid", () => {
  assert.match(appSource, /\$\{dicePad\}[\s\S]*?manual-calculations-container[\s\S]*?\$\{hodlSeedCopyRowMarkup\(hodlDiceFairnessToggleMarkup\([\s\S]*?\)\)\}[\s\S]*?<div id="dice-words"/);
  assert.match(appSource, /<div class="dealt-cards"[^>]*><\/div>[\s\S]*?manual-calculations-container[\s\S]*?\$\{hodlSeedCopyRowMarkup\(\)\}\s*<div id="dice-words"/);
  assert.match(appSource, /\$\{entropyPad\}\s*<div id="number-base-calculations"[^>]*><\/div>\s*\$\{hodlSeedCopyRowMarkup\(\)\}\s*<div id="entropy-words"/);
  assert.match(appSource, /<\/div>\$\{hodlSeedCopyRowMarkup\(\)\}<div id="seed-number-words"/);
  assert.match(appSource, /function hodlSeedMetaRowMarkup\(metaId, live = false\) \{\s*return `<div class="seed-word-meta"><p[^`]+<\/p><\/div>`;\s*\}/);
});

test("direct dice and card methods expose manual BIP39 calculations before copying", () => {
  assert.match(appSource, /id="show-manual-calculations"/);
  assert.match(appSource, /id="dice-manual-calculations" class="manual-calculations-container"/);
  assert.match(appSource, /id="cards-manual-calculations" class="manual-calculations-container"/);
  assert.match(appSource, /function hodlManualCalculationMarkup\(method, value, targetWords = hodlTargetWordCount\)/);
  assert.match(appSource, /hodlRenderManualCalculations\("dice-manual-calculations",\s*"dplus"/);
  assert.match(appSource, /hodlRenderManualCalculations\("dice-manual-calculations",\s*"bitbox"/);
  assert.match(appSource, /hodlRenderManualCalculations\("cards-manual-calculations",\s*"cards"/);
  assert.match(appSource, /D8 contributes 8 values and each hexadecimal D16 contributes 16 values/);
  assert.match(appSource, /Each D4 contributes one base-4 value and the final die contributes the coin bit/);
  assert.match(appSource, /Ranks are mapped to zero-based values/);
  assert.match(appSource, /dplus-calculation-stages/);
  assert.match(appSource, /dplus-calculation-stage.*stage\.face/);
  assert.match(css, /\.manual-calculation-row \{/);
  assert.match(css, /\.dplus-calculation-stages \{[^}]*grid-template-columns: repeat\(6, minmax\(0, 1fr\)\)/);
  assert.match(css, /\.dplus-calculation-stage span \{ grid-column: 1 \/ -1; color: var\(--muted\)/);
  assert.match(css, /\.dplus-calculation-stage \{/);
});

test("Seed phrase offers one-based or zero-based BIP39 word-number entry", () => {
  assert.match(appSource, /name="seed-method" value="words"/);
  assert.match(appSource, /name="seed-method" value="numbers"/);
  assert.match(appSource, /hodlT\("seed.method.words"\)/);
  assert.match(appSource, /hodlT\("seed.method.numbers"\)/);
  assert.match(appSource, /id="seed-zero-index"/);
  assert.match(appSource, /hodlT\("seed.zeroIndexNote"\)/);
  assert.match(appSource, /function hodlTranslateSeedNumberIndex\(value, toZeroIndexed\)/);
  assert.match(appSource, /function hodlSeedNumberCanInsertDigit\(input, digit, zeroIndexed = hodlSeedZeroIndexed\)/);
  assert.match(appSource, /function hodlAutocompleteSeedNumberInput\(input, event, targetWords = hodlTargetWordCount, zeroIndexed = hodlSeedZeroIndexed\)/);
  assert.match(appSource, /number <= 204 \|\| number > maximum/);
  assert.match(appSource, /class="dice-input-pad seed-number-pad"/);
  assert.match(appSource, /\[0, 1, 2, 3, 4, 5, 6, 7, 8, 9\]/);
  assert.match(appSource, /id="seed-number-words" class="dice-word-grid"/);
  assert.match(css, /\.dice-input-pad\.seed-number-pad \{ grid-template-columns: repeat\(5/);
  assert.match(appSource, /passphrase = !keyMode \|\| hdBrain/);
});

test("hashed cards can match Ian Coleman's suit-symbol SHA-256 transcript", () => {
  assert.match(appSource, /id="cards-ian-coleman"/);
  assert.match(appSource, /Match Ian Coleman method/);
  assert.match(appSource, /show and hash A\\u2660 2\\u2663 instead of As 2c/);
  assert.match(appSource, /placeholder = direct \? "A284 37A2 \\u2026" : hodlCardColemanSymbols \? "A\\u2660 2\\u2663 T\\u2665 T\\u2666\\u2026" : "As 2c Th Td\\u2026"/);
  assert.match(appSource, /autocapitalize="off" aria-labelledby="cards-input-label"/);
  assert.match(appSource, /function hodlCardsHashInput\(cards, coleman = false\)/);
  assert.match(appSource, /transcript\.replace\(\/c\/g, "\\u2663"\)\.replace\(\/d\/g, "\\u2666"\)\.replace\(\/h\/g, "\\u2665"\)\.replace\(\/s\/g, "\\u2660"\)/);
  assert.match(appSource, /hodlFilterCards\(value, hodlCardColemanSymbols\)/);
  assert.match(appSource, /input\.value = hodlFilterCards\(input\.value, hodlCardColemanSymbols\)/);
});

test("Number bases offers exact Base 2, 4, 8, 16, Crockford Base32, and Base64-alphabet input", () => {
  assert.match(appSource, /hodlT\(`mode\.\$\{mode\}`\)/);
  assert.doesNotMatch(template, />Hex or binary<\/button>/);
  assert.ok(app.includes('formatChoices=["bin","base4","base8","hex","base32","base64"]'));
  assert.match(app, /name="entropy-format" value="\$\{id\}"/);
  for (const label of ["Binary (Base 2)", "Base 4", "Octal (Base 8)", "Hexadecimal (Base 16)", "Crockford Base32", "Base64 (RFC 4648 alphabet)"]) {
    assert.ok(app.includes(`label:"${label}"`), label);
  }
  assert.match(app, /alphabet:"0123456789ABCDEFGHJKMNPQRSTVWXYZ"/);
  assert.match(app, /alphabet:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+\/"/);
  assert.match(app, /function hodlNumberBaseEntropy\(value,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /function hodlNumberBasePreviewWords\(value,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /function hodlNumberBaseValueFromBytes\(bytes,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /id="show-number-base-calculations"/);
  assert.match(app, /function hodlBinaryCalculationRows\(value,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /id="number-base-calculations" class="number-base-calculations-panel"/);
  assert.match(appSource, /id="global-sync-host"/);
  assert.doesNotMatch(appSource, /global-sync-hash-host/);
  assert.match(appSource, /id="global-entropy-sync"/);
  assert.match(app, /globalSync:!1/);
  assert.match(app, /entropyFormat:"bin"/);
  assert.ok(app.includes('function hodlNormalizeEntropyFormat(format){return Object.hasOwn(hodlEntropyFormats,String(format??""))?String(format):"bin"}'));
  assert.match(css, /\.global-sync-status \{[\s\S]*?color: var\(--ok\)/);
  // The sync control stacks: switch and title on one row, explanation beneath.
  assert.match(appSource, /<div class="global-sync-head">/);
  assert.match(appSource, /<span class="label">Sync entropy across methods<\/span><\/label>/);
  assert.match(appSource, /<p class="seed-autocomplete-note global-sync-note" id="global-sync-note">/);
  // The explanation describes the switch instead of naming it.
  assert.match(appSource, /id="global-entropy-sync" aria-describedby="global-sync-note"/);
  assert.doesNotMatch(appSource, /<strong>Sync entropy across methods<\/strong>/);
  assert.match(css, /\.global-sync-row \{ display: block; \}/);
  assert.match(css, /\.global-sync-head \{ display: flex; align-items: center;/);
  // It gives up the shared toggle's chip chrome, but not its 44px target, and
  // the chip elsewhere keeps both.
  // The chip's 44px box left 13px of its own height under the title; the row
  // hugs its content instead, staying full width and above the 24px floor.
  assert.match(css, /\.global-sync-toggle \{[^}]*min-height: 32px;[^}]*padding: 0; border: 0; background: none; \}/);
  assert.match(css, /\.seed-autocomplete-toggle \{[^}]*min-height: 44px;[^}]*border: 1px solid var\(--border\);[^}]*background: var\(--surface-2\);/s);
  // The title matches the Method label above it.
  assert.match(css, /\.global-sync-toggle \.label \{ margin: 0; \}/);
  // The explanation is subordinate to that title and sits directly under it.
  assert.match(css, /\.global-sync-note \{ display: block; margin: 0; font-size: 13px; line-height: 1\.45; \}/);
  // Whatever comes off the top is given back below, so the control sits with
  // the method it qualifies rather than centred in its own gap. Padding, not
  // margin: a bottom margin would collapse into .seed-length-control's larger
  // top margin and buy nothing.
  assert.match(css, /\.global-sync-host \{ margin-top: var\(--space-control\); padding-bottom: var\(--space-control\); \}/);
  assert.match(css, /\.number-base-calculation-list \{/);
  assert.match(app, /fields:\{[\s\S]*?base4:"",base8:"",base32:"",base64:""/);
  assert.match(app, /function hodlBase64KeyboardMarkup\(\)\{return hodlKeyboardMarkup\(!0,"Base64 entropy","base64-keyboard"\)\}/);
  assert.match(app, /function hodlBindBase64Keyboard\(input\)/);
  assert.match(app, /hodlT\("hex.heads"\)/);
  assert.match(app, /hodlT\("hex.tails"\)/);
  assert.match(css, /\.dice-input-pad\.entropy-keypad \{ grid-template-columns: repeat\(8[^}]*grid-auto-flow: row;/);
  assert.match(css, /\.dice-input-pad\.entropy-keypad\.coin-phase \{ grid-template-columns: repeat\(2/);
  assert.match(css, /\.dice-input-pad\.entropy-keypad-bin \{ grid-template-columns: repeat\(2/);
  assert.match(css, /\.dice-input-pad\.entropy-keypad-base4 \{ grid-template-columns: repeat\(4/);
  assert.doesNotMatch(css, /\.entropy-keypad-(?:base8|hex|base32)[^}]*grid-template-columns/);
});

test("dealt playing cards use theme-appropriate surfaces", () => {
  assert.match(css, /:root \{[\s\S]*?--playing-card-bg: #292929;[\s\S]*?--playing-card-fg: #eeeeee;/);
  assert.match(css, /:root\[data-theme="light"\] \{[\s\S]*?--playing-card-bg: #ffffff;[\s\S]*?--playing-card-fg: #111111;/);
  assert.match(css, /\.dealt-card \{[\s\S]*?background: var\(--playing-card-bg\); color: var\(--playing-card-fg\);/);
  assert.match(css, /\.dealt-card\.is-red \{ color: var\(--playing-card-red\); \}/);
});

test("card undo uses the keyboard delete icon and one rank-grid column", () => {
  assert.match(app, /class="card-undo-button seed-keyboard-delete" id="card-undo"[^>]*aria-label="\$\{hodlT\("cards.undo"\)\}"[^>]*><svg viewBox="0 0 24 18"/);
  assert.match(appSource, /function hodlSetInputValueAtEnd\(input, value\)/);
  assert.match(appSource, /hodlSetInputValueAtEnd\(input, value\);\s*input\.dispatchEvent\(new Event\("input"\)\)/);
  assert.match(css, /\.card-controls-row \{[\s\S]*?grid-template-columns: repeat\(7, minmax\(0, 1fr\)\)/);
  assert.match(css, /@media \(min-width: 640px\) \{\s*\.card-controls-row \{ grid-template-columns: repeat\(13, minmax\(0, 1fr\)\); \}/);
});

test("Cards offers isolated hashed and direct word-selection methods", () => {
  assert.match(app, /name="card-method" value="hashed"/);
  assert.match(app, /name="card-method" value="direct"/);
  assert.match(app, /hodlT\("cards.direct.title"\)/);
  assert.match(appSource, /fields: \{[\s\S]*?cards: "", directCards: ""/);
  assert.match(appSource, /direct \? "" : `<div class="card-suit-pad"/);
  assert.match(appSource, /hodlDirectCardRanks = \["A", "2", "3", "4", "5", "6", "7", "8"\]/);
  assert.match(appSource, /dealt-card dealt-card-rank-only/);
  assert.match(appSource, /For each of the first \$\{config\.partialWords\} words/);
  assert.match(appSource, /placeholder = direct \? "A284 37A2/);
  assert.match(appSource, /input\.onbeforeinput = direct \? \(event\) => hodlHandleGroupedSeparatorDelete/);
  assert.match(appSource, /else hodlHandleGroupedSeparatorDelete\(input, event\);/);
  assert.match(appSource, /<aside class="cards-reshuffle" id="cards-reshuffle" hidden><\/aside>\s*<div class="dealt-cards" id="dealt-cards"/);
  assert.match(appSource, /hodlDirectCardSetLabel\(parsed\.expectedMax\)/);
  assert.doesNotMatch(appSource, /Shuffle before the next draw\./);
});

test("hashed card buttons begin unselected and order suits Spades, Hearts, Clubs, Diamonds", () => {
  assert.match(appSource, /hodlCardSuits = \[\{ code: "S"[^\]]*\{ code: "H"[^\]]*\{ code: "C"[^\]]*\{ code: "D"/);
  assert.match(appSource, /hodlCardSuit = "", hodlCardRank = ""/);
  assert.match(appSource, /aria-pressed="false">\$\{suit\.symbol\}/);
  assert.match(appSource, /function hodlCardSelectionState\(cards, needed, selectedSuit = "", selectedRank = ""\)/);
  assert.match(appSource, /function hodlToggleCardChoice\(current, selected\)/);
  assert.match(appSource, /hodlCardSuit = hodlToggleCardChoice\(hodlCardSuit, button\.getAttribute\("data-card-suit"\)\)/);
  assert.match(appSource, /hodlCardRank = hodlToggleCardChoice\(hodlCardRank, button\.getAttribute\("data-card-rank"\)\)/);
});

test("seed phrase mode has a lowercase Jade-style on-screen keyboard", () => {
  assert.match(app, /function hodlSeedKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlPassphraseKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlPrivateKeyKeyboardToggleMarkup\(\)/);
  assert.match(app, /"passphrase-keyboard-toggle","on-screen passphrase keyboard"/);
  assert.match(app, /"private-keyboard-toggle","on-screen private key keyboard"/);
  assert.match(app, /function hodlSetOnScreenKeyboardOpen\(open\)/);
  assert.match(app, /querySelectorAll\("\[data-on-screen-keyboard-toggle\]"\)/);
  assert.match(app, /querySelectorAll\("\[data-on-screen-keyboard\]"\)/);
  assert.match(app, /<rect x="9" y="10"[^>]*>[\s\S]*<rect x="51" y="10" width="4"/);
  assert.match(app, /<rect x="12" y="18"[^>]*>[\s\S]*<rect x="48" y="18" width="4"/);
  assert.match(app, /function hodlSeedKeyboardMarkup\(\)/);
  assert.match(app, /data-seed-delete aria-label="Delete previous character"/);
  assert.match(app, /data-seed-keyboard-mode="lower"/);
  assert.match(app, /passphraseOnly\?`Change \$\{inputName\} character mode`:"Character mode switching is available for the passphrase"/);
  assert.match(app, />aA1<\/button><button[^>]*class="seed-keyboard-space"/);
  assert.match(app, /data-seed-key=" " aria-label="Enter space">space/);
  assert.ok(app.includes('number:["1234567890","!@#$%^&*()","-_+=/?\\\\"]'));
  assert.match(app, /Array\.from\(\{length:hodlSeedKeyboardLayouts\.number\[index\]\.length\}/);
  assert.match(app, /function hodlCycleSeedKeyboardLayout\(keyboard,button\)/);
  assert.match(app, /function hodlSetSeedKeyboardLayout\(keyboard,button,next\)/);
  assert.match(app, /order=\["lower","upper","number"\]/);
  assert.match(app, /function hodlSeedKeyboardCanEnterCharacter\(input,key,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /hodlBip39WordIndex=new Map\(hodlBip39Wordlist\.map\(\(word,index\)=>\[word,index\]\)\)/);
  assert.match(app, /hodlLastWordCache=new Map(?:\(\))?/);
  assert.match(app, /function hodlComputeTargetLastWords\(words,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /missingEntropyBits=config\.bits-prefixBits\.length/);
  assert.match(app, /for\(let suffix=0;suffix<2\*\*missingEntropyBits;suffix\+\+\)/);
  assert.match(app, /let finalContext=analysis\.finalContext,validation=/);
  assert.match(app, /options=context\.candidates/);
  assert.match(app, /function hodlSeedKeyboardCanEnterSpace\(input,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /words\.length<config\.words&&words\.every\(word=>hodlBip39WordSet\.has\(word\)\)/);
  assert.match(app, /function hodlUpdateSeedKeyboardKeys\(input,targetWords=hodlTargetWordCount\)/);
  // The seed keyboard doubles as the passphrase keyboard while that field has
  // focus, so the key-state update takes whichever keyboard is asking.
  assert.match(app, /function hodlUpdatePassphraseKeyboardKeys\(input,keyboardId="passphrase-keyboard"\)/);
  assert.match(app, /isPassphrase\(\)\?hodlUpdatePassphraseKeyboardKeys\(activeInput,"seed-keyboard"\)/);
  assert.match(app, /function hodlPrivateKeyboardCanEnterCharacter\(input,key\)/);
  assert.match(app, /function hodlUpdatePrivateKeyKeyboardKeys\(input,keyboardId="private-keyboard"\)/);
  assert.match(app, /function hodlPrivateKeyInitialCharacters\(kind,network\)/);
  assert.match(app, /network==="testnet"\?\["9","c"\]:\["5","K","L"\]/);
  assert.match(appWhitespace, /if\(kind==="minikey"\)return\["S"\]/);
  assert.match(app, /data-private-key-initial-row aria-label="Valid first characters" hidden/);
  assert.match(app, /keyboard\.classList\.toggle\("private-key-initial-options",show\)/);
  assert.match(app, /data-private-key-hex-keypad aria-label="Hexadecimal keypad" hidden/);
  assert.match(app, /\.\.\."0123456789"/);
  assert.match(app, /\.\.\."abcdef"/);
  assert.match(app, /keyboard\.classList\.toggle\("private-key-hex-options",hexOnly\)/);
  assert.match(css, /\.seed-keyboard\.private-key-initial-options \{ width: fit-content; \}/);
  assert.match(css, /\.private-key-hex-keypad \{ display: grid; gap: 4px; \}/);
  assert.match(app, /id="private-key-highlight" aria-hidden="true"/);
  assert.match(app, /id="private-key-meta" aria-live="polite"/);
  assert.match(app, /function hodlPrivateKeyInputAnalysis\(value,kind,network,trimBrainWallet=hodlBrainWalletTrimEnabled\(\)\)/);
  assert.match(app, /function hodlRenderPrivateKeyInputState\(input\)/);
  assert.match(app, /\$\{count2\} of 64 hexadecimal characters entered/);
  assert.match(app, /invalid character\$\{invalid\.length===1\?"":"s"\} highlighted/);
  assert.match(appWhitespace, /extra highlighted (?:·|\\xB7) remove to continue/);
  assert.match(app, /valid secp256k1 private key/);
  assert.match(app, /function hodlHexPrivateKeyPrefix\(value\)/);
  assert.match(app, /function hodlWifPrivateKeyPrefix\(value,network\)/);
  assert.match(app, /function hodlMiniPrivateKeyPrefix\(value\)/);
  assert.match(app, /name="kk" value="wif" checked/);
  assert.match(app, /name="kk" value="hex-key"/);
  assert.match(app, /hodlT\("key\.wif"\)/);
  assert.match(app, /hodlT\("key\.hex"\)/);
  assert.match(app, /function hodlDetectPrivateKeyKind\(value\)/);
  assert.match(app, /function hodlNormalizePrivateKeyKind\(kind,value=""\)/);
  assert.match(app, /var hodlPrivateKeyKinds=\["wif","hex-key","minikey","brain"\]/);
  assert.match(app, /function hodlPrivateKeyValues\(fields\)/);
  assert.match(app, /privateKeys:\{wif:"","hex-key":"",minikey:"",brain:""\}/);
  assert.match(app, /values\[previousKind\]=key\.value/);
  assert.match(app, /key\.value=values\[nextKind\]\|\|""/);
  assert.match(appWhitespace, /radio\.addEventListener\("input",change\);radio\.addEventListener\("change",change\)/);
  assert.match(app, /key\?\.dataset\.privateKeyKind\|\|checkedKeyKind/);
  assert.match(app, /function hodlPrivateKeyPlaceholder\(kind,network="mainnet"\)/);
  assert.match(appWhitespace, /if\(kind==="hex-key"\)return hodlHexPrivateKeyPrefix\(candidate\)/);
  assert.match(appWhitespace, /return hodlWifPrivateKeyPrefix\(candidate,hodlSelectedNetwork/);
  assert.match(app, /inputType==="insertFromPaste"/);
  assert.match(app, /function hodlAssertPrivateKeyKind\(value,network,kind,trimBrainWallet=!1\)/);
  assert.match(app, /keyKind:"wif"/);
  assert.match(app, /\^S\[1-9A-HJ-NP-Za-km-z\]\*\$/);
  assert.match(app, /prefixes=network==="testnet"\?\["9","c"\]:\["5","K","L"\]/);
  assert.match(app, /space\.disabled=kind!=="brain"/);
  assert.match(app, /function hodlDecodeMiniPrivateKey\(value\)/);
  assert.match(app, /\^S\(\?:\[1-9A-HJ-NP-Za-km-z\]\{21\}\|\[1-9A-HJ-NP-Za-km-z\]\{29\}\)\$/);
  assert.match(app, /function hodlPassphraseKeyboardMarkup\(\)/);
  assert.match(app, /function hodlPrivateKeyKeyboardMarkup\(\)/);
  assert.match(app, /function hodlBindPassphraseKeyboard\(inputId="pass",toggleId="passphrase-keyboard-toggle",inputName="passphrase",keyboardId="passphrase-keyboard"\)/);
  // Each on-screen keyboard owns a distinct element id, so two of them can
  // coexist without one binding stealing the other's keys.
  assert.match(app, /hodlKeyboardMarkup\(!0,"passphrase","passphrase-keyboard"\)/);
  assert.match(app, /hodlKeyboardMarkup\(!0,"private key","private-keyboard",!0\)/);
  assert.doesNotMatch(app, /hodlKeyboardMarkup\(!0\)/);
  assert.match(app, /function hodlRenderPassphraseKeyboard\(\)/);
  assert.match(app, /keyMode=hodlKeyMode==="key",hdBrain=hodlBrainHdActive\(\),privateKey=keyMode,passphrase=!keyMode\|\|hdBrain/);
  // Where the seed keyboard exists it already follows focus into the passphrase
  // box, so no second on-screen keyboard is rendered underneath it.
  assert.match(app, /shared=passphrase&&!!document\.getElementById\("seed-keyboard"\),ownToggle=passphrase&&!shared&&!hdBrain,enabled=!shared/);
  // Only one on-screen keyboard toggle per section: the seed keyboard and the
  // private-key keyboard each already serve the passphrase field too.
  assert.match(app, /ownToggle\?hodlPassphraseKeyboardToggleMarkup\(\):""/);
  assert.match(app, /passphrase\?\(ownToggle\?hodlPassphraseKeyboardToggleMarkup\(\):""\)\+hodlPassphraseBip39ToggleMarkup\(\)/);
  assert.match(app, /hodlPassphraseKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlPassphraseBip39ToggleMarkup\(checked=hodlPassphraseBip39Enabled\(\)\)/);
  assert.match(app, /function hodlAnalyzeBip39Passphrase\(value,activeCaret=null\)/);
  assert.match(app, /function hodlPassphraseBip39CanEnterCharacter\(input,key\)/);
  assert.match(app, /function hodlPassphraseBip39CanEnterSpace\(input\)/);
  assert.match(app, /passphraseBip39Words:!1/);
  assert.match(app, /hodlPrivateKeyKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlBrainWalletTrimEnabled\(\)/);
  assert.match(app, /id="brain-wallet-trim"/);
  assert.match(app, />Trim leading and trailing whitespace<\/strong>/);
  assert.match(app, /brainWalletTrim:!1/);
  assert.match(css, /\.brain-wallet-trim-toggle\[hidden\] \{ display: none; \}/);
  assert.doesNotMatch(appSource, /bitaddress\.org-style brain wallet/);
  assert.match(app, /id="private-key-input-help"[\s\S]*hodlPrivateKeyKeyboardToggleMarkup\(\)[\s\S]*<textarea id="key"/);
  assert.match(app, /privateKey\?"key":"pass",privateKey\?"private-keyboard-toggle":"passphrase-keyboard-toggle"/);
  assert.match(app, /hodlRenderPassphraseKeyboard\(\);return/);
  assert.match(template, /id="passphrase-field"[\s\S]*id="passphrase-keyboard-toggle-host" hidden[\s\S]*id="passphrase-highlight"[\s\S]*<input id="pass"/);
  assert.match(template, /id="master-fingerprint-preview"[\s\S]*id="passphrase-keyboard-host" hidden[\s\S]*id="key-settings"/);
  assert.match(app, /button\.disabled=constrained\?!hodlPassphraseBip39CanEnterCharacter\(input,button\.dataset\.seedKey\):!1/);
  assert.match(app, /function hodlBindSeedKeyboardDelete\(getInput,button,applyDelete=hodlApplySeedKeyboardKey\)/);
  assert.match(appWhitespace, /setTimeout\(\(\)=>\{holdTimer=null;repeated=true;remove\(\);if\(!button\.disabled\)repeatTimer=setInterval\(remove,69\)\},420\)/);
  assert.match(app, /\["pointerup","pointercancel","pointerleave","lostpointercapture"\]/);
  assert.match(appWhitespace, /if\(repeated\)\{event\.preventDefault\(\);repeated=false;return\}/);
  assert.match(app, /function hodlAutocompleteSeedInput\(input,event,completeExisting=!1,wholeWordlist=!1,enabledOverride=null\)/);
  assert.match(app, /id="passphrase-autocomplete"[^>]*checked/);
  assert.match(app, /function hodlAutocompletePassphraseInput\(input,event,completeExisting=!1\)/);
  assert.match(app, /passphraseAutocomplete:!0/);
  assert.match(app, /toggle\.checked&&hodlAutocompleteSeedInput\(input,null,!0\)/);
  assert.match(app, /inputType:"insertReplacementText"/);
  assert.match(appWhitespace, /toggle\.checked;input\.focus\(\{preventScroll:true\}\)/);
  assert.match(app, /event\.relatedTarget\?\.closest\?\.\("#seed-keyboard,\.seed-autocomplete-toggle"\)/);
  assert.match(app, /class="seed-entry-tools">\$\{hodlSeedKeyboardToggleMarkup\(\)\}<label class="seed-autocomplete-toggle"/);
  assert.match(app, /id="seed-meta"[^>]*><\/p>\$\{hodlSeedKeyboardMarkup\(\)\}<div id="last-words"/);
  assert.match(appWhitespace, /hodlBindSeedKeyboard\(input,config\.words\);hodlBindKeyFields\(\)/);
  assert.match(app, /keyboard\.querySelectorAll\("\[data-seed-delete\]"\)\.forEach\(button=>hodlBindSeedKeyboardDelete\(\(\)=>activeInput,button\)\)/);
  assert.match(app, /modeButton\.disabled=!pass/);
  assert.match(app, /hodlSetSeedKeyboardLayout\(keyboard,modeButton,"lower"\)/);
  assert.match(app, /hodlApplySeedKeyboardKey\(activeInput,button\.dataset\.seedKey\|\|""\)/);
  assert.match(appWhitespace, /hodlBindKeypadPointer\(keyboard\.querySelectorAll\("button"\),\(\)=>activeInput\)/);
  assert.match(app, /function hodlFilterSeed\(e\)\{[^}]*hodlLooksExtendedKey\(value\)\?value:value\.toLowerCase\(\)/);
  assert.match(css, /\.seed-entry-tools\s*\{[^}]*align-items: stretch[^}]*margin-top: var\(--space-component\)/s);
  assert.match(css, /\.passphrase-keyboard-tools \{[^}]*display: flex[^}]*margin-top: var\(--space-control\)/s);
  assert.match(css, /\.passphrase-keyboard-tools \{[^}]*display: flex[^}]*align-items: stretch[^}]*gap: var\(--space-control\)/s);
  assert.match(css, /\.dice-input-shell\.passphrase-input-shell input \{[^}]*position: relative[^}]*margin-top: 0[^}]*background: transparent[^}]*color: transparent/s);
  assert.match(css, /\.passphrase-bip39-options \{[^}]*flex: 1 1 auto[^}]*gap: var\(--space-control\)/s);
  assert.match(css, /\.passphrase-bip39-toggle, \.passphrase-autocomplete-toggle \{[^}]*width: 100%[^}]*margin-top: 0/s);
  assert.match(css, /\.passphrase-keyboard-host \.seed-keyboard \{ margin-top: var\(--space-control\); margin-right: auto; margin-left: 0; \}/);
  assert.match(css, /\.seed-keyboard-toggle,\s*\.theme-toggle\s*\{[^}]*width: 44px[^}]*min-height: 44px[^}]*height: auto/s);
  assert.match(css, /\.seed-keyboard-toggle svg \{[^}]*width: 30px[^}]*height: 22px/s);
  assert.match(css, /\.seed-keyboard-icon-case \{[^}]*fill: none[^}]*stroke: currentColor/s);
  assert.match(css, /\.seed-keyboard\s*\{[^}]*gap: 4px[^}]*max-width: 640px[^}]*margin: var\(--space-control\) auto 0 0[^}]*padding: 7px 8px/s);
  assert.match(css, /--seed-key-size: calc\(10% - 2\.7px\)/);
  assert.match(css, /\.seed-keyboard-key\[hidden\] \{ display: none; \}/);
  assert.match(css, /\.seed-keyboard-row \{ display: flex; justify-content: center;/);
  assert.match(css, /\.seed-keyboard-space-row \{ display: flex; justify-content: center; gap: 4px; \}/);
  assert.match(css, /\.seed-keyboard-mode:disabled \{[^}]*cursor: not-allowed[^}]*opacity: \.42/s);
  assert.match(css, /\.seed-keyboard-key:disabled,[\s\S]*?\.seed-keyboard-space:disabled \{[^}]*cursor: not-allowed[^}]*opacity: \.3/s);
});

test("multisig derivation settings follow the key inputs", () => {
  const fieldOrder = /id="msig-keys"[\s\S]*id="msig-key-order-status"[\s\S]*id="msig-hint"[\s\S]*id="msig-script-type"[\s\S]*id="msig-purpose"[\s\S]*id="msig-network"[\s\S]*id="msig-account"[\s\S]*id="msig-address-start"[\s\S]*id="msig-address-range"[\s\S]*id="msig-key-order"[\s\S]*id="msig-go"/;
  assert.match(template, fieldOrder);
  assert.match(app, fieldOrder);
});

test("key derivation and multisig use the accurate Script type label", () => {
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /id="script-type-field"[^>]*>[\s\S]*?Script type[\s\S]*?<select/);
    assert.match(markup, /<label class="field">(?:<span[^>]*>)?Script type(?:<\/span>)?\s*<select id="msig-script-type"[^>]*>/);
    assert.match(markup, /<option value="p2wsh" selected(?:="selected")?(?:\s[^>]*)?>Native SegWit<\/option>/);
    assert.match(markup, /<option value="p2tr"(?:\s[^>]*)?>Taproot<\/option>/);
    assert.doesNotMatch(markup, /<option value="p2wsh"[^>]*>[^<]*BIP48/);
    assert.doesNotMatch(markup, /name="msig-script"|Matches BIP48 script type|Bare P2SH/);
    assert.doesNotMatch(markup, />Address type</);
  }
});

test("key derivation separates script type from the hardened purpose index", () => {
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /id="script-type-field"[^>]*>[\s\S]*?Script type[\s\S]*?<select id="script-type">[\s\S]*?<option value="bip44"[^>]*>Legacy<\/option>[\s\S]*?<option value="bip49"[^>]*>Nested SegWit<\/option>[\s\S]*?<option value="bip84" selected(?:="selected")?[^>]*>Native SegWit<\/option>[\s\S]*?<option value="bip86"[^>]*>Taproot<\/option><\/select>/);
    assert.match(markup, /id="script-type"[\s\S]*id="purpose"[\s\S]*id="network"[\s\S]*id="account"/);
    assert.match(markup, /id="purpose" type="text" inputmode="numeric" value="84'"/);
    assert.match(markup, /id="purpose-help">Purpose index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="account-help">Account index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
  }
  assert.match(appSource, /function hodlReadPurpose\(mark = true\)/);
  assert.match(appSource, /hodlSetSelectedScriptType\(target\.value, true\)/);
  assert.match(appSource, /let derivedDefinition = \{ \.\.\.definition, purpose: purposeIndex, purposeHardened: hardening\.purpose \}/);
  assert.match(appSource, /originPath = derivationPlan\?\.originPath \?\?/);
  assert.match(appSource, /fields: \{ pass: "", script: "bip84", derivationPath: `m\/84'\/\$\{hodlDefaultCoinType\(\)\}'\/0'\/0\/0`, derivationAccountPath: `m\/84'\/\$\{hodlDefaultCoinType\(\)\}'\/0'`, purpose: "84'", purposeHarden: true, coinType: `\$\{hodlDefaultCoinType\(\)\}'`, coinTypeHarden: true, network: hodlNetworkDefault/);
});

test("one editable derivation path replaces schemes and accepts arbitrary depth", () => {
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /id="script-type-field">Script type[\s\S]*?id="derivation-path-field">Derivation path[\s\S]*?id="derivation-path" type="text" value="m\/84'\/0'\/0'\/0\/0"/);
    assert.match(markup, /<details class="derivation-advanced" id="derivation-advanced">[\s\S]*?<summary>Advanced entry<\/summary>/);
    assert.doesNotMatch(markup, /id="derivation-scheme"|id="custom-derivation-path"|id="scheme-script-index"/);
  }
  assert.match(appSource, /function hodlParseCustomDerivationPath\(value\)/);
  assert.match(appSource, /function hodlReadVisibleDerivationPath\(mark = true\)/);
  assert.match(appSource, /\.\.\.existing\.slice\(3\)/);
  assert.match(appSource, /accountPath = derivationPlan\?\.accountPath \|\| hodlAccountPath/);
});

test("advanced derivation indexes constrain and restore hardening suffixes", () => {
  assert.match(appSource, /function hodlSanitizeDerivationIndexDraft\(value\)/);
  assert.match(appSource, /function hodlRestoreAdvancedDerivationIndex\(input\)/);
  assert.match(appSource, /function hodlSyncAdvancedDerivationHardening\(input\)/);
  assert.match(appSource, /checkbox\.checked = parsed\.hardened/);
  assert.match(appSource, /input\.value = `\$\{parsed\.value\}\$\{parsed\.hardened \? "'" : ""\}`/);
  assert.match(appSource, /input\?\.addEventListener\("blur", \(\) => hodlRestoreAdvancedDerivationIndex\(input\)\)/);
  assert.match(appSource, /draft === "'" \? "0'" : hodlDefaultAdvancedDerivationIndex\(input\.id\)/);
});

test("derivation indexes keep adjacent Harden controls with safe defaults", () => {
  for (const markup of [template, appWhitespace]) {
    for (const id of ["purpose", "network", "account", "msig-purpose", "msig-network", "msig-account"]) {
      assert.match(markup, new RegExp(`id="${id}"[\\s\\S]*?id="${id}-harden" type="checkbox" checked`));
    }
    for (const id of ["branch-start", "address-start", "msig-branch-start", "msig-address-start"]) {
      assert.match(markup, new RegExp(`id="${id}"[\\s\\S]*?id="${id}-harden" type="checkbox"(?! checked)`));
    }
  }
  assert.match(css, /\.derivation-index-control \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\) auto;[\s\S]*?white-space: nowrap;/);
  assert.match(css, /\.derivation-index-prime \{[\s\S]*?left: 12px;[\s\S]*?white-space: pre;/);
  assert.match(css, /\.derivation-index-prime::before \{ content: attr\(data-index-value\); color: transparent; \}/);
  assert.match(appSource, /function hodlReadHardening\(prefix = ""\)/);
  assert.match(appSource, /function hodlSyncDerivationPrime\(input\)/);
  assert.match(appSource, /prime\.dataset\.indexValue = String\(input\.value \?\? ""\)/);
  assert.match(appSource, /hodlPathComponent\(e\.purpose, hardening\.purpose\)/);
  assert.match(appSource, /Hardened address indexes cannot be derived from multisig extended public keys/);
});

test("multisig script type and placeholders follow detected co-signer exports", () => {
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /option value="mixed" disabled data-custom-select-placeholder="true"(?:\s[^>]*)?>Mixed · incompatible keys/);
    assert.match(markup, /id="msig-script-warning" role="status" hidden/);
    assert.match(markup, /id="msig-go"[^>]*aria-describedby="msig-script-warning"/);
  }
  assert.match(template, /placeholder="\[fingerprint\/48h\/0h\/0h\/2h\]xpub…"/);
  assert.match(app, /function hodlMultisigKeyPlaceholder\(kind,network,purpose,coinType=hodlCoinTypeFromNetwork\(network\),hardening=/);
  assert.match(appWhitespace, /kind==="p2sh"&&purpose===45\)return`\[fingerprint\/\$\{purposeStep\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2sh"\|\|purpose===87\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2sh-p2wsh"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\/1h\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2wsh"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\/2h\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2tr"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(app, /function hodlMultisigPurposeIndex\(origin\)/);
  assert.match(app, /function hodlUpdateMsigPurposeDetection\(\)/);
  assert.doesNotMatch(app, /or BIP48 script 3h/);
  assert.doesNotMatch(app, /if\(steps\[3\]==="3h"\)return"p2tr"/);
  assert.match(app, /hodlT\("error\.msig\.purposeMixed"/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /if\(kind==="mixed"\)throw hodlError\("error\.msig\.mixedScripts"\)/);
});

test("key derivation shows the relevant paste-ready multisig co-signer exports", () => {
  assert.match(app, /function hodlBuildMultisigCosignerExports\(root,network,accountIndex,masterFingerprint,coinType=hodlCoinTypeFromNetwork\(network\)\)/);
  assert.match(appWhitespace, /accountId:"bip44",kind:"p2sh",standard:"bip45",label:"Legacy (?:·|\\xB7) BIP45 (?:·|\\xB7) No account",family:"x",accountPath:"m\/45'",originPath:"45h"/);
  assert.match(appWhitespace, /accountId:"bip44",kind:"p2sh",standard:"bip87",label:`Legacy (?:·|\\xB7) BIP87 (?:·|\\xB7) Account \$\{accountIndex\}`,family:"x",accountPath:`m\/87'\/\$\{coinType\}'\/\$\{accountIndex\}'`,originPath:`87h\/\$\{coinType\}h\/\$\{accountIndex\}h`/);
  assert.match(appWhitespace, /accountId:"bip49",kind:"p2sh-p2wsh",label:"Nested SegWit (?:·|\\xB7) BIP48",family:"x",scriptIndex:1/);
  assert.match(appWhitespace, /accountId:"bip84",kind:"p2wsh",label:"Native SegWit (?:·|\\xB7) BIP48",family:"x",scriptIndex:2/);
  assert.match(appWhitespace, /accountId:"bip86",kind:"p2tr",label:"Taproot (?:·|\\xB7) BIP86",family:"x"/);
  assert.match(app, /accountPath=definition\.accountPath\|\|`m\/48'\/\$\{coinType\}'\/\$\{accountIndex\}'\/\$\{definition\.scriptIndex\}'`/);
  assert.match(app, /value:`\[\$\{masterFingerprint\}\/\$\{originPath\}\]\$\{publicKey\}`/);
  assert.match(app, /multisigCosignerExports:root\.privateKey\?hodlBuildMultisigCosignerExports\(root,network,accountIndex,masterFingerprint,coinType\):\[\]/);
  assert.match(app, /function hodlRenderMultisigCosignerExport\(exports,accountId\)/);
  assert.match(app, /exports\.filter\(candidate=>candidate\.accountId===accountId\)/);
  assert.match(appWhitespace, /items\.map\(item=>hodlPublicFieldHtml\(hodlT\("result\.cosignerExport",\{prefix:item\.prefix,label:item\.label\}\),item\.value\)\)\.join\(""\)/);
  assert.match(app, /\$\{hodlSlip132WatchFields\(account,hodlWalletResult\)\}\s*\$\{hodlImportedCoreRecoveryExport\(hodlWalletResult,account\)\}\s*\$\{hodlRenderMultisigCosignerExport\(hodlWalletResult.multisigCosignerExports,account\.def\.id\)\}/);
  assert.doesNotMatch(`${app}\n${css}`, /account-multisig-exports/);
  assert.match(app, /Legacy P2SH requires the depth-1 BIP45 purpose key at m\/45h/);
  assert.match(app, /suffix=bip45\?`\/0\/\$\{branch\}\/\*`:`\/\$\{branch\}\/\*`/);
  assert.match(app, /Legacy BIP45 addresses use co-signer branch 0/);
  assert.match(app, /Legacy P2SH uses the selected BIP87 account paths/);
  assert.match(app, /function hodlMsigInnerDescriptor\(kind,m,inner,sorted\)/);
  assert.match(app, /function hodlMsigPolicyOp\(kind,sorted\)/);
  assert.match(app, /kind==="p2tr"\?sorted\?"sortedmulti_a":"multi_a":sorted\?"sortedmulti":"multi"/);
  // The branch descriptor is the source of truth: rust-miniscript (in the
  // WASM crate) derives every multisig address from it via descriptorDerive,
  // and the address-match look-ahead reuses the same engine through
  // hodlMsigAddr's raw-key descriptor.
  assert.match(app, /descriptorDerive\(descriptor,index,network\)/);
  assert.match(app, /hodlMsigAddr\(keys,hodlWalletResult\.m,hodlWalletResult\.network,hodlWalletResult\.script,hodlWalletResult\.sorted!==!1\)/);
  assert.match(app, /function hodlTaprootNumsKey\(\)/);
  assert.match(app, /function hodlXOnlyPubkey\(pubkey\)/);
});

test("derived wallets offer an address match check", () => {
  assert.match(app, /function hodlAddressMatchMarkup\(\)/);
  assert.match(app, /id="address-match"/);
  assert.match(app, /id="address-match-status"/);
  assert.match(app, /address-match-field">Check an address/);
  assert.match(app, /Paste an address shown by another wallet/);
  assert.match(app, /even if the index is beyond the table above/);
  assert.doesNotMatch(app, /Address from Sparrow/);
  // esbuild's output normalizes numeric literals (1000 -> 1e3) in every
  // transform, so check this literal against the untransformed source.
  assert.match(appSource, /var hodlAddressSearchLimit\s*=\s*1000/);
  assert.match(app, /function hodlMatchHdAddressBeyond\(address,account,start\)/);
  assert.match(app, /function hodlMatchMsigAddressBeyond\(address,start\)/);
  assert.match(app, /hodlAddressBranchTables\(branches,hasPrivate,"hd"\)\}\s*\$\{hodlAddressMatchMarkup\(\)/);
  assert.match(app, /hodlAddressBranchTables\(branches,!1,"msig"\)\}\s*\$\{hodlAddressMatchMarkup\(\)/);
  assert.match(css, /\.address-match-field/);
});

test("multisig key order is sorted by default and listed order is advanced", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /id="msig-advanced"/);
    assert.match(markup, /id="msig-key-order"/);
    assert.match(markup, /<option value="sorted" selected(?:="selected")?(?:\s[^>]*)?>Sorted (?:·|\\xB7) sortedmulti<\/option>/);
    assert.match(markup, /<option value="listed"(?:\s[^>]*)?>As listed (?:·|\\xB7) multi<\/option>/);
    assert.match(markup, /id="msig-key-order-status" hidden/);
  }
  assert.match(css, /\.msig-advanced summary/);
  assert.match(css, /\.msig-key-move-btn/);
  assert.match(app, /function hodlMsigKeysSorted\(\)/);
  assert.match(app, /function hodlBindMsigKeyReorder\(box\)/);
  assert.match(app, /function hodlMoveMsigKeyRow\(row,offset\)/);
  assert.match(app, /hodlT\("msig.moveUp"\)/);
  assert.match(app, /hodlT\("msig.moveDown"\)/);
  assert.match(app, /function hodlMsigScriptOrder\(keyTokens\)/);
  assert.match(app, /id="multisig-order-heading">\$\{hodlT\("msig\.orderHeading"\)\}/);
  assert.match(app, /keyOrder:"sorted"/);
  assert.match(app, /listed co-signer order is part of the script/);
});

test("multisig separates script type from purpose and keeps the Legacy BIP87 shortcut", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /id="msig-script-type"[\s\S]*id="msig-purpose"[\s\S]*id="msig-network"[\s\S]*id="msig-account"/);
    assert.match(markup, /id="msig-purpose" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="48"/);
    assert.match(markup, /id="msig-purpose-help"[^>]*>Purpose index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="msig-account-help"[^>]*>Account index (?:·|\\xB7) Hardened (?:·|\\xB7) Derived from co-signer key origins/);
    assert.match(markup, /id="msig-legacy-account-toggle" hidden/);
    assert.match(markup, /id="msig-legacy-bip87" type="checkbox"/);
    assert.match(markup, />Use standardized BIP87 accounts</);
    assert.match(markup, /m\/87h\/coinh\/accounth/);
  }
  assert.match(css, /\.msig-legacy-account-toggle\[hidden\] \{ display: none !important; \}/);
  assert.match(appSource, /if \(toggle\) toggle\.hidden = kind === "p2tr"/);
  assert.match(app, /hodlSetMsigPurpose\(hodlStandardMsigPurpose\(\)\)/);
  assert.match(appSource, /if \(kind === "p2tr"\) return 87;/);
  assert.match(appSource, /if \(document\.getElementById\("msig-legacy-bip87"\)\?\.checked\) return 87;/);
  assert.match(appSource, /if \(kind === "p2sh"\) return 45;/);
  assert.match(app, /hodlSetMsigPurpose\(hodlStandardMsigPurpose\(script\.value\)\)/);
  assert.match(app, /legacyBip87:!1/);
  assert.match(app, /purpose:"48"/);
  assert.match(app, /purposeIndexes\.push\(hodlMultisigPurposeIndex\(parsed\.origin\)\)/);
});

test("Native SegWit multisig uses the imported Bitcoin address encoder", () => {
  // hodlMsigAddr turns the keys into a wsh(sortedmulti(...)) descriptor and
  // the WASM crate (rust-miniscript) renders the address from it.
  assert.match(appSource, /`wsh\(\$\{inner\}\)`/);
  assert.match(appSource, /descriptorDerive\(descriptor, 0, network\)/);
  assert.doesNotMatch(appSource, /\bor\(net\)\.encode/);
});

test("every facade export app.js calls is imported from that facade", () => {
  // Pinning the addresses.js import list verbatim once let a used-but-
  // unimported helper ship (p2trLeafScript threw ReferenceError at runtime).
  // A hardcoded name list can lock in the next omission the same way, so
  // derive the expectation: for every local module app.js imports from, every
  // export the file actually calls must be in that module's import statement.
  const body = appSource.replace(/^import \{[^}]*\} from "\.\/[^"]+";$/gm, "");
  const importPattern = /^import \{([^}]*)\} from "\.\/([\w-]+)\.js";$/gm;
  let statement;
  const problems = [];
  while ((statement = importPattern.exec(appSource))) {
    const imported = new Set(statement[1].split(",").map((name) => name.trim().split(" as ").pop().trim()));
    const module = `src/js/${statement[2]}.js`;
    let exportsSource;
    try {
      exportsSource = read(module);
    } catch {
      continue; // not a source module (e.g. generated); nothing to check
    }
    const exported = new Set();
    for (const match of exportsSource.matchAll(/^export (?:const|function|class) (\w+)/gm)) exported.add(match[1]);
    for (const match of exportsSource.matchAll(/export \{([^}]*)\}/gm)) {
      for (const entry of match[1].split(",")) {
        const name = entry.trim().split(" as ").pop().trim();
        if (name) exported.add(name);
      }
    }
    for (const name of exported) {
      if (imported.has(name) || !new RegExp(`\\b${name}\\(`).test(body)) continue;
      // A local declaration shadows the import site and cannot throw.
      if (new RegExp(`function ${name}\\(|(?:const|let|var) ${name} =`).test(body)) continue;
      problems.push(`app.js calls ${name}() but does not import it from ./${statement[2]}.js`);
    }
  }
  assert.deepEqual(problems, [], problems.join("\n"));
});

test("the master fingerprint cards reserve a compact empty square for each LifeHash", () => {
  // Both cards keep a frame beside the value, while the image itself starts hidden.
  assert.match(app, /id="base-master-fingerprint-card"[\s\S]*?class="master-fingerprint-lifehash-frame"[\s\S]*?id="base-master-fingerprint-lifehash"[^>]*hidden/);
  assert.match(app, /id="passphrase-master-fingerprint-card"[\s\S]*?class="master-fingerprint-lifehash-frame"[\s\S]*?id="passphrase-master-fingerprint-lifehash"[^>]*hidden/);
  // The card setter renders the deterministic icon for the shown fingerprint.
  assert.match(app, /function hodlSetMasterFingerprintCard\(card,valueNode,value,imageNode\)/);
  assert.match(app, /hodlLifeHash\.fromFingerprint\(value\)/);
  assert.match(appSource, /imageNode\.hidden = true;\s*imageNode\.removeAttribute\("src"\);/);
  assert.match(appSource, /imageNode\.src = url;\s*imageNode\.hidden = false;/);
  assert.match(css, /\.master-fingerprint-card \{[^}]*display: grid;/);
  assert.match(css, /\.master-fingerprint-lifehash-frame \{[^}]*width: 40px; height: 40px;/);
  assert.doesNotMatch(css, /\.master-fingerprint-lifehash-frame \{[^}]*float: right;/);
  assert.match(css, /\.master-fingerprint-value \{[^}]*overflow: hidden;/);
  assert.match(css, /\.master-fingerprint-preview \{ display: grid; grid-template-columns: minmax\(0, 1fr\); gap: 8px; \}/);
  // Crisp pixels per the LifeHash presentation guidance.
  assert.match(css, /\.master-fingerprint-lifehash \{[^}]*image-rendering: pixelated;/);
});

test("the build inlines the LifeHash module", () => {
  const buildScript = read("scripts/build.mjs");
  assert.match(buildScript, /lifehash\.js/);
  assert.match(buildScript, /\/\*@@JS_LIFEHASH@@\*\//);
  assert.match(template, /<script>\/\*@@JS_LIFEHASH@@\*\/<\/script>/);
});

test("account results do not repeat derivation settings shown above", () => {
  assert.doesNotMatch(app, /account-summary-grid|function hodlAccountSummaryItem/);
  assert.doesNotMatch(css, /\.account-summary-grid/);
});

test("multisig account is displayed as a disabled value derived from key origins", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /<input id="msig-account" type="text" value="" placeholder="Derived from keys"[^>]*disabled/);
    assert.match(markup, /id="msig-account-warning" role="status" hidden/);
  }
  assert.match(app, /function hodlUpdateMsigAccount\(\)/);
  assert.match(app, /field\.value=summary\.mixed\?"Mixed"/);
  assert.match(app, /account:accountSummary\.account/);
  assert.match(app, /accountMixed:accountSummary\.mixed/);
});

test("multisig threshold labels describe signatures and keys", () => {
  for (const markup of [template, app]) {
    assert.match(markup, />Signatures needed to spend \(m\)/);
    assert.match(markup, />Total signing keys \(n\)/);
    assert.doesNotMatch(markup, /People \/ devices \(n\)/);
    assert.match(markup, /id="msig-m-number" type="number" min="1" max="15"[^>]*value="2"/);
    assert.match(markup, /id="msig-n-number" type="number" min="1" max="15"[^>]*value="3"/);
    assert.match(markup, /id="msig-m" type="range" min="1" max="15"[^>]*value="2"/);
    assert.match(markup, /id="msig-n" type="range" min="1" max="15"[^>]*value="3"/);
    assert.doesNotMatch(markup, /msig-threshold-ratio|msig-[mn]-output/);
    assert.doesNotMatch(markup, /<select id="msig-[mn]"/);
    assert.ok(markup.indexOf('class="msig-threshold-labels"') < markup.indexOf('<fieldset class="msig-threshold-control"'));
  }
  assert.match(css, /\.msig-threshold-number\s*\{[^}]*appearance: textfield[^}]*text-align: center/s);
  assert.match(css, /\.msig-threshold-labels label\s*\{[^}]*flex-direction: column[^}]*justify-content: flex-end;/s);
  assert.match(css, /\.msig-threshold-track span\s*\{[^}]*background: var\(--selection-accent\)/s);
  assert.match(css, /\.msig-threshold-thumb\s*\{[^}]*background: linear-gradient\(#858585, #5f5f5f\)/s);
  assert.match(css, /--msig-slider-inset: 14px/);
  assert.match(css, /\.msig-threshold-control\s*\{[^}]*margin: var\(--space-control\) 0 0/s);
  assert.match(css, /\.msig-threshold-labels\s*\{[^}]*margin: var\(--space-section\) 18px 0/s);
  assert.match(css, /\.msig-threshold-slider\s*\{[^}]*margin: 0 var\(--msig-slider-inset\)/s);
  assert.match(css, /\.msig-threshold-ticks\s*\{[^}]*margin: 0 var\(--msig-slider-inset\)/s);
  assert.match(css, /\.msig-threshold-ticks span\s*\{[^}]*left: var\(--msig-tick-position\)[^}]*transform: translateX\(-50%\)/s);
  assert.match(app, /hodlMsigSliderBaseMax=9,hodlMsigSliderLimit=15/);
  assert.match(app, /drag\.handle=delta<0\?"m":"n"/);
  assert.match(app, /visibleMax=Math\.max\(hodlMsigSliderBaseMax,n\)/);
  assert.match(app, /mNumber\.max=String\(hodlMsigSliderLimit\)/);
  assert.match(app, /nNumber\.min="1"/);
  assert.match(app, /n=hodlClampMsigThreshold\(nValue,1,hodlMsigSliderLimit\)/);
  assert.match(app, /m>=1&&n>=1&&m<=n&&n<=15/);
  assert.match(appWhitespace, /if\(moveOther\)\{if\(changed==="m"\)n=Math\.max\(n,m\);else if\(changed==="n"\)m=Math\.min\(m,n\)\}/);
  assert.match(app, /setActive=\(handle,value\)=>\{.*hodlChangeMsigThreshold\(handle,value,!0\)\}/);
  assert.match(app, /mInput\.addEventListener\("input",\(\)=>hodlChangeMsigThreshold\("m",mInput\.value,!0\)\)/);
  assert.match(app, /nInput\.addEventListener\("input",\(\)=>hodlChangeMsigThreshold\("n",nInput\.value,!0\)\)/);
  assert.match(app, /hodlChangeMsigThreshold\(handle,raw,!0\)/);
  assert.match(appWhitespace, /bindNumber\(mNumber,"m"\);bindNumber\(nNumber,"n"\)/);
  assert.match(app, /tick\.style\.setProperty\("--msig-tick-position",\(value-1\)\/span\*100\+"%"\)/);
});

test("multisig consistently uses derive for its heading and action", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /<h2[^>]*>Derive a multisig wallet<\/h2>/);
    assert.match(markup, /id="msig-go"[^>]*>Derive Multisig<\/button>/);
    assert.match(markup, /id="msig-go"[^>]*disabled[^>]*aria-disabled="true"/);
    assert.doesNotMatch(markup, /Create a multisig wallet|Build Multisig/);
  }
  assert.match(app, /function hodlValidatedMsigInputs\(\)/);
  assert.match(appSource, /hodlValidatedMsigInputs\(\);\s*ready = true/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /let\{network,coinType,count,addressStart,branchStart,branchRange,n,m,kind,purpose,hardening,legacyStandard,nodes,xpubs,keyTokens,accountSummary,accountWarning\}=hodlValidatedMsigInputs\(\)/);
});

test("Station add controls stay pinned to the right of their tab strips", () => {
  assert.match(css, /\.key-tab-strip \{ display: flex; align-items: flex-end; min-width: 0; margin-top: 12px; \}/);
  assert.match(css, /\.key-tabs \{\s*display: flex;[^}]*flex: 1 1 auto; min-width: 0;/s);
  assert.match(css, /\.add-item-control \{ position: relative; display: inline-flex; flex: 0 0 auto; \}/);
});

test("the Key Station method picker is one dropdown carrying every method's mark", () => {
  for (const markup of [template, appSource]) {
    // #modes hosts the title and the dropdown; the segmented row is gone.
    assert.match(markup, /<div class="key-mode-select" id="modes"><p class="label" id="key-method-label"[^>]*>Method<\/p><\/div>/);
    assert.doesNotMatch(markup, /key-mode-control|key-mode-label/);
  }
  // The title is the control's accessible name, so speech input can say it.
  assert.match(css, /\.key-mode-select > \.label \{ margin: 0 0 8px; \}/);
  assert.doesNotMatch(template, /Brain wallet — lab/);
  // The labels live in the locale catalogs; the dropdown reads them through hodlT.
  assert.match(appSource, /option\.textContent = hodlT\(`mode\.\$\{mode\}`\);/);
  for (const mode of ["dice", "cards", "hex", "seed", "key"]) {
    assert.ok(en[`mode.${mode}`]?.length > 0, `mode.${mode} label is missing from the English catalog`);
  }
  assert.equal(en["mode.dice"], "Dice rolls");
  assert.equal(en["mode.hex"], "Number bases");
  assert.equal(en["mode.seed"], "Seed phrase");
  assert.equal(en["mode.key"], "Private key");
  // The marks outlived the buttons: the dropdown shows them instead.
  assert.match(appSource, /function hodlCreateKeyMethodIcon\(mode\) \{/);
  for (const mode of ["dice", "cards", "hex", "seed"]) {
    assert.match(appSource, new RegExp(`mode === "${mode}"`), `${mode} icon branch is missing`);
  }
  assert.match(appSource, /else \{\s*add\("circle", \{ cx: "7\.5"/);
  assert.match(appSource, /fill: "var\(--key-method-card-bg\)", "data-part": "card-front"/);
  // A plain select that enhanced-inputs.js upgrades, so it is the Script type
  // control's chrome rather than a second dropdown implementation.
  assert.match(appSource, /hodlKeyModeSelectEl\.id = "key-mode-select";/);
  assert.match(appSource, /hodlKeyModeSelectEl\.setAttribute\("aria-labelledby", "key-method-label"\);/);
  assert.match(appSource, /hodlKeyModeSelectEl\.entropylabOptionIcon = \(value\) => hodlCreateKeyMethodIcon\(value\);/);
  assert.match(appSource, /hodlModesEl\.appendChild\(hodlKeyModeSelectEl\);/);
  // Every path that changes the method moves the control, and the sync cannot
  // loop back through onchange.
  assert.match(appSource, /function hodlSyncKeyModeSelect\(\) \{/);
  assert.match(appSource, /hodlKeyModeSelectEl\.dispatchEvent\(new Event\("entropylab:sync-select"\)\);/);
  assert.equal(appSource.match(/hodlSyncKeyModeSelect\(\);/g).length, 3, "every method update must move the dropdown");
  // No button plumbing is left behind.
  assert.doesNotMatch(appSource, /hodlModesEl\.children/);
  assert.doesNotMatch(css, /\.key-mode-control/);
  // Choosing a method invalidates the live result; opening the list does not.
  assert.match(appSource, /closest\("#modes \.custom-select-option, #seed-length \.custom-select-option/);
  // The mark rides ahead of the label in the button and in every option.
  assert.match(css, /\.key-method-icon \{\s*display: inline-flex; flex: 0 0 18px;/);
  assert.match(css, /\.key-mode-select \.custom-select-option \{ display: flex; align-items: center; gap: 8px; \}/);
  assert.match(css, /\.key-mode-select \.custom-select-value \{ display: inline-flex; align-items: center; gap: 8px;/);
  // The card mark masks against the row it sits on, selected or not.
  assert.match(css, /\.key-mode-select \.custom-select-button \{ --key-method-card-bg: var\(--bg\); \}/);
  assert.match(css, /\.key-mode-select \.custom-select-list \{ --key-method-card-bg: var\(--surface-2\); \}/);
  assert.match(css, /\.key-mode-select \.custom-select-option\[aria-selected="true"\] \{ --key-method-card-bg:/);
});

test("Station icons keep the original SP mark while normalizing the MS key cluster", () => {
  assert.match(css, /\.key-tab-icon\.key-tab-lab-icon\.bench-tab-icon,\s*\.multisig-tab-icon\.bench-tab-icon \{\s*flex: 0 0 18px; width: 18px; height: 18px;/);
  assert.match(css, /\.bench-tab-icon svg \{ display: block; width: 100%; height: 100%; overflow: visible; \}/);
  assert.match(css, /\.multisig-tab-icon\.bench-tab-icon \{ flex-basis: 21px; width: 21px; height: 24px; \}/);
  assert.match(appSource, /svg\.setAttribute\("viewBox", monochrome \? "0 0 21 24" : "0 -4 49 40"\)/);
  assert.match(appSource, /keys\.setAttribute\("data-part", "key-cluster"\)/);
  assert.match(appSource, /if \(monochrome\) assembly\.setAttribute\("transform", "translate\(-1\.8 4\.65\) scale\(\.431\)"\)/);
  assert.match(appSource, /svg\.setAttribute\("viewBox", "0 0 24 24"\)/);
  assert.doesNotMatch(appSource, /coinCore/);
  for (const factory of ["hodlCreateLabIcon", "hodlCreateBip85BenchIcon", "hodlCreateMsigIcon", "hodlCreateSilentPaymentsIcon"]) {
    assert.match(appSource, new RegExp(`function ${factory}\\(`));
  }
});

test("the delete control reads as unavailable on a Station tab", () => {
  // All three strips ship it disabled: a fresh page holds only the bench,
  // and app.js keeps minus unavailable while that bench is selected.
  for (const markup of [template, appSource]) {
    for (const id of ["delete-key", "delete-bip85", "delete-msig"]) {
      assert.match(
        markup,
        new RegExp(`<button class="add-key remove-key" id="${id}"[^>]*disabled`),
        `${id} must ship disabled`,
      );
    }
  }
  assert.match(appSource, /function hodlSyncKeyDeleteButton\(\) \{[\s\S]*?button\.disabled = !state \|\| state\.isLab;/);
  assert.match(appSource, /function hodlSyncMsigDeleteButton\(\) \{[\s\S]*?button\.disabled = !state \|\| state\.isLab;/);
  // Disabled, it drops off the muted tone the live plus keeps.
  assert.match(css, /\.add-key:disabled \{ color: var\(--border\); cursor: not-allowed; \}/);
  assert.match(css, /\.add-key \{[^}]*color: var\(--muted\);/s);
  // And it never lights up under the pointer: both accent states exclude it.
  assert.match(css, /\.add-key:not\(:disabled\):hover \{ background: transparent; color: var\(--accent\); \}/);
  assert.match(css, /\.add-key:not\(:disabled\):active \{ background: transparent; color: var\(--accent\); \}/);
});

test("seed-entry tools keep a square keyboard toggle and a block note on narrow screens", () => {
  assert.match(
    css,
    /@media \(max-width: 520px\)[\s\S]*\.seed-entry-tools \{ align-items: flex-start; \}[\s\S]*\.seed-autocomplete-note \{ display: block; margin-top: 2px; \}/,
  );
});

test("multisig heading spans beneath the delete action on narrow screens", () => {
  assert.match(
    css,
    /@media \(max-width: 520px\)[\s\S]*\.key-panel-head \{ display: grid; grid-template-columns: minmax\(0, 1fr\) auto; \}[\s\S]*\.key-panel-head > div:first-child \{ grid-column: 1 \/ -1; grid-row: 2; width: 100%; \}[\s\S]*\.key-panel-head > \.delete-key \{ grid-column: 2; grid-row: 1; justify-self: end; \}/,
  );
});

test("the tools' closing button groups stack full width on narrow screens", () => {
  // Wrapped, each control is only as wide as its label and the group reads as
  // ragged lines. Below 520px every child takes the whole row instead.
  assert.match(
    css,
    /@media \(max-width: 520px\)[\s\S]*\.current-item-actions,\s*\.bip85-actions,\s*\.psbt-actions \{ align-items: stretch; \}[\s\S]*\.current-item-actions > \*,\s*\.bip85-actions > \*,\s*\.psbt-actions > \* \{ width: 100%; justify-content: center; \}/,
  );
  // .psbted-actions pins the editor's row to flex-end, so the stacking rule has
  // to follow it to win on order.
  assert.ok(
    css.indexOf(".psbt-actions > *") > css.indexOf(".psbted-actions { align-items: flex-end; }"),
    "the narrow-screen stack must follow .psbted-actions so its alignment wins",
  );
});

test("private alternate account exports are visible without an accordion", () => {
  assert.match(appWhitespace, /if\(includePrivate\)return`<div class="wallet-advanced">\$\{privateExport\}<\/div>`/);
  assert.doesNotMatch(app, /Advanced private export/);
});

test("top banners share one consistent gap", () => {
  // The network banner left the group for the header status tag; the beta
  // banner, the no-JS notice, and the hosted-site warning still share the gap.
  assert.match(
    css,
    /\.beta-warning, \.online-warning\s*\{[^}]*margin: 0 0 12px;/s,
  );
  // The title block that used to follow them is gone, so the banners' 12px now
  // collapses into the leading card's own 16px.
  assert.match(css, /\.card \{[^}]*margin: 16px 0; \}/);
});

test("the beta notice sits at the top of the page as a banner", () => {
  for (const markup of [template, app]) {
    const wrapper = markup.indexOf('<div class="wrap">');
    const live = markup.slice(wrapper).replace(/<!--[\s\S]*?-->/g, "");
    // It is a load-time warning again, so it keeps the alert role and leads
    // the wrap, ahead of the hosted-site warning and the pitch card.
    assert.match(live, /<aside class="beta-warning no-print" id="beta-warning" role="alert">\s*<div class="beta-warning-text"(?: [^>]*)?><strong>Beta software<\/strong> EntropyLab is experimental and should only be used for testing and educational purposes\.<\/div>/);
    assert.ok(
      live.indexOf("<strong>Beta software") < live.indexOf('id="online-warning"'),
      "the beta banner must precede the online warning",
    );
    assert.ok(
      live.indexOf("<strong>Beta software") < live.indexOf('class="kicker"'),
      "the beta banner must precede the pitch card",
    );
    // The closing footer disclaimer is gone; the only other .beta-warning is
    // the no-JS notice in the static template.
    assert.doesNotMatch(live, /site-footer|fine-print/);
  }
  assert.doesNotMatch(css, /\.site-footer|\.fine-print/);
});

test("the page closes on a footer in both markups", () => {
  // Not the removed beta fine print: a plain closing line that ships in the
  // static template and the runtime template alike, and stays off paper. The
  // build stamp (version, commit, LifeHash of the commit) rides the footer;
  // the build tokens are stamped by scripts/build.mjs.
  for (const markup of [template, app]) {
    // esbuild escapes the emoji and the middots when it minifies the
    // runtime template, so the two markups carry the same characters in two
    // spellings.
    assert.match(
      markup,
      /<footer class="page-footer muted no-print"><div>Team Ooga Booga<\/div><div class="page-footer-emoji">(?:🪨|\\u\{1FAA8\}) (?:🔥|\\u\{1F525\}) (?:🎲|\\u\{1F3B2\}) (?:🍌|\\u\{1F34C\})<\/div><div>Since 964013 (?:·|\\x[Bb]7|\\u00[Bb]7) <span class="page-footer-build">v\{\{VERSION\}\} (?:·|\\x[Bb]7|\\u00[Bb]7) commit <code>\{\{COMMIT_SHORT\}\}<\/code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="\{\{COMMIT\}\}" width="20" height="20" alt="LifeHash of the build commit" hidden><\/span><\/div><div class="page-footer-links">/,
    );
    // A fourth row closes it: the two controls that left the header bar.
    assert.match(
      markup,
      /<div class="page-footer-links"><a class="btn secondary github-repo-link"[\s\S]*?<button type="button" class="theme-toggle" id="theme-toggle"[\s\S]*?<\/button><\/div><\/footer>/,
    );
    // It closes the wrap, so nothing of the page follows it.
    assert.ok(
      markup.indexOf('class="page-footer') > markup.indexOf('class="card muted sources"'),
      "the footer must follow the sources card",
    );
  }
  // The wrap gives up its bottom padding so the footer's own padding is the
  // page's last band of space; a top border draws the seam above it.
  // The widest seam in the page opens above it, wider than the major seam the
  // sources card takes, so the closing line reads as its own band.
  assert.match(css, /\.page-footer \{ margin-top: var\(--space-lede\); padding: 24px 0; border-top: 1px solid var\(--border\); text-align: center; color: var\(--faint\);/);
  // .muted would otherwise colour it: the footer rule has to win on order.
  assert.ok(
    css.indexOf(".page-footer {") > css.indexOf(".muted {"),
    "the footer rule must follow .muted so its colour wins",
  );
  // The emoji row outgrows the two text rows it sits between.
  assert.match(css, /\.page-footer-emoji \{[^}]*font-size: 1\.5em;/);
  assert.doesNotMatch(css, /\.wrap \{[^}]*16px 64px/);
});

test("the beta banner carries a dismiss control in a narrow right-hand column", () => {
  // Both markups ship the control: the static template renders before boot,
  // and the runtime template replaces it once the application takes over.
  for (const markup of [template, app]) {
    assert.match(
      markup,
      /<button type="button" class="beta-warning-dismiss" id="beta-warning-dismiss" aria-label="Dismiss the beta software warning"[^>]*>/,
      "the dismiss button must ship in both markups",
    );
    // The label sits after the message, so the column reads last.
    assert.ok(
      markup.indexOf('class="beta-warning-text"') < markup.indexOf('class="beta-warning-dismiss"'),
      "the dismiss column must follow the warning text",
    );
  }
  // The banner is a row: the message takes the slack, the control does not.
  assert.match(css, /#beta-warning, #online-warning \{ display: flex; align-items: flex-start; gap: 12px; \}/);
  assert.match(css, /\.beta-warning-text, \.online-warning-text \{ flex: 1; \}/);
  assert.match(css, /\.beta-warning-dismiss \{[^}]*flex: none;[^}]*\}/s);
  // White on the dark banner, near-black on the light theme's pale one: the
  // glyph must stay legible in both.
  assert.match(css, /\.beta-warning-dismiss \{[^}]*color: #ffffff;[^}]*\}/s);
  assert.match(css, /:root\[data-theme="light"\] \.beta-warning-dismiss \{ color: var\(--fg\); \}/);
  // The author display would otherwise beat the user agent's [hidden] rule
  // and the dismissed banner would stay on screen.
  assert.match(css, /#beta-warning\[hidden\], #online-warning\[hidden\] \{ display: none; \}/);
  // Only the dismissible banner uppercases its label; the noscript notice
  // shares .beta-warning and must keep its sentence casing.
  assert.match(css, /\.beta-warning-text strong, \.online-warning-text strong \{[^}]*line-height: 1; text-transform: uppercase;\s*color: var\(--danger-bright\);[^}]*\}/s);
  // The label takes the banner's own size: a smaller one read as a caption
  // rather than the sentence's lead-in.
  assert.doesNotMatch(css, /\.beta-warning-text strong, \.online-warning-text strong \{[^}]*font-size/s);
  assert.doesNotMatch(css, /\.beta-warning strong \{[^}]*text-transform/);
  // Boot wires the control, and the click hides the banner outright.
  assert.match(appWhitespace, /function hodlInitBetaWarningDismiss\(\)\{/);
  assert.match(appWhitespace, /hodlInitBetaWarningDismiss\(\)/);
  assert.match(app, /getElementById\("beta-warning-dismiss"\)/);
  assert.match(app, /banner\.hidden\s*=\s*!0|banner\.hidden\s*=\s*true/);
  // The dismissal outlives a reload, keyed to the build version so every
  // release warns again, and wrapped so a storage-less origin still boots.
  assert.match(app, /"entropylab-beta-banner-dismissed"/);
  assert.match(appWhitespace, /try\{localStorage\.setItem\(hodlBetaBannerStorageKey,"\{\{VERSION\}\}"\)\}catch/);
  // Re-hiding on a later visit runs before first paint, not at boot: the
  // application waits on the WebAssembly module, so a banner hidden there
  // would paint first and flash. The inline head script sets the attribute
  // and the stylesheet keeps the row out of the very first frame.
  assert.match(
    template,
    /try\{if\(localStorage\.getItem\("entropylab-beta-banner-dismissed"\)==="\{\{VERSION\}\}"\)document\.documentElement\.dataset\.betaBannerDismissed=""\}catch\(e\)\{\}/,
  );
  assert.ok(
    template.indexOf("betaBannerDismissed") < template.indexOf("<body"),
    "the pre-paint check must ship in the head",
  );
  assert.match(css, /:root\[data-beta-banner-dismissed\] #beta-warning \{ display: none; \}/);
  // Boot must not be the thing that hides an already-dismissed banner.
  assert.doesNotMatch(appWhitespace, /localStorage\.getItem\(hodlBetaBannerStorageKey\)/);
});

test("the online and noscript warnings are titled like the beta banner", () => {
  // The online warning ships in both markups; the noscript notice is static
  // only, because the application root it would live in is replaced at boot.
  for (const markup of [template, app]) {
    assert.match(
      markup,
      /<div class="online-warning-text"(?: [^>]*)?><strong>Online version<\/strong> Do not enter seed phrases/,
      "the online warning must carry its label in a wrapper",
    );
    // The hosted-site warning is permanent: no dismiss control anywhere.
    assert.doesNotMatch(
      markup,
      /online-warning-dismiss/,
      "the online warning must not carry a dismiss control",
    );
  }
  assert.match(template, /<div class="beta-warning-text"><strong>JavaScript is required<\/strong> EntropyLab performs wallet/);
  // No lead-in colons anywhere: the label is a line of its own now.
  assert.doesNotMatch(`${template}\n${app}`, /<strong>(Online version|JavaScript is required|Beta software):<\/strong>/);
  // The noscript notice carries no control: there is no JavaScript running to
  // answer one. It takes the label treatment and nothing else.
  const noscript = template.slice(template.indexOf("<noscript>"), template.indexOf("</noscript>"));
  assert.doesNotMatch(noscript, /-dismiss/, "the noscript notice cannot carry a scripted control");
  // The hosted-site warning is permanent: the reveal unit must not read or
  // write storage, so every visit warns again.
  assert.match(online, /getElementById\("online-warning"\)\?\.removeAttribute\("hidden"\)/);
  assert.doesNotMatch(online, /localStorage/, "the online warning must not touch storage");
  assert.doesNotMatch(css, /\.online-warning-dismiss/);
});

test("the beta disclaimer gates the page as a modal until accepted", () => {
  // The overlay sits in the static template after the #btc-calc root (whose
  // last child is the page footer): the application boot replaces that root's
  // contents, so the gate must live outside it — and outside the runtime
  // template — to survive boot.
  const rootAt = template.indexOf('<div id="btc-calc">');
  const footerAt = template.indexOf('<footer class="page-footer');
  const overlayAt = template.indexOf('<div class="disclaimer-overlay');
  assert.ok(rootAt >= 0 && footerAt > rootAt && overlayAt > footerAt, "the disclaimer overlay must follow the #btc-calc root");
  assert.ok(overlayAt < template.indexOf("/*@@JS_BROWSER_CHECK@@*/"), "the disclaimer overlay must ship before the scripts");
  assert.doesNotMatch(appSource, /beta-disclaimer/, "the runtime template must not carry the disclaimer");
  // It starts hidden: the reveal is scripted, so a no-JavaScript host never
  // sees an overlay it cannot dismiss.
  assert.match(
    template,
    /<div class="disclaimer-overlay no-print" id="beta-disclaimer" role="alertdialog" aria-modal="true" aria-labelledby="beta-disclaimer-title" aria-describedby="beta-disclaimer-text" hidden>/,
  );
  assert.match(template, /<p class="disclaimer-title" id="beta-disclaimer-title"[^>]*>Beta software<\/p>/);
  assert.match(
    template,
    /<p class="disclaimer-text" id="beta-disclaimer-text"[^>]*>EntropyLab is experimental and should only be used for testing and educational purposes\. This tool is intended for offline use by advanced users only\. Any use online or with real funds can be dangerous\.<\/p>/,
  );
  assert.match(template, /<button class="btn primary" id="beta-disclaimer-accept" type="button"[^>]*>I understand<\/button>/);
  // The fade: transparent until .is-visible, faded out and inert once
  // .is-dismissed, and motion-free when the user prefers reduced motion.
  assert.match(css, /\.disclaimer-overlay \{\s*position: fixed; inset: 0;[^}]*opacity: 0; transition: opacity \.24s ease;/s);
  // The page behind the card is defocused as well as darkened.
  assert.match(css, /\.disclaimer-overlay \{[^}]*-webkit-backdrop-filter: blur\(6px\); backdrop-filter: blur\(6px\);/s);
  assert.match(css, /\.disclaimer-overlay\[hidden\] \{ display: none; \}/);
  assert.match(css, /\.disclaimer-overlay\.is-visible \{ opacity: 1; \}/);
  assert.match(css, /\.disclaimer-overlay\.is-dismissed \{ opacity: 0; pointer-events: none; \}/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ \.disclaimer-overlay \{ transition: none; \} \}/);
  assert.match(css, /\.disclaimer-card \{[^}]*border: 1px solid var\(--danger\);/s);
  // Icon and title share the banner's brighter alert red, and the title takes
  // the body size so it labels the sentence instead of heading it.
  assert.match(css, /\.disclaimer-icon \{[^}]*color: var\(--danger-bright\); \}/);
  assert.match(css, /\.disclaimer-title \{ margin: 12px 0 12px; font-size: 18px; font-weight: 700; text-transform: uppercase; color: var\(--danger-bright\); \}/);
  // The button sits clear of the warning it answers.
  assert.match(css, /\.disclaimer-text \{ margin: 0 24px 28px;/);
  // The accept button is widened and uppercased in the card only; the shared
  // .btn base still carries every other button in the app.
  assert.match(css, /\.disclaimer-card \.btn \{ padding: 0 32px; font-size: 18px; text-transform: uppercase; \}/);
  assert.match(css, /\.tab, \.btn \{\s*min-height: 44px; padding: 0 14px;/);
});

test("the lockup steps down again below 400px", () => {
  const narrow = css.slice(css.indexOf("@media (max-width: 400px)"));
  assert.ok(narrow, "the 400px breakpoint is missing");
  assert.match(narrow, /\.site-title \{ font-size: 17px; \}/);
  // The picker holds a fourth slot in the control row, so the icons close up.
  assert.match(narrow, /\.download-controls \{ gap: 4px; \}/);
  // It has to follow the 719px block, which sets the wordmark to 19px, or the
  // cascade hands the wider rule the win at equal specificity.
  assert.ok(
    css.indexOf("@media (max-width: 719px)") < css.indexOf("@media (max-width: 400px)"),
    "the 400px block must come after the 719px block",
  );
});

test("the layout has a 320px floor that the fixed header shares", () => {
  assert.match(css, /:root \{[^}]*--site-min-width: 320px;/s);
  assert.match(css, /html, body \{[^}]*min-width: var\(--site-min-width\);/s);
  // position: fixed sizes to the viewport rather than the body, so the bar
  // needs its own copy of the floor or it shrinks past what sits beneath it.
  assert.match(css, /\.site-header \{[^}]*min-width: var\(--site-min-width\);/s);
  // The literal appears once among the declarations, in the token itself, so
  // the two floors cannot be set apart. Prose may name the value freely.
  const declarations = css.replace(/\/\*[\s\S]*?\*\//g, "");
  assert.equal(declarations.match(/320px/g).length, 1);
});

test("header theme toggle cycles dark, light, and OS themes without a flash", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /class="theme-toggle" id="theme-toggle" data-theme-mode="dark" aria-label="Theme: dark\. Switch to light"/);
  }
  assert.match(template, /<script>\(function\(\)\{try\{var m=localStorage\.getItem\("entropylab-theme"\)/);
  assert.match(app, /var hodlThemeModes=\["dark","light"\],hodlThemeStorageKey="entropylab-theme"/);
  // The page eases between the two grounds, and holds still for anyone who
  // asked the system for less motion.
  assert.match(css, /html, body \{[^}]*transition: background-color \.21s ease; \}/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ html, body \{ transition: none; \} \}/);
  // Two states only: the toggle flips, it does not cycle.
  assert.doesNotMatch(`${template}\n${app}`, /theme-icon-system|"system"/);
  assert.doesNotMatch(css, /theme-icon-system/);
  // A first visit opens in whichever mode the operating system asks for,
  // before first paint as well as at boot.
  assert.match(
    template,
    /if\(m==="light"\|\|\(m!=="dark"&&matchMedia\("\(prefers-color-scheme: light\)"\)\.matches\)\)document\.documentElement\.dataset\.theme="light"/,
  );
  assert.match(appWhitespace, /return hodlStoredThemeMode\(\)\|\|\(hodlThemeLightQuery\.matches\?"light":"dark"\)/);
  // Both modes are stored explicitly now: dark can no longer be encoded as a
  // missing key, because a missing key is what defers to the system.
  assert.doesNotMatch(appWhitespace, /removeItem\(hodlThemeStorageKey\)/);
  assert.match(appWhitespace, /localStorage\.setItem\(hodlThemeStorageKey,mode\)/);
  assert.match(app, /function hodlApplyTheme\(mode\)/);
  assert.match(appSource, /hodlInitSecretFieldAutoClear\(\);\s*hodlInitNetworkPicker\(\);\s*hodlInitTheme\(\);/);
  assert.match(css, /:root\[data-theme="light"\] \{\s*color-scheme: light;/);
  assert.match(css, /@media print \{\s*:root, :root\[data-theme\] \{/);
  // Off the bar it keeps the shared 44px chrome instead of the header's 40px
  // square: nothing in the header squeezes it any more.
  assert.doesNotMatch(css, /\.download-controls \.theme-toggle/);
  assert.match(css, /\.seed-keyboard-toggle, \.theme-toggle \{[^}]*flex: 0 0 44px; width: 44px; min-height: 44px;/s);
});

test("the site header is fixed, carries the logo, and holds the version, download, and theme controls", () => {
  for (const markup of [template, app]) {
    // The header precedes the page wrapper, so the banners scroll beneath it.
    const header = markup.indexOf('<div class="site-header no-print">');
    const wrapper = markup.indexOf('<div class="wrap">');
    assert.ok(header >= 0, "the fixed site header is missing");
    assert.ok(header < wrapper, "the site header must come before the page wrapper");
    assert.match(markup, /<span class="site-logo" aria-hidden="true"><\/span>\s*<span class="site-title">EntropyLab<\/span>/);
    // The version left the bar: it is the footer's build stamp now, and the
    // row needed the width for the network picker.
    assert.doesNotMatch(markup.slice(header, wrapper), /site-version/);
    for (const control of [/class="btn secondary download-html header-button"/, /id="network-picker-button"/]) {
      assert.match(markup.slice(header, wrapper), control, `the fixed header is missing ${control}`);
    }
    // The repository link and the theme toggle close the page instead: they
    // are in the footer's fourth row, not the bar.
    for (const moved of [/github-repo-link/, /id="theme-toggle"/]) {
      assert.doesNotMatch(markup.slice(header, wrapper), moved, `${moved} should have left the header`);
      assert.match(markup.slice(markup.indexOf('class="page-footer-links"')), moved);
    }
    // The in-flow title block folded into the marketing card, so the wrapper
    // opens on that card and carries no second header of its own.
    const live = markup.slice(wrapper).replace(/<!--[\s\S]*?-->/g, "");
    // The wrapper opens on the beta banner; the static template follows with
    // a no-JS notice the runtime page has no need of. Both then carry the
    // conditional warnings, which start hidden.
    assert.match(live, /<div class="wrap">\s*<aside class="beta-warning no-print" id="beta-warning" role="alert">[\s\S]*?<\/aside>\s*(?:<noscript>[\s\S]*?<\/noscript>\s*)?(?:<aside[^>]*online-warning[\s\S]*?<\/aside>\s*)*<section class="card">/);
    assert.doesNotMatch(markup.slice(wrapper), /<header>|download-controls/);
  }
  assert.doesNotMatch(css, /^header (\{|h1)/m);
  assert.match(css, /\.site-header \{\s*position: fixed; top: 0; left: 0; right: 0;/);
  assert.match(css, /\.site-header-inner \{[^}]*height: var\(--site-header-height\)/s);
  // The mark's own art margin supplies the lockup gap, so the flex gap is
  // cancelled on that side; without this the wordmark drifts 6px further out.
  assert.match(css, /\.site-logo \{[^}]*margin-right: -6px;/s);
  // The wordmark shares the h1's display face rather than the control sans.
  // The wordmark runs to both ends of the ramp rather than tracking --fg, so
  // each theme has to name its own end.
  assert.match(css, /\.site-title \{[^}]*font-family: var\(--display\);[^}]*color: #ffffff;/);
  assert.match(css, /:root\[data-theme="light"\] \.site-title \{ color: #000000; \}/);
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.site-title \{ font-size: 19px; \}/);
  // No version rides the lockup any more, at any width.
  assert.doesNotMatch(css, /\.site-version/);
  // online.js never fetched or rewrote the version label, and there is none to
  // rewrite now: the app makes no runtime requests.
  assert.doesNotMatch(online, /fetch\s*\(|site-version|innerHTML/);
  // Content clears the fixed header on screen, and reclaims the space in print.
  assert.match(css, /\.wrap \{ max-width: 1000px; margin: 0 auto; padding: calc\(var\(--site-header-height\) \+ 20px\) 16px 0; \}/);
  assert.match(css, /@media print \{[\s\S]*?\.wrap \{ padding-top: 20px; \}/);
  assert.match(css, /html \{[^}]*scroll-padding-top: calc\(var\(--site-header-height\) \+ 12px\)/);
  // Every header control is one height, and Journal file actions deliberately
  // reuse that same compact sizing.
  assert.match(css, /\.header-button, \.journal-file-button \{ min-height: 40px; font-size: 14px; \}/);
  assert.match(css, /--site-header-height: 52px;/);
  // enhanced-inputs.js swaps the language select for a custom listbox; the
  // generated control keeps the bar's 40px chrome and sans face instead of
  // the form control's 44px minimum, control margin, and mono face, which
  // bulged out of the 52px bar.
  assert.match(css, /\.locale-control \.custom-select \{[^}]*margin-top: 0;[^}]*font-family: inherit;[^}]*font-size: 14px;/s);
  assert.match(css, /\.locale-control \.custom-select-button \{[^}]*min-height: 40px;[^}]*padding: 0 12px;[^}]*border-radius: 8px;[^}]*background: var\(--surface-2\)/s);
  assert.match(css, /\.custom-select-chevron \{[^}]*width: 12px; height: 12px;[^}]*stroke: currentColor;[^}]*stroke-linecap: round; stroke-linejoin: round;/s);
  assert.match(appSource, /class="network-picker-chevron"[^>]*>[\s\S]*?<path d="m6 9 6 6 6-6"\/>/);
  assert.match(read("src/js/enhanced-inputs.js"), /chevronPath\.setAttribute\("d", "m6 9 6 6 6-6"\)/);
});

test("the header logo is inlined for both themes and never fetched from assets", () => {
  assert.match(css, /\.site-logo svg \{ display: block; width: 100%; height: 100%; \}/);
  assert.match(css, /\.site-logo \.site-logo-light \{ display: none; \}/);
  assert.match(css, /:root\[data-theme="light"\] \.site-logo \.site-logo-dark \{ display: none; \}/);
  assert.match(css, /:root\[data-theme="light"\] \.site-logo \.site-logo-light \{ display: block; \}/);
  assert.doesNotMatch(css, /data:image/);
  // No markup copy may point the logo at the hosted assets directory.
  for (const markup of [template, app]) {
    assert.doesNotMatch(markup, /online-brand-mark/);
    assert.doesNotMatch(markup, /assets\/entropylab_(dark|light)\.png/);
  }
});

test("the seam into the tool is wider than the page's other major seams", () => {
  assert.match(css, /--space-major: 32px;/);
  assert.match(css, /--space-lede: 48px;/);
  // The pitch-to-tool seam is the page's widest; the closing Sources card keeps
  // the ordinary major one. Both collapse with a neighbouring card's 16px, so
  // the larger value wins rather than the two adding up.
  // The strip is the panel's top edge now, so the tool seam is above the tabs
  // and there is no gap below them to collapse with anything.
  assert.match(css, /\.workspace \{ position: relative; margin: var\(--space-lede\) 0 0; \}/);
  // The card's surface comes off it: no background, no border, padding kept.
  assert.match(css, /\.sources \{ margin-top: var\(--space-major\); background: none; border: 0; \}/);
  for (const markup of [template, app]) {
    assert.match(markup, /<section class="card muted sources">/);
  }
});

test("the marketing card states its pitch as a list rather than a paragraph", () => {
  for (const markup of [template, app]) {
    const list = markup.match(/<ul class="pitch-list muted">[\s\S]*?<\/ul>/)?.[0];
    assert.ok(list, "the pitch list is missing");
    assert.equal((list.match(/<li[\s>]/g) || []).length, 4);
    assert.match(list, /<li[^>]*>Save this air-gapped bitcoin calculator to a removable drive/);
    assert.match(list, /<li[^>]*>Keep your private keys offline\.<\/li>/);
    // The prose it replaced is gone, not merely hidden.
    assert.doesNotMatch(markup, /A signing device is only required when you spend/);
  }
  // The list stands in for a paragraph, so it carries the space a paragraph
  // would have above it and leaves the card's padding to close it out.
  assert.match(css, /\.pitch-list \{ display: grid; gap: 7px; margin: var\(--space-component\) 0 0; padding-left: 20px; \}/);
});

test("the Keys tool intro tells what the calculator does, like the other tool intros", () => {
  for (const markup of [template, appSource]) {
    // No placeholder copy rides the page's first tool intro.
    assert.doesNotMatch(markup, /lorem ipsum/i);
    assert.match(markup, /<p class="muted calc-intro">Turn entropy you bring (?:—|\\u2014) dice rolls, playing cards, a number in any base, a seed phrase, or a private key/);
    assert.match(markup, /This does not invent entropy (?:—|\\u2014) it is a calculator, and nothing leaves this page\.<\/p>/);
  }
});

test("the favicon ships inside the document instead of the assets directory", () => {
  assert.match(
    template,
    /<title>EntropyLab — Offline Bitcoin Key &amp; Wallet Calculator<\/title><link rel="icon" type="image\/png" sizes="64x64" href="data:image\/png;base64,\/\*@@FAVICON@@\*\/"><link rel="icon" type="image\/svg\+xml" href="data:image\/svg\+xml,\/\*@@FAVICON_SVG@@\*\/">/,
  );
  // The inlined icon covers hosted and offline alike, so online.js no longer
  // layers a same-origin link over it.
  assert.doesNotMatch(online, /online-favicon|assets\/favicon\.png/);
});

test("narrow screens keep the fixed header on one row by hiding control labels", () => {
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.control-label \{ display: none; \}/);
  // The footer link collapses with them, squared off against the 44px toggle.
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.page-footer-links \.github-repo-link \{ flex: 0 0 44px; width: 44px; padding: 0; justify-content: center; \}/);
  // The download button squares off against the 40px network picker.
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.download-controls \.download-html \{ flex: 0 0 40px; width: 40px; padding: 0; justify-content: center; \}/);
  for (const markup of [template, app]) {
    // The version reads as plain text beside the logo; "v0.1.3" already says
    // what it is, so it never carries a control label.
    assert.doesNotMatch(markup, /version-picker|version-select|<span class="control-label">Version<\/span>/);
    // The glyph precedes the label at every width and stands alone once the
    // labels collapse, so it is never hidden.
    assert.match(markup, /<svg class="download-mark"[^>]*><path d="M12 3v12M7 11l5 5 5-5M5 21h14"\/><\/svg><span class="control-label"[^>]*>Download<\/span><\/a>/);
    assert.match(css, /\.download-mark \{ display: block; flex: 0 0 auto; \}/);
    assert.doesNotMatch(css, /@media \(max-width: 719px\) \{[\s\S]*?\.download-mark \{/);
    // One rule owns the icon-to-label gap in each row, so they cannot drift.
    assert.match(css, /\.download-controls > a, \.journal-file-button \{ display: inline-flex; align-items: center; gap: 6px;/);
    assert.match(css, /\.page-footer-links > a \{ display: inline-flex; align-items: center; gap: 6px;/);
    assert.doesNotMatch(css, /\.download-controls \.github-repo-link/);
    // Centring the label's em box leaves its caps a pixel below the icon's
    // centre line, so the label carries an optical nudge back up.
    assert.match(css, /\.control-label \{ position: relative; top: -1px; \}/);
    assert.match(markup, /<span class="control-label"[^>]*>GitHub<\/span><\/a>/);
    // Each accessible name still contains its visible label (WCAG 2.5.3).
    assert.match(markup, /class="btn secondary download-html header-button"[^>]*aria-label="Download EntropyLab"/);
    assert.match(markup, /class="btn secondary github-repo-link"[^>]*aria-label="View the EntropyLab GitHub repository in a new tab"/);
  }
});

test("PSBT amounts and fees are labeled as unverified claims", () => {
  assert.match(app, /BTC claimed/);
  assert.match(app, /Unverified fee \(PSBT witness UTXO claims\)/);
  assert.match(app, /Input amounts and any fee are unverified PSBT claims/);
  assert.doesNotMatch(app, /Fee \(from PSBT fields\)/);
});

test("seed-length selector offers all five BIP39 sizes as a dropdown", () => {
  for (const markup of [template, appSource]) {
    // One dropdown in the Method control's clothes, not five buttons.
    assert.match(markup, /<select id="seed-length-select" aria-labelledby="seed-length-label">/);
    for (const words of [12, 15, 18, 21, 24]) {
      assert.match(markup, new RegExp(`<option value="${words}"[^>]*>${words} words</option>`), `${words} is missing`);
    }
    assert.match(markup, /<option value="24" selected="selected"[^>]*>24 words<\/option>/);
    assert.doesNotMatch(markup, /data-seed-words|seed-length-options/);
  }
  assert.match(css, /\.key-mode-select \.custom-select, \.seed-length-select \.custom-select \{ margin-top: 0; \}/);
  // Half the card until the header's breakpoint, then the whole of it.
  assert.match(css, /\.key-mode-select, \.seed-length-select \{ width: calc\(50% - var\(--space-component\) \/ 2\); \}/);
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.key-mode-select, \.seed-length-select \{ width: 100%; \}/);
  assert.doesNotMatch(css, /\.seed-length-options/);
  // One choice drives the same state the five buttons did, and the sync back
  // cannot loop through onchange.
  assert.match(appSource, /hodlSeedLengthSelectEl\.onchange = \(\) => hodlSetSeedLength\(Number\(hodlSeedLengthSelectEl\.value\)\);/);
  assert.match(appSource, /hodlSeedLengthSelectEl\.dispatchEvent\(new Event\("entropylab:sync-select"\)\);/);
});

test("D++ uses the published hexadecimal D16 transcript without a notation toggle", () => {
  assert.match(appSource, /let dplusFaces = \["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"\]/);
  // The label text lives in the locale catalogs now; the key call stays in the source.
  assert.match(appSource, /hodlT\("dice\.label\.dplus", \{ final: hodlDPlusFinalDescription/);
  assert.match(en["dice.label.dplus"], /^D\+\+ rolls \(D8, D16, D16; then/);
  assert.doesNotMatch(en["dice.label.dplus"], /D8 1–8, D16 0–F/);
  assert.doesNotMatch(appSource, /D\+\+ rolls \(D8 1\\u20138, D16 0\\u2013F/);
  assert.match(appSource, /accessibleRange\.className = "sr-only";\s*accessibleRange\.textContent = rollRange;/);
  assert.doesNotMatch(appSource, /meta\.append\(document\.createTextNode\(" \\xB7 "\), emphasis, document\.createTextNode\(rollRange\)\)/);
  assert.match(appSource, /D8 labeled 1\\u20138 and two hexadecimal D16 dice labeled 0\\u2013F/);
  assert.match(appSource, /hodlT\("dice.help.dplus"/);
  assert.doesNotMatch(appSource, /data-dplus-die|hodlDPlusNumberedD16|dplusNumberedD16|Decimal D16/);
  assert.doesNotMatch(css, /dplus-die-pad|dplus-key-decimal|dplus-key-face/);
});

test("dice rolls hide Pearson chi-squared fairness behind a text expand button", () => {
  assert.match(app, /id="dice-fairness-toggle"/);
  assert.match(app, /aria-controls="dice-fairness"/);
  assert.match(app, /class="dice-fairness-toggle"/);
  assert.match(app, /data-dice-fairness-glyph/);
  assert.match(app, /hodlT\("dice.fairness.toggle"\)/);
  assert.match(appSource, /<div class="seed-word-copy-row">\$\{leading\}<span class="seed-phrase-copied"/);
  assert.match(css, /\.seed-word-copy-row \.dice-fairness-toggle \{ margin-right: auto; \}/);
  assert.match(app, /id="dice-fairness" class="dice-fairness" hidden role="status" aria-live="polite"/);
  assert.match(app, /function hodlSetDiceFairnessOpen\(open\)/);
  assert.match(app, /function hodlChiSquaredCdf\(/);
  assert.match(app, /function hodlDiceFairnessAssess\(rolls,\s*labels,\s*title\)/);
  assert.match(app, /function hodlRenderDiceFairness\(value,\s*method,\s*targetWords\s*=\s*hodlTargetWordCount\)/);
  assert.match(app, /hodlRenderDiceFairness\(input\.value,\s*hodlDiceMethod,\s*config\.words\)/);
  assert.match(app, /showDiceFairness:!1/);
  assert.match(app, /dice\.fairness\.verdict\./);
  assert.match(app, /hodlT\("dice.fairness.hideAria"\)/);
  assert.match(css, /\.dice-fairness \{/);
  assert.match(css, /\.dice-fairness-toggle \{/);
  assert.match(css, /\.dice-fairness\[data-tone="danger"\] \{/);
  assert.match(template, /dicefairness\.johnellmore\.com/);
  assert.match(template, /How can I test whether a die is fair/);
});

test("card suit glyphs have explicit local symbol-font fallbacks (issue #104)", () => {
  // ♠ ♥ ♦ ♣ (U+2660–U+2666) appear wherever cards are entered or displayed,
  // but not every default UI font covers them (notably SF Mono on macOS).
  // Both stacks must name local symbol fonts before the generic fallback so
  // the suits render on Windows, macOS, and Linux.
  for (const property of ["--sans", "--mono"]) {
    const stack = css.match(new RegExp(`${property}: ([^;]+);`))?.[1] ?? "";
    for (const family of ['"Segoe UI Symbol"', '"Apple Symbols"', '"Noto Sans Symbols"']) {
      assert.ok(stack.includes(family), `${property} is missing the ${family} fallback`);
    }
    assert.ok(/, (sans-serif|monospace)$/.test(stack.trim()), `${property} must keep its generic fallback last`);
  }
  // Fonts are local system fonts only: no webfont may ever be downloaded.
  assert.doesNotMatch(css, /@font-face|\.woff2?|fonts\.googleapis|fonts\.gstatic/);
  assert.doesNotMatch(template, /@font-face|\.woff2?|fonts\.googleapis|fonts\.gstatic/);
});

test("virtual keypads never focus the field on touch so the mobile keyboard stays closed (#123)", () => {
  const body = (name) => appSource.slice(appSource.indexOf(`function ${name}(`), appSource.indexOf("\nfunction ", appSource.indexOf(`function ${name}(`) + 1));
  for (const name of ["hodlInsertDiceControl", "hodlInsertEntropyControl", "hodlApplySeedKeyboardKey", "hodlSetInputValueAtEnd", "hodlBindSeedNumberPad"]) {
    assert.doesNotMatch(body(name), /\.focus\(/, `${name} must not focus the input`);
  }
  assert.match(body("hodlBindKeypadPointer"), /event\.preventDefault\(\);\s*if \(event\.pointerType === "mouse"\) getInput\(\)\?\.focus\(/);
  assert.match(body("hodlPlaceCaret"), /document\.activeElement === input/);
  // Every keypad routes pointerdown through the shared binder; no pad focuses the input directly.
  assert.doesNotMatch(appSource, /pointerdown", \(event\) => \{\s*event\.preventDefault\(\);\s*\w+\.focus\(/);
  for (const call of ['hodlFormEl.querySelectorAll("[data-d]")', 'hodlFormEl.querySelectorAll("[data-entropy-digit]")', 'hodlFormEl.querySelectorAll("[data-direct-card-rank], #card-undo")', 'pad.querySelectorAll("button")', 'keyboard.querySelectorAll("button")']) {
    assert.ok(appSource.includes(`hodlBindKeypadPointer(${call}`), `${call} keypad is bound`);
  }
});

test("workspace tabs place Vanity between Keys and BIP-85", () => {
  assert.match(appSource, /\["calc", "workspace\.key", "workspace\.keyShort"\], \["vanity", "workspace\.vanity", "workspace\.vanityShort"\], \["bip85", "workspace\.bip85", "workspace\.bip85Short"\], \["msig", "workspace\.msig", "workspace\.msigShort"\], \["sp", "workspace\.sp", "workspace\.spShort"\], \["bip47", "workspace\.bip47", "workspace\.bip47Short"\], \["psbt", "workspace\.psbt", "workspace\.psbtShort"\]/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip85-card"/);
    assert.match(markup, /id="bip85-go"/);
    assert.match(markup, /Derive child/);
    assert.match(markup, /This does not invent entropy/);
  }
  assert.match(css, /#bip85-card\[hidden\]/);
});

test("one PSBT workspace contains PSBT / Nonce and PSBT Editor tabs", () => {
  assert.match(appSource, /\["psbt", "workspace\.psbt", "workspace\.psbtShort"\]/);
  assert.doesNotMatch(appSource, /\["psbted", "workspace\.psbted", "workspace\.psbtedShort"\]/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /<div class="tool-intro-stack" id="psbt-tool-intros" hidden>[\s\S]*?id="psbt-tool-intro"[\s\S]*?id="psbted-tool-intro"[\s\S]*?<section class="key-manager no-print" id="psbt-manager" hidden>/);
    assert.match(markup, /<section class="key-manager no-print" id="psbt-manager" hidden>/);
    assert.match(markup, /<div class="key-tab-strip">\s*<div class="key-tabs" id="psbt-tool-tabs" role="tablist" aria-label="PSBT stations">/);
    assert.match(markup, /class="tab key-tab is-lab active"[^>]*data-psbt-tool="nonce"/);
    assert.match(markup, /class="tab key-tab is-lab"[^>]*data-psbt-tool="editor"/);
    assert.doesNotMatch(markup, /class="psbt-tool-tabs segmented-control/);
  }
  assert.match(appSource, /data-psbt-tool="nonce"[^>]*data-i18n="workspace\.psbtNonce">PSBT \/ Nonce/);
  assert.match(appSource, /data-psbt-tool="editor"[^>]*data-i18n="workspace\.psbted">PSBT Editor/);
  assert.match(appSource, /getElementById\("psbt-manager"\)/);
  assert.match(appSource, /getElementById\("psbt-tool-intros"\)/);
  assert.match(appSource, /function hodlShowPsbtTool\(id, focus = false\)/);
  assert.match(appSource, /hodlInitTabDrag\(document\.getElementById\("psbt-tool-tabs"\)\)/);
  assert.match(appSource, /getElementById\("psbted-card"\)\.hidden = !visible \|\| hodlPsbtTool !== "editor"/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="psbted-card"/);
    assert.match(markup, /id="psbted-text"/);
    assert.match(markup, /id="psbted-load"/);
    assert.match(markup, /id="psbted-wipe"/);
    assert.match(markup, /id="psbted-out"/);
    assert.match(markup, /id="psbted-error"/);
    // The comparison surface must exist in both markups: the editor's compare
    // wiring looks the ids up at boot, and a template without them kills the
    // page (initPsbtEditor throws inside hodlBoot).
    assert.match(markup, /id="psbted-compare-text"/);
    assert.match(markup, /id="psbted-compare-go"/);
    assert.match(markup, /id="psbted-compare-clear"/);
    assert.match(markup, /id="psbted-compare-error"/);
    assert.match(markup, /id="psbted-compare-out"/);
    assert.match(markup, /rust-bitcoin compiled to WebAssembly/);
    // The row must carry psbted-actions in both markups so the editor's
    // button rows keep their compact, text-sized buttons.
    assert.match(markup, /<div class="row psbt-actions psbted-actions">/);
  }
  assert.match(css, /\.psbted-actions \{ align-items: flex-end; \}/);
  assert.match(css, /\.psbted-actions \.btn \{ min-height: 0; padding: 6px 10px; \}/);
  assert.match(appSource, /import \{ initPsbtEditor \} from "\.\/psbt-editor\.js"/);
  // The editor reads the header picker's network through the passed getter.
  assert.match(appSource, /initPsbtEditor\(\{ networkDefault: \(\) => hodlNetworkDefault \}\)/);
  assert.match(css, /#psbted-card\[hidden\]/);
  assert.match(css, /#psbt-card:not\(\[hidden\]\), #psbted-card:not\(\[hidden\]\), #vanity-card:not\(\[hidden\]\) \{[^}]*border-radius: 0 0 20px 20px;/s);
});

test("Journal gates its three tools behind the encrypted notebook", () => {
  assert.match(appSource, /\["psbt", "workspace\.psbt", "workspace\.psbtShort"\], \["journal", "workspace\.journal", "workspace\.journalShort"\]\];/);
  assert.match(appSource, /import \{[\s\S]*wipeJournal,[\s\S]*\} from "\.\/journal\.js"/);
  assert.match(appSource, /import \{[\s\S]*sealDocument as hodlJournalSealDocument,[\s\S]*\} from "\.\/journal\.js"/);
  assert.match(appSource, /openExport as hodlJournalOpenExport/);
  assert.match(appSource, /sealExport as hodlJournalSealExport/);
  assert.match(appSource, /function hodlShowJournalTool\(id, focus = false\)/);
  assert.match(appSource, /hodlInitTabDrag\(document\.getElementById\("journal-tool-tabs"\)\)/);
  assert.match(appSource, /hodlInitJournalNotebook\(\)/);
  assert.match(appSource, /function hodlJournalNotesClick\(field\)/);
  assert.match(appSource, /notesText\.addEventListener\("click", \(\) => hodlJournalNotesClick\(notesText\)\)/);
  assert.match(appSource, /function hodlRefreshJournalKeyPicker\(\)/);
  assert.match(appSource, /function hodlJournalInsertKey\(select, field\)/);
  assert.match(appSource, /function hodlJournalImportFile\(file\)/);
  assert.match(appSource, /hodlSerializeNotebook\(hodlJournal\)/);
  assert.match(appSource, /hodlJournalWipeMem\(\)/);
  assert.match(appSource, /function hodlInitSecretFieldAutoClear\(\) \{[\s\S]*hodlJournalWipeMem\(\)/);
  assert.match(appSource, /function hodlJournalWipeMem\(\) \{[\s\S]*hodlJournalWipeNotebook\(\)/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /<div class="tool-intro" id="journal-tool-intro" hidden>[\s\S]*?<h2>Entropy Journal<\/h2>[\s\S]*?<section class="key-manager no-print" id="journal-manager" hidden>/);
    assert.match(markup, /id="journal-global-download"[^>]*disabled aria-disabled="true"[^>]*>[\s\S]*?<span>Download journal<\/span><\/button>/);
    assert.match(markup, /class="btn clear-current-action" id="journal-global-clear"[^>]*disabled aria-disabled="true"[^>]*>Clear journal<\/button>/);
    assert.match(markup, /<section class="key-manager no-print" id="journal-manager" hidden>/);
    assert.match(markup, /<div class="key-tabs" id="journal-tool-tabs" role="tablist" aria-label="Journal stations">/);
    assert.doesNotMatch(markup, /id="journal-book-tab"|data-journal-tool="book"/);
    assert.match(markup, /id="journal-notes-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="notes"[^>]*disabled/);
    assert.match(markup, /id="journal-state-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="state"[^>]*disabled/);
    assert.match(markup, /id="journal-log-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="log"[^>]*disabled/);
    assert.match(markup, /id="journal-card" role="region" aria-label="Encrypted Journal"/);
    assert.match(markup, /id="journal-create"/);
    assert.match(markup, /id="journal-unlock"/);
    assert.match(markup, /id="journal-save"/);
    assert.match(markup, /id="journal-input"/);
    assert.match(markup, /id="journal-create-password"/);
    assert.match(markup, /id="journal-open-password"/);
    assert.match(markup, /id="journal-entry-notes"/);
    assert.match(markup, /class="journal-password-validation" id="journal-create-password-status" role="status" aria-live="polite" hidden/);
    assert.match(markup, /id="journal-create-password"[^>]*aria-describedby="journal-create-password-note journal-create-password-status"/);
    assert.match(markup, /class="journal-password-validation" id="journal-create-confirm-status" role="status" aria-live="polite" hidden/);
    assert.match(markup, /id="journal-create-confirm"[^>]*aria-describedby="journal-create-confirm-status"/);
    assert.match(markup, /class="row bip85-actions journal-create-actions">\s*<button class="btn primary" id="journal-create"[^>]*>Create journal<\/button>\s*<span class="journal-create-ready" id="journal-create-ready" hidden><span class="journal-create-ready-arrow" aria-hidden="true">←<\/span> Ready to create journal<\/span>/);
    assert.match(markup, /does not invent entropy/);
    assert.match(markup, /The journal lives in this page until you save the encrypted file/);
    assert.match(markup, /id="journal-notes-card"/);
    assert.match(markup, /id="journal-state-card"/);
    assert.match(markup, /id="journal-log-card"/);
    assert.match(markup, /id="journal-notes-card"[^>]*>[\s\S]*?id="journal-notes-tool-intro"[\s\S]*?<h2>Notepad<\/h2>[\s\S]*?id="journal-page-tabs"/);
    assert.match(markup, /id="journal-state-card"[^>]*>[\s\S]*?id="journal-state-tool-intro"[\s\S]*?<h2>Session state<\/h2>[\s\S]*?id="journal-state-text"/);
    assert.match(markup, /id="journal-log-card"[^>]*>[\s\S]*?id="journal-log-tool-intro"[\s\S]*?<h2>Session log<\/h2>[\s\S]*?id="journal-log-out"/);
    assert.match(markup, /<div class="key-tab-strip journal-page-tab-strip"><div class="key-tabs" id="journal-page-tabs" role="tablist" aria-label="Notepad pages"><\/div>/);
    assert.match(markup, /id="add-journal-page"[^>]*aria-label="Add notepad page"/);
    assert.match(markup, /id="delete-journal-page"[^>]*aria-label="Delete current notepad page"[^>]*disabled/);
    assert.match(markup, /class="journal-format-bar" role="group" aria-label="Notepad appearance and inserts"/);
    assert.match(markup, /id="journal-key-insert"[^>]*aria-label="Insert a Key Station key"/);
    assert.match(markup, /id="journal-font"[\s\S]*?id="journal-size"[\s\S]*?id="journal-spacing"/);
    assert.match(markup, /<div class="journal-notes-wrap" id="journal-page-panel" role="tabpanel"[^>]*>\s*<div class="journal-notes-render" id="journal-notes-render" aria-hidden="true"><\/div>\s*<textarea class="journal-notes-text" id="journal-notes-text"[^>]*aria-placeholder="Add new note"[^>]*><\/textarea>\s*<div class="journal-notes-prompt" id="journal-notes-prompt" aria-hidden="true"><span id="journal-notes-prompt-before"><\/span><span class="journal-notes-prompt-text" id="journal-notes-prompt-text">Add new note<\/span><\/div>/);
    assert.match(markup, /class="seed-phrase-copy journal-notes-copy" id="journal-notes-copy"[^>]*aria-label="Copy notepad page"[^>]*disabled><svg[^>]*><rect class="seed-copy-icon-clip"[^>]*\/><path class="seed-copy-icon-board"[^>]*\/><\/svg><\/button>/);
    assert(markup.indexOf('class="journal-format-bar"') < markup.indexOf('id="journal-page-tabs"') && markup.indexOf('id="journal-page-tabs"') < markup.indexOf('id="journal-page-panel"'), "notepad controls should precede the page tabs while the tabs stay joined to the editor");
    assert.match(markup, /class="btn secondary journal-download-action journal-file-button" id="journal-notes-download"[^>]*aria-label="Download notepad"[^>]*><svg class="download-mark"[\s\S]*?<span class="control-label">Download notepad<\/span><\/button>/);
    assert.match(markup, /class="btn secondary journal-upload-action journal-file-button" id="journal-notes-upload"[^>]*aria-label="Upload notebook"[^>]*><svg class="download-mark"[\s\S]*?<path d="M12 17V5M7 10l5-5 5 5M5 21h14"\/>[\s\S]*?<span class="control-label">Upload<\/span><\/button>/);
    assert.equal([...markup.matchAll(/class="journal-encrypt-download"/g)].length, 3, "each Journal tab should carry the shared encryption choice");
    assert.match(markup, /id="journal-notes-encrypt" type="checkbox" checked><span>Use journal password to encrypt<\/span>/);
    assert.match(markup, /id="journal-state-encrypt" type="checkbox" checked><span>Use journal password to encrypt<\/span>/);
    assert.match(markup, /id="journal-log-encrypt" type="checkbox" checked><span>Use journal password to encrypt<\/span>/);
    assert.match(markup, /id="journal-notes-file"[^>]*accept="\.json,\.txt,application\/json,text\/plain"/);
    assert.doesNotMatch(markup, /id="journal-notes-download-text"|Download plain-text notes/);
    assert.doesNotMatch(markup, /id="journal-note-add"|>Add note</);
    assert.doesNotMatch(markup, /id="journal-state-capture"|Capture this session/);
    assert.match(markup, /id="journal-state-text"[^>]*readonly aria-readonly="true"/);
    assert.match(markup, /id="journal-state-private"/);
    assert(markup.indexOf('id="journal-state-text"') < markup.indexOf('id="journal-state-download"'), "Session state download should follow the live snapshot");
    assert.match(markup, /class="btn secondary journal-download-action journal-file-button" id="journal-state-download"[^>]*aria-label="Download session state"[^>]*>[\s\S]*?<span class="control-label">Download session state<\/span><\/button>/);
    assert.match(markup, /<div class="journal-log-wrap"><pre class="journal-log" id="journal-log-out"[^>]*>No events yet\.<\/pre><button class="seed-phrase-copy journal-log-copy" id="journal-log-copy"[^>]*aria-label="Copy session log"[^>]*><svg[^>]*><rect class="seed-copy-icon-clip"[^>]*\/><path class="seed-copy-icon-board"[^>]*\/><\/svg><\/button><\/div>/);
    assert.match(markup, /class="btn secondary journal-download-action journal-file-button" id="journal-log-download"[^>]*aria-label="Download session log"[^>]*>[\s\S]*?<span class="control-label">Download session log<\/span><\/button>/);
    assert.match(markup, /class="btn clear-current-action" id="journal-log-clear"[^>]*>Clear log<\/button>/);
    assert.match(markup, /class="row psbt-actions journal-log-actions"/);
  }
  assert.match(appSource, /data-journal-tool="notes"[^>]*data-i18n="workspace\.journalNotes"[^>]*>Notepad/);
  assert.match(appSource, /data-journal-tool="state"[^>]*data-i18n="workspace\.journalState"[^>]*>Session state/);
  assert.match(appSource, /data-journal-tool="log"[^>]*data-i18n="workspace\.journalLog"[^>]*>Session log/);
  assert.match(css, /#journal-card\[hidden\]/);
  assert.match(css, /#journal-notes-card\[hidden\]/);
  assert.match(css, /#journal-state-card\[hidden\]/);
  assert.match(css, /#journal-log-card\[hidden\]/);
  assert.match(css, /#journal-locked-panel\[hidden\]/);
  assert.match(css, /\.journal-password-label \{[^}]*display: flex;[^}]*justify-content: space-between;[^}]*flex-wrap: wrap;/);
  assert.match(css, /\.journal-password-validation\.is-invalid \{ color: var\(--danger\); \}/);
  assert.match(css, /\.journal-password-validation\.is-valid \{ color: var\(--ok\); \}/);
  assert.match(css, /\.journal-create-ready \{[^}]*display: inline-flex;[^}]*color: var\(--ok\);/);
  assert.match(css, /\.journal-create-ready-arrow \{[^}]*font-size: 18px;/);
  assert.match(css, /@media \(max-width: 520px\) \{[\s\S]*\.journal-create-ready-arrow \{ transform: rotate\(90deg\); \}/);
  assert.match(css, /\.journal-section-intro \{ margin: 0 0 24px; \}/);
  assert.match(css, /\.journal-section-intro > \.muted \{ max-width: 760px; margin: 0; \}/);
  assert.match(css, /\.journal-global-actions \{[^}]*margin-top: var\(--space-component\);/);
  assert.match(css, /#journal-tool-tabs \.key-tab:disabled,[\s\S]*opacity: \.52; cursor: not-allowed;/);
  assert.match(css, /#journal-card:not\(\[hidden\]\), #journal-notes-card:not\(\[hidden\]\), #journal-state-card:not\(\[hidden\]\), #journal-log-card:not\(\[hidden\]\) \{[^}]*border-radius: 0 0 20px 20px;/s);
  assert.match(css, /\.journal-notes-wrap \{[^}]*--journal-font-family:[^}]*position: relative;/s);
  assert.match(css, /\.journal-page-tab-strip \{ margin-top: 0; margin-bottom: -1px; \}/);
  assert.match(css, /\.key-tab\.journal-page-tab\.active,[^}]*background: var\(--bg\); border-bottom-color: var\(--bg\);/);
  assert.match(css, /\.journal-page-tab \.journal-page-tab-short \{ display: none; \}/);
  assert.match(css, /\.journal-page-tab\.is-default \.journal-page-tab-full \{ display: none; \}/);
  assert.match(css, /\.journal-page-tab\.is-default \.journal-page-tab-short \{ display: inline-block; \}/);
  assert.match(css, /\.journal-format-bar \{[^}]*grid-template-columns: repeat\(2,[^}]*padding: 0 0 12px;/);
  assert.match(css, /\.journal-key-control \{ grid-column: 1 \/ -1; \}/);
  assert.match(css, /\.journal-notes-text \{[^}]*min-height: 20rem;[^}]*color: transparent;[^}]*caret-color: var\(--fg\);/s);
  assert.match(css, /\.journal-notes-text \{[^}]*border-top-left-radius: 0;/s);
  assert.match(css, /\.journal-notes-render \{[^}]*pointer-events: none;[^}]*white-space: pre-wrap;/s);
  assert.match(css, /\.journal-inline-key-lifehash \{[^}]*width: 1\.1em; height: 1\.1em;/s);
  assert.match(css, /\.journal-notes-prompt \{[^}]*color: transparent;[^}]*white-space: pre-wrap;/s);
  assert.match(css, /\.journal-notes-prompt-text \{ color: var\(--faint\); \}/);
  assert.match(css, /\.journal-notes-copy \{[^}]*position: absolute;[^}]*top: 10px; right: 12px;[^}]*opacity: 0; pointer-events: none; transition: opacity \.18s ease;/s);
  assert.match(css, /\.journal-notes-copy\.is-visible, \.journal-notes-copy:hover, \.journal-notes-copy:focus-visible \{ opacity: 1; pointer-events: auto; \}/);
  assert.match(css, /\.journal-notes-copy\.is-copied, \.journal-notes-copy\.is-copied:not\(:disabled\):hover \{ color: var\(--ok\); \}/);
  assert.match(appSource, /notesText\.addEventListener\("mousemove", \(\) => hodlJournalRevealCopyButton\(notesCopy\)\)/);
  assert.match(appSource, /hodlJournalFormatNotebook\(field\.value\)[\s\S]*?button\.dataset\.phrase = phrase/);
  assert.match(appSource, /hodlCopySeedPhraseButton\(notesCopy\);[\s\S]*?hodlJournalRevealCopyButton\(notesCopy, 1900\)/);
  assert.match(css, /\.btn:is\(\.download-html, \.save-recovery-sheet, \.save-wallet-dat, \.journal-download-action\) \{[^}]*var\(--ok\)/s);
  assert.match(css, /\.header-button, \.journal-file-button \{ min-height: 40px; font-size: 14px; \}/);
  assert.match(css, /\.download-controls > a, \.journal-file-button \{ display: inline-flex; align-items: center; gap: 6px; text-decoration: none; \}/);
  assert.match(css, /\.journal-file-button \.control-label \{ display: inline; \}/);
  assert.match(css, /\.journal-file-actions \.journal-upload-action \{[^}]*var\(--blue\)/s);
  assert.match(css, /\.journal-file-actions \.journal-upload-action \{ margin-inline-start: auto; \}/);
  assert.match(css, /\.journal-download-options \{[^}]*display: flex;[^}]*align-items: center;/);
  assert.match(css, /\.journal-encrypt-option input \{[^}]*accent-color: var\(--ok\);/);
  assert.match(css, /\.journal-notes-status:empty \{ display: none; \}/);
  assert.match(css, /\.journal-log-wrap \{ position: relative; margin: 0 0 14px; \}/);
  assert.match(css, /\.journal-log \{[^}]*padding: 12px 44px 12px 12px;[^}]*background: #000;/s);
  assert.match(css, /:root\[data-theme="light"\] \.journal-log \{ background: var\(--surface-2\); \}/);
  assert.match(css, /\.journal-log-copy \{ position: absolute; z-index: 1; top: 10px; right: 12px; \}/);
  assert.match(css, /\.journal-log-actions #journal-log-clear \{ margin-inline-start: auto; \}/);
  assert.match(appSource, /logCopy\.dataset\.phrase = logOut\.textContent \|\| "";\s*hodlCopySeedPhraseButton\(logCopy\)/);
  assert.match(appSource, /"journal-notes-download": \["journal", "download", "notebook"\]/);
  assert.match(appSource, /"journal-state-download": \["journal", "download", "session-state"\]/);
  assert.match(appSource, /"journal-log-download": \["journal", "download", "session-log"\]/);
  assert.match(appSource, /"journal-notes-upload": \["journal", "upload", "notebook"\]/);
  assert.match(appSource, /"journal-notes-copy": \["journal", "copy", "notepad-page"\]/);
  assert.match(appSource, /"journal-log-copy": \["journal", "copy", "session-log"\]/);
  assert.match(appSource, /function hodlJournalSyncEncryptDownloads\(source\) \{[\s\S]*checkbox\.checked = hodlJournalEncryptDownloads/);
  assert.match(appSource, /function hodlJournalDownloadContent\(kind, filename, text,[\s\S]*hodlJournalSealExport\(kind, text, hodlJournalKeys\)/);
  assert.doesNotMatch(appSource, /Downloaded a .*reloadable notebook/);
  assert.match(appSource, /outer\?\.entropylabJournalExport[\s\S]*hodlJournalOpenExport\(outer, hodlJournalKeys\)/);
  assert.match(appSource, /document\.getElementById\("journal-global-download"\)\?\.addEventListener\("click", hodlJournalSaveFile\)/);
  assert.match(appSource, /document\.getElementById\("journal-global-clear"\)\?\.addEventListener\("click", hodlJournalWipeMem\)/);
  assert.match(appSource, /function hodlInitJournalActionAudit\(\)[\s\S]*document\.addEventListener\("click",[\s\S]*document\.addEventListener\("change",/);
  assert.match(appSource, /control\.id === "journal-key-insert" \|\| control\.type === "file"/);
  assert.match(appSource, /function hodlJournalRefreshSessionState\(\)/);
  assert.match(appSource, /function hodlScheduleJournalStateRefresh\(\) \{[\s\S]*queueMicrotask\([\s\S]*hodlJournalRefreshSessionState\(\)/);
  assert.match(appSource, /function hodlJournalLog\([\s\S]*?hodlScheduleJournalStateRefresh\(\)/);
  assert.match(appSource, /hodlJournalTool === "state"\) hodlJournalRefreshSessionState\(\)/);
  assert.doesNotMatch(appSource, /hodlJournalLog\("capture"|hodlJournalCaptureSession/);
  assert.match(appSource, /hodlJournalLog\("inspect", kind, "psbt"\)[\s\S]*hodlJournalLog\("inspect-error", "", "psbt"\)/);
  assert.match(appSource, /hodlJournalLog\("calculate", hodlSpMode, "sp"\)[\s\S]*hodlJournalLog\("calculate-error", hodlSpMode, "sp"\)/);
  assert.match(appSource, /hodlJournalLog\("derive-error", "", "bip85"\)/);
  assert.match(appSource, /hodlJournalLog\("note-delete", "", "journal"\)/);
  assert.match(appSource, /hodlJournal\.log\.length = 0;\s*hodlJournalLog\("clear", "session-log", "journal"\)/);
  assert.match(css, /#journal-notes-card:not\(\[hidden\]\), #journal-state-card:not\(\[hidden\]\), #journal-log-card:not\(\[hidden\]\) \{[^}]*border-radius: 0 0 20px 20px;/s);
  assert.equal(en["workspace.journal"], "Journal");
  assert.equal(en["workspace.journalNotes"], "Notepad");
  assert.equal(en["workspace.journalState"], "Session state");
  assert.equal(en["workspace.journalLog"], "Session log");
  assert.match(appSource, /PASSWORD_MIN_LENGTH as hodlJournalPasswordMinLength/);
  assert.match(appSource, /function hodlSyncJournalCreatePasswordValidation\(\) \{[\s\S]*Array\.from\(passwordValue\)\.length >= hodlJournalPasswordMinLength[\s\S]*Password has too few characters[\s\S]*Passwords do not match/);
  assert.match(appSource, /if \(ready\) ready\.hidden = !\(passwordLongEnough && confirmValue && passwordsMatch\);/);
  assert.match(appSource, /\["journal-create-password", "journal-create-confirm"\][\s\S]*addEventListener\("input", hodlSyncJournalCreatePasswordValidation\)/);
  assert.match(appSource, /function hodlSyncJournalTool\(\) \{[\s\S]*unlocked = hodlJournalUnlocked\(\)[\s\S]*button\.disabled = !unlocked;[\s\S]*button\.setAttribute\("aria-disabled", String\(!unlocked\)\)[\s\S]*journal-notes-card"\)\.hidden = !visible \|\| !unlocked/);
  assert.match(appSource, /async function hodlJournalCreate\(\) \{[\s\S]*hodlJournalShowWork\(\);\s*hodlShowJournalTool\("notes"\)/);
  assert.match(appSource, /async function hodlJournalUnlock\(\) \{[\s\S]*hodlJournalShowWork\(\);\s*hodlShowJournalTool\("notes"\)/);
  assert.match(appSource, /function hodlJournalLock\(\) \{[\s\S]*hodlJournalTool = "book";[\s\S]*hodlSyncJournalTool\(\)/);
  assert.match(appSource, /function hodlJournalWipeMem\(\) \{[\s\S]*hodlJournalTool = "book";[\s\S]*hodlSyncJournalTool\(\)/);
  // The notebook never seals or opens without an explicit click.
  const init = appSource.slice(appSource.indexOf("function hodlInitJournalNotebook()"), appSource.indexOf("function hodlJournalWipeMem()"));
  assert.doesNotMatch(init, /hodlJournalCreate\(\);/);
});

test("fixed inner tabs reserve the height of their longest introduction", () => {
  assert.match(css, /\.tool-intro-stack \{ display: grid; \}/);
  assert.match(css, /\.tool-intro-stack\[hidden\] \{ display: none !important; \}/);
  assert.match(css, /\.tool-intro-stack > \.tool-intro \{ grid-area: 1 \/ 1; visibility: hidden; \}/);
  assert.match(css, /\.tool-intro-stack > \.tool-intro\.active \{ visibility: visible; \}/);
  assert.match(css, /\.tool-intro-stack \+ \.key-manager \{ margin-top: 0; \}/);
  assert.match(css, /\.tool-intro-stack \+ \.key-manager > \.key-tab-strip \{ margin-top: 0; \}/);
  assert.match(appSource, /if \(intros\) intros\.hidden = !visible;/);
  assert.match(appSource, /nonceIntro\.classList\.toggle\("active", visible && hodlPsbtTool === "nonce"\);\s*nonceIntro\.setAttribute\("aria-hidden", String\(!visible \|\| hodlPsbtTool !== "nonce"\)\);/);
  assert.match(appSource, /editorIntro\.classList\.toggle\("active", visible && hodlPsbtTool === "editor"\);\s*editorIntro\.setAttribute\("aria-hidden", String\(!visible \|\| hodlPsbtTool !== "editor"\)\);/);
});

test("BIP-85 stays available as a workspace without a duplicate Key Station action", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="go"[^>]*>Derive Key<\/button>[\s\S]*?id="journal-open"[^>]*>Save to Journal<\/button>[\s\S]*?id="wipe"/);
    assert.doesNotMatch(markup, /id="bip85-open"|>Derive BIP-85 child<\/button>/);
  }
  assert.match(appSource, /getElementById\("journal-open"\)/);
  assert.match(appSource, /\["calc", "workspace\.key", "workspace\.keyShort"\], \["vanity", "workspace\.vanity", "workspace\.vanityShort"\], \["bip85", "workspace\.bip85", "workspace\.bip85Short"\]/);
});

test("Silent Payments sits between Multi Signature and PSBT / Nonce", () => {
  const order = /Keys[\s\S]*Multi Signature[\s\S]*Silent Payments[\s\S]*aria-label="PSBT"/;
  assert.match(template, order);
  assert.match(appSource, /\["calc", "workspace\.key", "workspace\.keyShort"\], \["vanity", "workspace\.vanity", "workspace\.vanityShort"\], \["bip85", "workspace\.bip85", "workspace\.bip85Short"\], \["msig", "workspace\.msig", "workspace\.msigShort"\], \["sp", "workspace\.sp", "workspace\.spShort"\], \["bip47", "workspace\.bip47", "workspace\.bip47Short"\], \["psbt", "workspace\.psbt", "workspace\.psbtShort"\]/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="sp-card"/);
    assert.match(markup, /id="sp-key"/);
    assert.match(markup, /id="sp-network"/);
    assert.match(markup, /id="sp-derive"/);
    assert.match(markup, /id="sp-send-go"/);
    assert.match(markup, /id="sp-verify-go"/);
    assert.match(markup, /BIP-352/);
  }
  assert.match(css, /#sp-card\[hidden\]/);
});

test("Silent Payments has a connected SP Station with a monochrome coin-and-signal icon", () => {
  assert.match(appSource, /function hodlCreateSilentPaymentsIcon\(\) \{/);
  assert.match(appSource, /span\.className = "key-tab-icon key-tab-lab-icon silent-payments-icon bench-tab-icon"/);
  assert.match(appSource, /\[\["signal-inner",[\s\S]*?\["signal-outer",/);
  assert.match(appSource, /rim\.setAttribute\("data-part", "coin-rim"\)/);
  assert.match(appSource, /ridge\.setAttribute\("data-part", "coin-ridge"\)/);
  assert.doesNotMatch(appSource, /let inset = document\.createElementNS/);
  assert.match(appSource, /function hodlInitSpBench\(\) \{/);
  assert.match(appSource, /label\.textContent = "SP Station";/);
  assert.match(appSource, /button\.append\(hodlCreateSilentPaymentsIcon\(\), label\);/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="sp-manager"/);
    assert.match(markup, /id="sp-tabs"/);
  }
  assert.doesNotMatch(template, /aria-label="Silent Payments"><span class="workspace-tab-icon/);
});

test("BIP-47 sits between Silent Payments and PSBT / Nonce", () => {
  const order = /Silent Payments[\s\S]*BIP-47[\s\S]*aria-label="PSBT"/;
  assert.match(template, order);
  assert.match(appSource, /\["sp", "workspace\.sp", "workspace\.spShort"\], \["bip47", "workspace\.bip47", "workspace\.bip47Short"\], \["psbt", "workspace\.psbt", "workspace\.psbtShort"\]/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip47-card"/);
    assert.match(markup, /id="bip47-key"/);
    assert.match(markup, /id="bip47-network"/);
    assert.match(markup, /id="bip47-identity"/);
    assert.match(markup, /id="bip47-derive"/);
    assert.match(markup, /id="bip47-send-go"/);
    assert.match(markup, /id="bip47-notify-go"/);
    assert.match(markup, /id="bip47-verify-go"/);
    assert.match(markup, /BIP-47/);
  }
  assert.match(css, /#bip47-card\[hidden\]/);
  assert.equal(en["workspace.bip47"], "BIP-47");
  assert.equal(en["workspace.bip47Short"], "BIP47");
});

test("BIP-47 has a connected Station and states that it never scans the chain", () => {
  assert.match(appSource, /function hodlCreateBip47Icon\(\) \{/);
  assert.match(appSource, /span\.className = "key-tab-icon key-tab-lab-icon bip47-bench-icon bench-tab-icon"/);
  assert.match(appSource, /function hodlInitBip47Bench\(\) \{/);
  assert.match(appSource, /label\.textContent = "BIP-47 Station";/);
  assert.match(appSource, /button\.append\(hodlCreateBip47Icon\(\), label\);/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip47-manager"/);
    assert.match(markup, /id="bip47-tabs"/);
  }
  // The tab is a calculator: it must say so, and must never fetch or broadcast.
  assert.match(appSource, /Educational calculator only/);
  assert.match(appSource, /does not scan the chain/);
  assert.match(appSource, /Receiving the coins still needs a node or a wallet somewhere else/);
  assert.doesNotMatch(appSource, /fetch\(\s*["'`]https?:/);
});

test("BIP-47 refuses child secrets without private material", () => {
  const bip47 = read("src/js/bip47.js");
  // Watch-only means the public half only: the ECDH steps need a private key
  // and must say so rather than returning something derived from nothing.
  assert.match(bip47, /Receive addresses need the recipient's private payment code node/);
  assert.match(bip47, /watch-only material cannot produce them/i);
  assert.match(appSource, /The m\/47h path is hardened, so a root xpub cannot reach it/);
  assert.match(appSource, /Watch-only material cannot derive these addresses/);
  // No CSPRNG anywhere in the scheme layer, and no network of any kind.
  assert.doesNotMatch(bip47, /Math\.random|getRandomValues/);
  assert.doesNotMatch(bip47, /fetch\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage/);
});

test("the workspace switcher keeps every tool on screen as a tab strip", () => {
  // The switcher is a nav holding one scrollable strip of tabs; it is neither
  // a segmented control nor a dropdown. Every tool is visible without asking.
  assert.match(template, /<nav class="workspace no-print" id="workspace">/);
  assert.match(appSource, /<nav class="workspace no-print" id="workspace"><\/nav>/);
  assert.doesNotMatch(template, /segmented-control" id="workspace"/);
  assert.match(template, /<div class="workspace-tabs" id="workspace-tabs" role="tablist" aria-label="Tool">/);
  // All seven tools ship in the static markup, each with a full name and the
  // short form narrow screens show instead.
  for (const [full, short, key, shortKey] of [["Keys", "Keys", "workspace.key", "workspace.keyShort"], ["Vanity", "Vanity", "workspace.vanity", "workspace.vanityShort"], ["BIP-85", "BIP85", "workspace.bip85", "workspace.bip85Short"], ["Multi Signature", "MultiSig", "workspace.msig", "workspace.msigShort"], ["Silent Payments", "SP", "workspace.sp", "workspace.spShort"], ["PSBT", "PSBT", "workspace.psbt", "workspace.psbtShort"], ["Journal", "Journal", "workspace.journal", "workspace.journalShort"]]) {
    assert.ok(
      template.includes(`<span class="workspace-tab-full">${full}</span><span class="workspace-tab-short">${short}</span>`),
      `${full} is missing from the workspace strip`,
    );
    assert.match(appSource, new RegExp(`\\["[a-z0-9]+", "${key.replaceAll(".", "\\.")}", "${shortKey.replaceAll(".", "\\.")}"\\]`));
  }
  // One swaps for the other at the width the header drops its own labels.
  assert.match(css, /\.workspace-tab-short \{ display: none; \}/);
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.workspace-tab-full \{ display: none; \}\s*\.workspace-tab-short \{ display: inline; \}/);
  assert.match(appSource, /fullLabel\.textContent = hodlT\(label\);\s*shortLabel\.textContent = hodlT\(short\);/);
  // Hidden text leaves the accessibility tree, so the full name is stated on
  // the tab itself and assistive tech hears it at every width.
  assert.match(appSource, /button\.setAttribute\("aria-label", hodlT\(label\)\);/);
  for (const full of ["Keys", "Vanity", "BIP-85", "Multi Signature", "Silent Payments", "PSBT", "Journal"]) {
    assert.match(template, new RegExp(`aria-label="${full.replace("/", "\\/")}">[\\s\\S]*?<span class="workspace-tab-full">${full.replace("/", "\\/")}</span>`), `${full} tab needs its accessible name`);
  }
  // A tablist owes arrow keys; the key and multisig strips already answer them.
  assert.match(appSource, /function hodlWorkspaceTabKeydown\(event, index\) \{/);
  assert.match(appSource, /if \(event\.key === "ArrowRight"\) next = \(index \+ 1\) % length;/);
  assert.match(appSource, /else if \(event\.key === "ArrowLeft"\) next = \(index - 1 \+ length\) % length;/);
  assert.match(appSource, /else if \(event\.key === "Home"\) next = 0;/);
  assert.match(appSource, /else if \(event\.key === "End"\) next = length - 1;/);
  assert.match(appSource, /button\.onkeydown = \(event\) => hodlWorkspaceTabKeydown\(event, index\);/);
  // Nothing collapses the strip behind a control: no toggle, no dropdown, and
  // no open/close state left over from one.
  assert.doesNotMatch(`${template}${appSource}`, /workspace-menu|hodlSetWorkspaceMenuOpen/);
  assert.doesNotMatch(css, /\.workspace-menu/);
  // It wears the key tabs' folder shape: a raised active tab whose bottom
  // border is painted out against the strip's rule.
  // The strip overlaps the panel by a pixel rather than drawing its own rule:
  // it is a scroll container, so it would clip any tab reaching past its edge
  // and the chosen tab could never cut the line.
  assert.match(css, /\.workspace-tabs \{[^}]*margin-bottom: -1px;/s);
  assert.doesNotMatch(css, /\.workspace-tabs \{[^}]*border-bottom:/s);
  assert.match(css, /\.workspace-tab \{[^}]*border-radius: 10px 10px 0 0;/s);
  // The chosen tab takes the panel's ground and hides its own bottom edge in
  // it, so the strip's rule is cut and the two become one shape.
  assert.match(css, /\.workspace-tab\.active \{[^}]*background: var\(--bg\); color: var\(--fg\); border-color: var\(--border\); border-bottom-color: var\(--bg\);/s);
  // The panel closes the folder: the tool content sits inside a border that
  // carries on from the strip, open at the top where the strip's rule is.
  for (const markup of [template, appSource]) {
    assert.match(markup, /<div class="workspace-panel" id="workspace-panel">/);
  }
  assert.match(css, /\.workspace-panel \{[^}]*border: 1px solid var\(--border\); border-radius: 0 0 20px 20px;/s);
  // Cards in the panel close on their own edge; the page's other cards, the
  // pitch and the sources among them, keep the shared 16px both ways.
  assert.match(css, /\.workspace-panel \.card \{ margin-bottom: 0; \}/);
  assert.match(css, /\.card \{[^}]*margin: 16px 0; \}/);
  // Every tool panel lives inside it, and the closing Sources card does not.
  for (const markup of [template, appSource]) {
    const panel = markup.slice(markup.indexOf('<div class="workspace-panel"'), markup.indexOf('class="card muted sources"'));
    for (const id of ["calc-card", "bip85-card", "msig-card", "sp-card", "psbt-card", "journal-card", "journal-notes-card", "journal-state-card", "journal-log-card"]) {
      assert.ok(panel.includes(`id="${id}"`), `${id} must sit inside the workspace panel`);
    }
    assert.ok(panel.includes('<div id="out">'), "the results region must sit inside the workspace panel");
  }
  // Overflow scrolls instead of wrapping or hiding, so more tools still fit.
  assert.match(css, /\.workspace-tabs \{[^}]*overflow-x: auto;/s);
  assert.match(css, /\.workspace-tabs::-webkit-scrollbar \{ display: none;/);
  // Runtime: entries drive the workspace, the strip drags like the key tabs,
  // and the active tab is scrolled into view when it changes.
  assert.match(appSource, /strip\.setAttribute\("role", "tablist"\);/);
  assert.match(appSource, /button\.onclick = \(\) => hodlShowWorkspace\(id\);/);
  assert.match(appSource, /hodlInitTabDrag\(strip\);/);
  assert.match(appSource, /\[\.\.\.hodlElement\("#workspace-tabs"\)\.querySelectorAll\("\[data-workspace\]"\)\]\.forEach/);
  assert.match(appSource, /hodlRevealTab\(hodlElement\("#workspace-tabs"\)/);
  // A hint points at tools past the right edge. It tracks what is still out
  // there rather than merely whether the strip scrolls, so it clears once the
  // end is reached, and it is decorative: the tabs are the real route.
  for (const markup of [template, appSource]) {
    assert.match(markup, /More tools/);
  }
  // It is a real control, so it is a button with a label rather than a
  // decorative span: an interactive element must not be hidden from the
  // accessibility tree.
  assert.match(template, /<button type="button" class="workspace-more" id="workspace-more" aria-controls="workspace-tabs" aria-label="Scroll the tool list to see more tools" hidden>/);
  assert.match(appSource, /hint\.setAttribute\("aria-label", "Scroll the tool list to see more tools"\);/);
  assert.doesNotMatch(appSource, /hint\.setAttribute\("aria-hidden"/);
  // One click finishes the journey: the label promises the remaining tools and
  // clears at the end, so stopping short would read as a broken control.
  assert.match(appSource, /hint\.onclick = \(\) => strip\.scrollTo\(\{\s*left: strip\.scrollWidth,/s);
  assert.match(appSource, /behavior: matchMedia\("\(prefers-reduced-motion: reduce\)"\)\.matches \? "auto" : "smooth",/);
  // No edge fade: the strip is narrow enough on a phone that every pixel of a
  // label has to stay readable.
  assert.doesNotMatch(`${css}${appSource}`, /has-overflow/);
  assert.match(appSource, /function hodlSyncWorkspaceOverflow\(\) \{/);
  assert.match(appSource, /hint\.hidden = strip\.scrollWidth - strip\.clientWidth - strip\.scrollLeft <= 1;/);
  assert.match(appSource, /strip\.addEventListener\("scroll", hodlSyncWorkspaceOverflow, \{ passive: true \}\);/);
  assert.match(appSource, /new ResizeObserver\(hodlSyncWorkspaceOverflow\)\.observe\(strip\);/);
  assert.match(css, /\.workspace-more \{[^}]*position: absolute; right: 0; bottom: 100%;/s);
  assert.match(css, /\.workspace-more\[hidden\] \{ display: none; \}/);
});

test("Key Station stays put and a derived key opens a fingerprint tab with a summary", () => {
  assert.match(appSource, /function hodlNewLabState\(\) \{/);
  assert.match(appSource, /hodlNewKeyState\("Key Station", 0, 0\)/);
  assert.match(appSource, /name = state\.isLab \? "Key Station"/);
  assert.match(appSource, /path\.setAttribute\("d", hodlKeySilhouette\)/);
  assert.match(css, /\.key-tab-icon\.key-tab-lab-icon \{[^}]*color: var\(--muted\);/s);
  assert.match(appSource, /function hodlCommitDerivedKey\(\) \{/);
  assert.match(appSource, /function hodlSelectLab\(\) \{/);
  assert.match(appSource, /function hodlSyncKeyResultView\(\) \{/);
  assert.match(appSource, /hodlKeys\.push\(hodlNewLabState\(\)\)/);
  assert.match(appSource, /hodlCommitDerivedKey\(\)/);
  assert.match(appSource, /button\.id = state\.isLab \? "key-tab-lab"/);
  assert.match(appSource, /function hodlAddKey\(\) \{\s*hodlSelectLab\(\);/s);
  assert.match(appSource, /button\.disabled = !state \|\| state\.isLab;/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="key-summary"/);
    assert.match(markup, /id="key-lab"/);
    assert.match(markup, /id="key-edit-inputs"/);
    assert.match(markup, /id="key-summary-path"/);
    assert.match(markup, /Open Key Station to derive another key/);
  }
  assert.match(appSource, /function hodlSnapshotKeySummary\(/);
  assert.match(appSource, /state\.createdScript = hodlKeySummaryScript\(state\)/);
  assert.match(appSource, /state\.createdPath = hodlKeySummaryPath\(state\)/);
  assert.match(appSource, /function hodlFillLabFromKey\(source\) \{/);
  assert.match(appSource, /function hodlEditKeyInputs\(\) \{/);
  assert.match(appSource, /hodlSelectKey\(hodlFillLabFromKey\(hodlKeys\[hodlActiveKey\]\)\)/);
  assert.match(appSource, /if \(edit\) edit\.onclick = hodlEditKeyInputs;/);
  assert.match(css, /#calc-card\.is-result-view #modes/);
  assert.match(css, /#calc-card:not\(\.is-result-view\) #out/);
});

test("derived key results put private recovery before script type and addresses", () => {
  assert.match(appSource, /\$\{hodlHdWalletData\(t\)\}[\s\S]*id="acct-tabs-label">Script type[\s\S]*id="acct"/);
  assert.match(appSource, /id="wallet-private-heading">\$\{hodlT\("result.private"\)\}/);
  assert.match(appSource, /hodlT\("result.privateDesc"\)/);
  assert.match(appSource, /id="account-private-heading">\$\{hodlT\("result.privateAccount"\)\}/);
  assert.match(appSource, /id="account-watch-heading">\$\{hodlT\("result.watchOnly"\)\}/);
  assert.match(appSource, /id="account-address-heading">Addresses/);
  assert.match(appSource, /Verify the first selected address on another trusted wallet or signing device before accepting bitcoin\./);
  assert.doesNotMatch(appSource, /id="account-receive-heading">Receive/);
  assert.match(appSource, /if \(state\) state\.reveal = hodlRevealPrivate;/);
  assert.match(appSource, /hodlBindWalletResultActions\(\);/);
});

test("every MS Station co-signer row can pick any session key, and key reuse offers a derivation path", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /class="station-key-source msig-station-key-source"[\s\S]*id="msig-session-keys"[\s\S]*id="msig-reuse-session-keys"[\s\S]*id="msig-session-key-status"/);
    assert.match(markup, /Bring in a key from Key Station/);
  }
  assert.match(appSource, /function hodlSessionMsigKeys\(\) \{/);
  assert.match(appSource, /function hodlMatchingMsigExport\(result\) \{/);
  assert.match(appSource, /function hodlSyncMsigKeyAvatar\(row\) \{/);
  assert.match(appSource, /chips\.className = "msig-session-keys"/);
  assert.match(appSource, /hodlCreateMsigSessionKeyButton\(option, "msig-session-key"/);
  assert.match(appSource, /function hodlPickMsigSessionKey\(state, row = hodlMsigNextKeyRow\(\)\) \{/);
  assert.match(appSource, /\(\) => hodlPickMsigSessionKey\(option\.state, row\)/);
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, fingerprint\)/);
  assert.match(appSource, /hodlRefreshMsigSessionPickers\(\)/);
  // Reusing a key for another co-signer must come with a derivation path so
  // every slot derives distinct public keys in the descriptor.
  assert.match(appSource, /className = "msig-key-reuse"/);
  assert.match(appSource, /function hodlSyncMsigKeyReuse\(row\) \{/);
  assert.match(appSource, /function hodlMsigSuggestedDerivationPath\(parsed, row\) \{/);
  assert.match(appSource, /function hodlStripMsigKeyPath\(value\) \{/);
  assert.match(appSource, /function hodlMsigBaseKeyId\(parsed\) \{/);
  assert.match(appSource, /Append a different derivation path so this co-signer derives a different public key in the descriptor\./);
  assert.match(appSource, /parsed\.derivationPath = parsedOrigin\.derivationPath \|\| ""/);
  assert.match(appSource, /must be unhardened \(like \/1\); hardened steps cannot be derived from an extended public key/);
  assert.match(appSource, /function hodlMsigDerivedNode\(parsed\) \{/);
  assert.match(appSource, /let node = hodlMsigDerivedNode\(parsed\);\s*return hodlHex\.encode\(node\.publicKey\)/);
  assert.match(appSource, /\]\$\{canonical\}\$\{parsed\.derivationPath \? "\/" \+ parsed\.derivationPath : ""\}/);
  assert.match(appSource, /var hodlMsigKeyTarget = null/);
  assert.match(appSource, /function hodlMsigNextKeyRow\(\) \{/);
  assert.match(appSource, /reuseSessionKeys\?\.addEventListener\("change"/);
  assert.match(appSource, /Reused keys need different derivation paths\./);
  assert.match(css, /\.msig-session-keys \{/);
  assert.match(css, /\.msig-session-key \{/);
  assert.match(css, /\.msig-session-key\.active/);
  assert.match(css, /\.msig-key-reuse \{/);
  assert.match(css, /\.msig-key-ident \{/);
});

test("BIP-85 and SP Stations can bring in compatible Key Station roots", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip85-session-keys"/);
    assert.match(markup, /id="sp-session-keys"/);
    assert.match(markup, /Bring in a key from Key Station/);
    assert.doesNotMatch(markup, /id="bip85-use-calc"/);
    assert.doesNotMatch(markup, /id="sp-use-calc"/);
  }
  assert.match(appSource, /function hodlSessionHdRootKeys\(\) \{/);
  assert.match(appSource, /state\.result\?\.kind === "hd" && \(state\.result\.mnemonic \|\| state\.result\.rootXprv\)/);
  assert.match(appSource, /function hodlFillStationKeyPicker\(id, selectedSource, onSelect, keys = hodlSessionHdRootKeys\(\)\) \{/);
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, fingerprint\)/);
  assert.match(appSource, /function hodlPickBip85SessionKey\(state\) \{/);
  assert.match(appSource, /function hodlPickSpSessionKey\(state\) \{/);
  assert.match(appSource, /document\.getElementById\("bip85-key"\)\.value = rootXprv;/);
  assert.match(appSource, /document\.getElementById\("sp-key"\)\.value = state\.result\?\.mnemonic \|\| state\.result\?\.rootXprv \|\| "";/);
  assert.match(appSource, /document\.getElementById\("sp-pass"\)\.value = state\.result\?\.mnemonic \? state\.fields\?\.pass \|\| "" : "";/);
  assert.match(appSource, /document\.getElementById\("bip85-key"\)\.addEventListener\("input"/);
  assert.match(appSource, /document\.getElementById\("sp-key"\)\.addEventListener\("input", detachStationKey\)/);
  assert.match(css, /\.session-key-picker \{ display: flex; flex-wrap: wrap; gap: 8px; \}/);
  // The selected chip is unmistakable: accent border and tint plus a check
  // mark, so the selection never rests on the border colour alone.
  assert.match(css, /\.session-key-option\.active \{[^}]*border-color: var\(--selection-accent\)[^}]*box-shadow: inset 0 0 0 1px var\(--selection-accent\)/s);
  assert.match(css, /\.session-key-option\.active \.session-key-check \{ display: inline-flex; \}/);
});

test("MS Station stays put and a derived wallet opens its own results tab", () => {
  assert.match(appSource, /function hodlNewMsigLabState\(\) \{/);
  assert.match(appSource, /hodlNewMsigState\("MS Station", 0, 0\)/);
  assert.match(appSource, /name = state\.isLab \? "MS Station"/);
  assert.match(appSource, /button\.append\(hodlCreateMsigIcon\(state\.isLab\), label\)/);
  assert.match(appSource, /function hodlCommitDerivedMsig\(\) \{/);
  assert.match(appSource, /function hodlSelectMsigLab\(\) \{/);
  assert.match(appSource, /hodlMsigs\.push\(hodlNewMsigLabState\(\)\)/);
  assert.match(appSource, /hodlCommitDerivedMsig\(\)/);
  assert.match(appSource, /out\.innerHTML = `/);
  assert.match(appSource, /function hodlAddMsig\(\) \{\s*hodlSelectMsigLab\(\);/s);
  assert.match(appSource, /function hodlFillMsigLabFromWallet\(source\) \{/);
  assert.match(appSource, /function hodlEditMsigInputs\(\) \{/);
  assert.match(appSource, /hodlSelectMsig\(hodlFillMsigLabFromWallet\(hodlMsigs\[hodlActiveMsig\]\)\)/);
  assert.match(appSource, /if \(edit\) edit\.onclick = hodlEditMsigInputs;/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="msig-summary"/);
    assert.match(markup, /id="msig-lab"/);
    assert.match(markup, /id="msig-out"/);
    assert.match(markup, /id="msig-edit-inputs"/);
  }
  assert.match(css, /#msig-card:not\(\.is-result-view\) #msig-out/);
  assert.match(css, /#msig-card\.is-result-view \.msig-lab/);
});

test("BIP-85 Station retains each child in a LifeHash fingerprint tab", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip85-manager"/);
    assert.match(markup, /id="bip85-tabs"/);
    assert.match(markup, /id="add-bip85"/);
    assert.match(markup, /id="delete-bip85"/);
    assert.match(markup, /id="bip85-bench"/);
  }
  assert.match(appSource, /function hodlNewBip85BenchState\(\) \{/);
  assert.match(appSource, /name: "BIP-85 Station"/);
  assert.match(appSource, /function hodlCreateBip85Tab\(index\) \{/);
  assert.match(appSource, /if \(state\.isLab\) button\.append\(hodlCreateBip85BenchIcon\(\), label\)/);
  assert.match(appSource, /function hodlCreateBip85BenchIcon\(\) \{/);
  assert.match(appSource, /\["seed", "M12 1\.75/);
  assert.match(appSource, /\["left-leaf",/);
  assert.match(appSource, /\["right-leaf",/);
  assert.match(css, /\.bench-tab-icon,[\s\S]*?width: 18px; height: 18px;[\s\S]*?color: var\(--muted\);/);
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, state\.fingerprint\)/);
  assert.match(appSource, /hodlBip85Children\.push\(state\)/);
  assert.match(appSource, /function hodlDeleteActiveBip85\(\) \{[\s\S]*wipeBip85Result\(state\.result\)/);
  assert.match(appSource, /state\.reveal = hodlBip85Reveal/);
  assert.match(css, /#bip85-card:not\(\[hidden\]\)/);
});

test("session wallets use folder tabs that merge into the card", () => {
  assert.match(css, /\.key-manager \{ margin: 14px 0 -1px;/);
  assert.match(css, /\.key-tab \{[^}]*border-radius: 10px 10px 0 0;/s);
  assert.match(css, /\.key-tab\.active, \.key-tab-editing \{[^}]*border-bottom-color: var\(--surface\);/s);
  assert.match(css, /#calc-card:not\(\[hidden\]\), #msig-card:not\(\[hidden\]\), #bip85-card:not\(\[hidden\]\), #sp-card:not\(\[hidden\]\), #psbt-card:not\(\[hidden\]\), #psbted-card:not\(\[hidden\]\), #vanity-card:not\(\[hidden\]\) \{[^}]*border-radius: 0 0 20px 20px;/s);
  assert.match(css, /\.workspace-tab \{[^}]*border-radius: 10px 10px 0 0;/s);
  assert.match(appSource, /let lifehash = tab\.querySelector\("\.key-tab-lifehash"\);/);
  assert.doesNotMatch(appSource, /editor\.append\(hodlCreateKeyIcon\(state\.color\), input\)/);
});

test("the vanity grinder is a workspace tab that ships collapsed and never auto-runs", () => {
  // The tab is registered between Keys and BIP-85 and localized like the rest.
  assert.match(appSource, /\["vanity", "workspace\.vanity", "workspace\.vanityShort"\]/);
  for (const code of ["en", "de", "es", "fr", "pt"]) {
    const catalog = JSON.parse(read(`src/locales/${code}.json`));
    assert.ok(catalog["workspace.vanity"]?.length, `${code} workspace.vanity`);
    assert.ok(catalog["workspace.vanityShort"]?.length, `${code} workspace.vanityShort`);
  }
  // Both templates carry the intro and the card, both hidden until the tab is
  // picked; the card is a tabpanel and stays out of print output.
  for (const markup of [template, appSource]) {
    assert.match(markup, /<div class="tool-intro" id="vanity-tool-intro" hidden>/);
    assert.match(markup, /<section class="card no-print" id="vanity-card" role="tabpanel" hidden>/);
    // The key comes in through the same clickable Key Station picker the
    // BIP-85 and Silent Payments tabs use; the selected key is restated with
    // its starting passphrase, labelled and read-only.
    assert.match(markup, /<p class="label">Bring in a key from Key Station<\/p>/);
    assert.match(markup, /<div class="session-key-picker" id="vanity-session-keys" role="group" aria-label="Key Station keys" hidden><\/div>/);
    assert.match(markup, /<div class="vanity-source" id="vanity-source" hidden>/);
    assert.match(markup, /<span class="vanity-source-kicker">Selected key<\/span>/);
    assert.match(markup, /<label class="field" for="vanity-pass">Starting passphrase <span class="vanity-source-from" id="vanity-pass-from"><\/span><\/label>/);
    assert.match(markup, /<input id="vanity-pass" readonly autocomplete="off" spellcheck="false"[^>]*aria-describedby="vanity-pass-note">/);
    // Method and address type are dropdowns; the derivation grind swaps the
    // counter fields for an account index range.
    assert.match(markup, /<select id="vanity-method">\s*<option value="passphrase" selected(?:="selected")?>Passphrase grind<\/option>\s*<option value="derivation">Derivation grind<\/option>/);
    assert.match(markup, /<select id="vanity-script">[\s\S]*?<option value="p2wpkh" selected(?:="selected")?>[\s\S]*?<option value="p2tr">[\s\S]*?<option value="sp">Silent Payments BIP-352 · sp1qq…<\/option>/);
    assert.match(markup, /<input id="vanity-prefix" autocomplete="off" spellcheck="false"[^>]*aria-describedby="vanity-prefix-help">/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Passphrase length\s*<input id="vanity-length" type="number" min="1" max="32"[^>]*value="8"/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Start counter\s*<input id="vanity-start" inputmode="numeric"[^>]*value="0"/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Range size\s*<input id="vanity-count" inputmode="numeric"[^>]*value="1000000"/);
    assert.match(markup, /<label class="field" data-vanity-method="derivation" hidden>Start account\s*<input id="vanity-account-start" inputmode="numeric"[^>]*value="0"/);
    assert.match(markup, /<label class="field" data-vanity-method="derivation" hidden>Accounts to try\s*<input id="vanity-account-count" inputmode="numeric"[^>]*value="100000"/);
    assert.match(markup, /<input id="vanity-workers" type="number" min="1" max="64"/);
    assert.match(markup, /<p class="muted" id="vanity-estimate" aria-live="polite"><\/p>/);
    assert.match(markup, /<button class="btn primary" id="vanity-go" type="button">Start grinding<\/button>/);
    assert.match(markup, /id="vanity-progress" role="progressbar"[^>]*hidden>/);
    assert.match(markup, /<button class="btn secondary" id="vanity-stop" type="button" disabled>Stop<\/button>/);
    assert.match(markup, /<button class="btn clear-current-action" id="vanity-wipe" type="button" disabled aria-disabled="true">Clear results<\/button>/);
    assert.match(markup, /<p class="muted" id="vanity-status" aria-live="polite">/);
    assert.match(markup, /<p class="err" id="vanity-error" role="alert"><\/p>/);
    assert.match(markup, /<div id="vanity-out" aria-live="polite"><\/div>/);
    // The passphrase warning is part of the card, not a docs afterthought.
    assert.match(markup, /A vanity passphrase is a BIP39 passphrase/);
    // No typed salt, no brain-wallet convention: the grind runs on a key.
    const card = markup.slice(markup.indexOf('id="vanity-tool-intro"'), markup.indexOf('id="vanity-out"'));
    assert.doesNotMatch(card, /id="vanity-salt"|brain.wallet|SHA-256/i);
  }
  // The tab rides the same show/hide plumbing as every other tool, and
  // leaving the tab stops the grind instead of grinding unseen.
  assert.match(appSource, /getElementById\("vanity-card"\)\.hidden = id !== "vanity"/);
  assert.match(appSource, /\["bip85", "sp", "bip47", "msig", "calc", "vanity"\]\.forEach/);
  assert.match(appSource, /else if \(hodlWorkspace === "vanity"\) hodlVanityCancel\(\);/);
  assert.match(appSource, /function hodlInitWorkspace\(\) \{[\s\S]*?hodlInitVanity\(\);/);
  // The workers spawn only from the button handler; nothing starts on boot,
  // on tab switches, or on input.
  assert.match(appSource, /go\.onclick = hodlRunVanity;/);
  assert.match(appSource, /function hodlRunVanity\(\) \{[\s\S]*?new VanityGrinder\(/);
  assert.equal(appSource.indexOf("new VanityGrinder"), appSource.indexOf("new VanityGrinder", appSource.indexOf("function hodlRunVanity")));
  // Passphrases are private material: masked by default behind the same
  // reveal-toggle convention as the other tools, and copied from match state
  // rather than a DOM attribute so a wipe cannot leave a copyable secret.
  assert.match(appSource, /hodlVanityReveal = false/);
  assert.match(appSource, /type="checkbox" id="vanity-reveal"/);
  assert.match(appSource, /copyMarkup\("data-vanity-copy", index, "Copy passphrase"\)/);
  assert.match(appSource, /\$\{attribute\}="\$\{index\}"/);
  const vanityController = appSource.slice(appSource.indexOf("// ── Vanity grinder"), appSource.indexOf("function hodlInitWorkspace()"));
  assert.doesNotMatch(vanityController, /data-phrase/);
  // Blob workers keep the artifact one file; the CSP pins exactly that.
  assert.match(template, /worker-src 'self' blob:/);
  assert.match(read("src/js/vanity.js"), /new Blob\(\[VANITY_WORKER_SOURCE\]/);
  // The picker rides the shared station-key plumbing and lists derived HD-root
  // keys only — the Key Station lab tab is a work surface, never a chip.
  assert.match(appSource, /hodlFillStationKeyPicker\("vanity-session-keys", hodlVanitySource, hodlPickVanitySessionKey, hodlVanitySourceKeys\(\)\)/);
  assert.match(appSource, /function hodlVanitySourceKeys\(\) \{\s*return hodlSessionHdRootKeys\(\);/);
  // The selected key's passphrase is read from its state, never retyped: the
  // source panel shows it verbatim and the plan reads it again at start.
  assert.match(vanityController, /function hodlVanitySyncSource\(\) \{[\s\S]*?pass = String\(state\.fields\?\.pass \?\? ""\)[\s\S]*?field\.value = pass;/);
  assert.match(vanityController, /function hodlVanityPlan\(state, method, scriptId\) \{[\s\S]*?validateVanityPassphrase\(fields\.pass \?\? ""\)/);
  // Matching is mainnet only, on the key's own account path.
  assert.match(vanityController, /Vanity matching is Bitcoin mainnet/);
  assert.match(vanityController, /vanityPathIndexes\(fields\.derivationAccountPath \|\| "m\/84'\/0'\/0'"\)/);
  // Update key goes through the same Edit input → Derive path the Keys tab
  // uses (lab clone, restore, hodlCalculateKey), then folds a re-fingerprinted
  // key back into its own tab and gives the lab back.
  assert.match(vanityController, /async function hodlVanityApplyMatch\(index\) \{[\s\S]*?hodlFillLabFromKey\(state\)[\s\S]*?draft\.fields\.pass = match\.passphrase;[\s\S]*?draft\.fields\.account = `\$\{match\.index\}[\s\S]*?await hodlDeriveWithProgress\("key", hodlCalculateKey\);[\s\S]*?hodlKeys\[target\] = \{ \.\.\.active, id: state\.id, number: state\.number, color: state\.color/);
  assert.match(vanityController, /data-vanity-apply="\$\{index\}"/);
  assert.match(vanityController, /Saved to key \$\{hodlEscapeHtml\(match\.savedTo\)\}/);
  // The chip picker marks the selected chip with a check, not colour alone.
  assert.match(appSource, /check\.className = "session-key-check";/);
  assert.match(css, /\.session-key-option\.active \{[^}]*border-color: var\(--selection-accent\)/s);
  assert.match(css, /\.session-key-option\.active \.session-key-check \{ display: inline-flex; \}/);
  // The picker fills on tab entry and station-key refreshes, never at boot:
  // the chips carry LifeHash images and the LifeHash module is a later
  // parser-inserted script, which the WASM-ready promise can beat (the same
  // hazard the footer's load-event wait documents).
  const vanityInit = appSource.slice(appSource.indexOf("function hodlInitVanity()"), appSource.indexOf("function hodlInitWorkspace()"));
  assert.doesNotMatch(vanityInit, /hodlFillStationKeyPicker\s*\(|hodlFillKeyTabLifehash\s*\(/);
  assert.match(appSource, /else if \(id === "vanity"\) \{\s*\/\/ [^\n]*\n\s*hodlFillStationKeyPicker\("vanity-session-keys"[^\n]*\n\s*hodlVanitySyncSource\(\);/);
  // The LifeHash image filler itself is boot-safe: `typeof undeclared?.prop`
  // throws a ReferenceError, so the plain typeof guard must come first (a
  // boot-time picker refresh would otherwise kill the page in Chromium).
  assert.match(appSource, /function hodlFillKeyTabLifehash\(image, fingerprint\) \{[\s\S]*?if \(!image \|\| !fingerprint \|\| typeof hodlLifeHash === "undefined" \|\| typeof hodlLifeHash\.fromFingerprint !== "function"\) return;/);
  const vanityJs = read("src/js/vanity.js");
  // Grinding is WASM-only: candidates are produced by the vanity_grind export
  // inside the worker's WebAssembly instance (PBKDF2, BIP32, and the address
  // encoders). The JS side has no hash or curve grind loop and no CPU
  // fallback — it spawns workers, validates input, derives the parent node
  // once for the derivation grind (on the app side, through hdkey.js), and
  // re-encodes matching records for display through the same WASM-backed
  // address facade every other tool uses.
  assert.match(read("src/js/vanity-worker.js"), /wasm\.vanity_grind\(/);
  assert.doesNotMatch(vanityJs, /secp256k1|getPublicKey|Point\.|pbkdf2Sha512|hmacSha512|sha512/, "no curve or hash math on the JS side");
  assert.doesNotMatch(vanityJs, /fallback/i, "no CPU fallback grind path");
  // Both methods are the engine's, not JS approximations.
  assert.match(read("vanity-wasm/src/lib.rs"), /const SCRIPT_SP: u32 = 4;[\s\S]*const MODE_PASSPHRASE: u32 = 0;[\s\S]*const MODE_NODE: u32 = 1;[\s\S]*const PBKDF2_ROUNDS: u32 = 2048;/);
  // The calculator contract: no randomness anywhere in the vanity code paths.
  for (const path of ["src/js/vanity.js", "src/js/vanity-worker.js", "vanity-wasm/src/lib.rs"]) {
    assert.doesNotMatch(read(path), /Math\.random|getRandomValues|rand::|getrandom/, `${path} must never invent entropy`);
  }
});

test("the private recovery section lists the BIP39 passphrase beside the seed phrase", () => {
  // The HD result carries the passphrase text (not just a flag) so the row
  // can render; imported roots and single keys carry an empty one.
  assert.match(appSource, /passphraseUsed: source\.passphraseUsed,\s*passphrase: source\.passphrase \?\? "",/);
  assert.match(appSource, /\{ mnemonic, passphraseUsed: passphrase\.length > 0, passphrase, entropyHex, seedHex,/);
  assert.match(appSource, /\{ mnemonic: null, passphraseUsed: false, passphrase: "", entropyHex: null,/);
  // Rendered right after the words, through the same masked private field as
  // the entropy and seed hex; absent when no passphrase is in use.
  assert.match(appSource, /hodlSeedPhraseField\(`Your seed phrase[^\n]*\n[^\n]*\n[^\n]*\n\s*if \(wallet\.mnemonic && wallet\.passphraseUsed && wallet\.passphrase\) privateFields\.push\(hodlPrivateFieldHtml\("BIP39 passphrase", wallet\.passphrase\)\);\n\s*if \(wallet\.entropyHex\)/);
});

test("the vanity estimate is timed from a device sample, and Stop on first find halts the grind at the first match", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /<button class="btn secondary" id="vanity-stop" type="button" disabled>Stop<\/button>\s*<button class="btn secondary" id="vanity-first" type="button" aria-pressed="false"[^>]*>Stop on first find<\/button>/);
  }
  const vanityController = appSource.slice(appSource.indexOf("// ── Vanity grinder"), appSource.indexOf("function hodlInitWorkspace()"));
  // The sample runs on tab entry, once per session, never while a grind is
  // on, and never at boot (the tab-entry branch is the only caller).
  assert.match(appSource, /else if \(id === "vanity"\) \{[^}]*hodlVanitySyncSource\(\);\s*hodlVanityStartBenchmark\(\);\s*\}/);
  assert.match(vanityController, /function hodlVanityStartBenchmark\(\) \{\s*if \(hodlVanityBench \|\| hodlVanityBenchPending \|\| hodlVanityRunning\) return;/);
  assert.equal(appSource.split("hodlVanityStartBenchmark()").length, 3, "one definition, one call site");
  const vanityInit = appSource.slice(appSource.indexOf("function hodlInitVanity()"), appSource.indexOf("function hodlInitWorkspace()"));
  assert.doesNotMatch(vanityInit, /vanityBenchmark|hodlVanityStartBenchmark/);
  // The estimate uses the live rate while grinding, otherwise the sample
  // scaled by the worker count, and speaks in time.
  assert.match(vanityController, /function hodlVanityExpectedRate\(\) \{\s*if \(hodlVanityRunning && hodlVanityLiveRate > 0\) return hodlVanityLiveRate;/);
  assert.match(vanityController, /expect a match roughly every \$\{hodlVanityFormatDuration\(Number\(work\) \/ rate\)\}/);
  assert.match(vanityController, /"Measuring this device…"/);
  // Stop on first find is a toggle that asks the pool to stop as the first
  // match lands, and the status says so.
  assert.match(vanityController, /if \(hodlVanityStopFirst && hodlVanityRunning\) hodlVanityStop\(\);/);
  assert.match(vanityController, /"Stopped at first match"/);
  assert.match(vanityController, /document\.getElementById\("vanity-first"\)\.onclick = hodlVanityToggleStopFirst;/);
  // Worker chunks adapt to the device so the bar moves smoothly from the start.
  const worker = read("src/js/vanity-worker.js");
  assert.match(worker, /var STEP_MS = 120;/);
  assert.match(worker, /var chunkSize = mode === 1 \? 512 : 16;/);
  assert.match(worker, /chunkSize = Math\.max\(MIN_CHUNK, Math\.min\(MAX_CHUNK, Math\.round\(chunk \* STEP_MS \/ elapsed\)\)\);/);
});

test("Update key carries the fingerprint and LifeHash with it: rows show the resulting key, images never paint a stale fingerprint, loaded tools reload", () => {
  const vanityController = appSource.slice(appSource.indexOf("// ── Vanity grinder"), appSource.indexOf("function hodlInitWorkspace()"));
  // A passphrase-grind row is its own seed, so its fingerprint is computed
  // from the key's words once and rendered with a LifeHash; an account row
  // keeps the key's fingerprint.
  assert.match(vanityController, /function hodlVanityMatchFingerprint\(match, run\) \{[\s\S]*?if \(run\.method !== "passphrase"\) return \(match\.fingerprint = run\.sourceLabel\);[\s\S]*?hodlMnemonicToSeed\(mnemonic, match\.passphrase\)[\s\S]*?hodlFingerprintHex\(root\.fingerprint\)/);
  assert.match(vanityController, /<th scope="col">Key after update<\/th>/);
  assert.match(vanityController, /box\.querySelectorAll\("img\[data-vanity-lifehash\]"\)\.forEach\(\(image\) => hodlFillKeyTabLifehash\(image, image\.dataset\.vanityLifehash\)\);/);
  // The shared LifeHash filler tags the image with the fingerprint it was
  // asked for and lets only the latest request paint.
  assert.match(appSource, /image\.dataset\.fingerprint = fingerprint;\s*hodlLifeHash\.fromFingerprint\(fingerprint\)\.then\(\(url\) => \{\s*if \(!image\.isConnected \|\| image\.dataset\.fingerprint !== fingerprint\) return;/);
  // Tools holding the old seed reload it, and the status names the change.
  assert.match(vanityController, /if \(hodlSpSource === "key:" \+ updated\.id\) hodlPickSpSessionKey\(updated\);\s*if \(hodlBip85Source === "key:" \+ updated\.id\) hodlPickBip85SessionKey\(updated\);/);
  assert.match(vanityController, /its master fingerprint and LifeHash changed from \$\{run\.sourceLabel\} to \$\{match\.savedTo\}/);
});
