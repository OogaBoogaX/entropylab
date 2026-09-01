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
    assert.match(markup, /<select id="psbt-network"><option value="mainnet" selected(?:="selected")?>Bitcoin mainnet<\/option>/);
    assert.match(markup, /<select id="sp-network"><option value="mainnet" selected(?:="selected")?>Bitcoin mainnet<\/option>/);
  }
  assert.match(appSource, /function hodlReadCoinType\(input = document\.getElementById\("network"\), mark = true\)/);
  assert.match(appSource, /function hodlNetworkFromCoinType\(coinType\)/);
  assert.match(appSource, /Number\(coinType\) === 1 \? "testnet" : "mainnet"/);
  assert.match(app, /coinType:"0'",coinTypeHardened?:!0,network:"mainnet"|coinType:"0'",coinTypeHarden:!0,network:"mainnet"/);
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
  assert.match(appSource, /label\.innerHTML = `\$\{hodlCopiedIconMarkup\(\)\}<span>Done<\/span>`/);
  assert.match(appSource, /async function hodlAddressRowsWithProgress/);
  assert.match(css, /\.derive-progress\.is-complete \{[^}]*var\(--ok\)/);
  assert.match(css, /\.derive-progress \{[\s\S]*?border: 0;/);
  assert.match(css, /\.btn\.primary\[data-derivation-state="running"\][\s\S]*?background: var\(--danger\)/);
  assert.doesNotMatch(css, /derive-progress-slide|animation: derive-progress/);
  assert.match(appSource, /button\.textContent = "Stop"/);
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
  assert.equal(appSource.match(/A derivation is already running\./g)?.length, 2);
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
  assert.match(appSource, />Direct word entry</);
  assert.match(appSource, />BIP39 word numbers</);
  assert.match(appSource, /id="seed-zero-index"/);
  assert.match(appSource, /0–2047 instead of the default 1–2048/);
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
  assert.match(template, />Number bases<\/button>/);
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
  assert.match(css, /\.number-base-calculation-list \{/);
  assert.match(app, /fields:\{[^}]*base4:"",base8:"",base32:"",base64:""/);
  assert.match(app, /function hodlBase64KeyboardMarkup\(\)\{return hodlKeyboardMarkup\(!0,"Base64 entropy","base64-keyboard"\)\}/);
  assert.match(app, /function hodlBindBase64Keyboard\(input\)/);
  assert.match(app, /coin flip \$\{Math\.min\(definition\.remainderBits,coinFlipsEntered\+1\)\} of \$\{definition\.remainderBits\}/);
  assert.match(app, /Heads \(0\) or Tails \(1\)/);
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
  assert.match(app, /class="card-undo-button seed-keyboard-delete" id="card-undo"[^>]*aria-label="Undo last card"[^>]*><svg viewBox="0 0 24 18"/);
  assert.match(appSource, /function hodlSetInputValueAtEnd\(input, value\)/);
  assert.match(appSource, /hodlSetInputValueAtEnd\(input, value\);\s*input\.dispatchEvent\(new Event\("input"\)\)/);
  assert.match(css, /\.card-controls-row \{[\s\S]*?grid-template-columns: repeat\(7, minmax\(0, 1fr\)\)/);
  assert.match(css, /@media \(min-width: 640px\) \{\s*\.card-controls-row \{ grid-template-columns: repeat\(13, minmax\(0, 1fr\)\); \}/);
});

test("Cards offers isolated hashed and direct word-selection methods", () => {
  assert.match(app, /name="card-method" value="hashed"/);
  assert.match(app, /name="card-method" value="direct"/);
  assert.match(app, />Direct word selection</);
  assert.match(appSource, /fields: \{[^}]*cards: "", directCards: ""/);
  assert.match(appSource, /direct \? "" : `<div class="card-suit-pad"/);
  assert.match(appSource, /hodlDirectCardRanks = \["A", "2", "3", "4", "5", "6", "7", "8"\]/);
  assert.match(appSource, /dealt-card dealt-card-rank-only/);
  assert.match(appSource, /Each four-character group selects one word; spaces separate the groups/);
  assert.match(appSource, /placeholder = direct \? "A284 37A2/);
  assert.match(appSource, /input\.onbeforeinput = direct \? \(event\) => hodlHandleGroupedSeparatorDelete/);
  assert.match(appSource, /else hodlHandleGroupedSeparatorDelete\(input, event\);/);
  assert.match(appSource, /<aside class="cards-reshuffle" id="cards-reshuffle" hidden><\/aside>\s*<div class="dealt-cards" id="dealt-cards"/);
  assert.match(appSource, /Shuffle \$\{hodlDirectCardSetLabel\(parsed\.expectedMax\)\} \(any suit\) before the \$\{parsed\.entries\.length \? "next" : "first"\} draw\./);
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
  assert.match(app, /<strong>WIF<\/strong>/);
  assert.match(app, /<strong>Private key hex<\/strong>/);
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
    assert.match(markup, /id="script-type-field">Script type\s*<select/);
    assert.match(markup, /<label class="field">Script type\s*<select id="msig-script-type"[^>]*>/);
    assert.match(markup, /<option value="p2wsh" selected(?:="selected")?>Native SegWit<\/option>/);
    assert.match(markup, /<option value="p2tr">Taproot<\/option>/);
    assert.doesNotMatch(markup, /<option value="p2wsh"[^>]*>[^<]*BIP48/);
    assert.doesNotMatch(markup, /name="msig-script"|Matches BIP48 script type|Bare P2SH/);
    assert.doesNotMatch(markup, />Address type</);
  }
});

test("key derivation separates script type from the hardened purpose index", () => {
  for (const markup of [template, appWhitespace]) {
    assert.match(markup, /id="script-type-field">Script type\s*<select id="script-type"><option value="bip44">Legacy<\/option><option value="bip49">Nested SegWit<\/option><option value="bip84" selected(?:="selected")?>Native SegWit<\/option><option value="bip86">Taproot<\/option><\/select>/);
    assert.match(markup, /id="script-type"[\s\S]*id="purpose"[\s\S]*id="network"[\s\S]*id="account"/);
    assert.match(markup, /id="purpose" type="text" inputmode="numeric" value="84'"/);
    assert.match(markup, /id="purpose-help">Purpose index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="account-help">Account index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
  }
  assert.match(appSource, /function hodlReadPurpose\(mark = true\)/);
  assert.match(appSource, /hodlSetSelectedScriptType\(target\.value, true\)/);
  assert.match(appSource, /let derivedDefinition = \{ \.\.\.definition, purpose: purposeIndex, purposeHardened: hardening\.purpose \}/);
  assert.match(appSource, /originPath = derivationPlan\?\.originPath \?\?/);
  assert.match(appSource, /fields: \{ pass: "", script: "bip84", derivationPath: "m\/84'\/0'\/0'\/0\/0", derivationAccountPath: "m\/84'\/0'\/0'", purpose: "84'", purposeHarden: true, coinType: "0'", coinTypeHarden: true, network: "mainnet"/);
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
    assert.match(markup, /option value="mixed" disabled data-custom-select-placeholder="true">Mixed · incompatible keys/);
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
  assert.match(app, /Co-signer purpose indexes do not match/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /if\(kind==="mixed"\)throw new Error\("Co-signer keys indicate different script types/);
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
  assert.match(appWhitespace, /items\.map\(item=>hodlPublicFieldHtml\(`Multisig co-signer \$\{item\.prefix\} · \$\{item\.label\}`,item\.value\)\)\.join\(""\)/);
  assert.match(app, /\$\{hodlSlip132WatchFields\(account,hodlWalletResult\)\}\s*\$\{hodlImportedCoreRecoveryExport\(hodlWalletResult,account\)\}\s*\$\{hodlRenderMultisigCosignerExport\(hodlWalletResult.multisigCosignerExports,account\.def\.id\)\}/);
  assert.doesNotMatch(`${app}\n${css}`, /account-multisig-exports/);
  assert.match(app, /Legacy P2SH requires the depth-1 BIP45 purpose key at m\/45h/);
  assert.match(app, /suffix=bip45\?`\/0\/\$\{branch\}\/\*`:`\/\$\{branch\}\/\*`/);
  assert.match(app, /Legacy BIP45 addresses use co-signer branch 0/);
  assert.match(app, /Legacy P2SH uses the selected BIP87 account paths/);
  assert.match(app, /function hodlMsigInnerDescriptor\(kind,m,inner,sorted\)/);
  assert.match(app, /function hodlMsigPolicyOp\(kind,sorted\)/);
  assert.match(app, /kind==="p2tr"\?sorted\?"sortedmulti_a":"multi_a":sorted\?"sortedmulti":"multi"/);
  assert.match(app, /hodlMsigAddr\(publicKeys,m,network,kind,sorted\)/);
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
    assert.match(markup, /<option value="sorted" selected(?:="selected")?>Sorted (?:·|\\xB7) sortedmulti<\/option>/);
    assert.match(markup, /<option value="listed">As listed (?:·|\\xB7) multi<\/option>/);
    assert.match(markup, /id="msig-key-order-status" hidden/);
  }
  assert.match(css, /\.msig-advanced summary/);
  assert.match(css, /\.msig-key-move-btn/);
  assert.match(app, /function hodlMsigKeysSorted\(\)/);
  assert.match(app, /function hodlBindMsigKeyReorder\(box\)/);
  assert.match(app, /function hodlMoveMsigKeyRow\(row,offset\)/);
  assert.match(app, /textContent="Move up"/);
  assert.match(app, /textContent="Move down"/);
  assert.match(app, /function hodlMsigScriptOrder\(keyTokens\)/);
  assert.match(app, /id="multisig-order-heading">Script key order/);
  assert.match(app, /keyOrder:"sorted"/);
  assert.match(app, /notes\.push\("This wallet uses "/);
});

test("multisig separates script type from purpose and keeps the Legacy BIP87 shortcut", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /id="msig-script-type"[\s\S]*id="msig-purpose"[\s\S]*id="msig-network"[\s\S]*id="msig-account"/);
    assert.match(markup, /id="msig-purpose" type="number" min="0" max="2147483647" step="1" inputmode="numeric" value="48"/);
    assert.match(markup, /id="msig-purpose-help">Purpose index (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="msig-account-help">Account index (?:·|\\xB7) Hardened (?:·|\\xB7) Derived from co-signer key origins/);
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
  assert.match(appSource, /addressFromScript\(p2wshScript\(ms\), network\)/);
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
    assert.match(markup, /<input id="msig-account" type="text" value="" placeholder="Derived from keys" disabled/);
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
    assert.match(markup, /<h2>Derive a multisig wallet<\/h2>/);
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
    assert.match(live, /<aside class="beta-warning no-print" id="beta-warning" role="alert">\s*<div class="beta-warning-text"><strong>Beta software<\/strong> EntropyLab is experimental and should only be used for testing and educational purposes\.<\/div>/);
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
      /<footer class="page-footer muted no-print"><div>Team Ooga Booga<\/div><div class="page-footer-emoji">(?:🪨|\\u\{1FAA8\}) (?:🔥|\\u\{1F525\}) (?:🎲|\\u\{1F3B2\}) (?:🍌|\\u\{1F34C\})<\/div><div>Since 964013 (?:·|\\x[Bb]7|\\u00[Bb]7) <span class="page-footer-build">v\{\{VERSION\}\} (?:·|\\x[Bb]7|\\u00[Bb]7) commit <code>\{\{COMMIT_SHORT\}\}<\/code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="\{\{COMMIT\}\}" width="20" height="20" alt="LifeHash of the build commit" hidden><\/span><\/div><\/footer>/,
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
      /<button type="button" class="beta-warning-dismiss" id="beta-warning-dismiss" aria-label="Dismiss the beta software warning">/,
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
      /<div class="online-warning-text"><strong>Online version<\/strong> Do not enter seed phrases/,
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
  assert.match(template, /<p class="disclaimer-title" id="beta-disclaimer-title">Beta software<\/p>/);
  assert.match(
    template,
    /<p class="disclaimer-text" id="beta-disclaimer-text">EntropyLab is experimental and should only be used for testing and educational purposes\. This tool is intended for offline use by advanced users only\. Any use online or with real funds can be dangerous\.<\/p>/,
  );
  assert.match(template, /<button class="btn primary" id="beta-disclaimer-accept" type="button">I understand<\/button>/);
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
  // 6px flex gap plus this margin, down from 12px, so the version closes up on
  // the wordmark as both shrink.
  assert.match(narrow, /\.site-version \{ font-size: 11px; margin-left: 2px; \}/);
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
    assert.match(markup, /class="theme-toggle header-button" id="theme-toggle" data-theme-mode="dark" aria-label="Theme: dark\. Switch to light"/);
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
  assert.match(appSource, /hodlInitSecretFieldAutoClear\(\);\s*hodlInitTheme\(\);/);
  assert.match(css, /:root\[data-theme="light"\] \{\s*color-scheme: light;/);
  assert.match(css, /@media print \{\s*:root, :root\[data-theme\] \{/);
  assert.match(css, /\.download-controls \.theme-toggle \{ flex: 0 0 40px; width: 40px; align-self: center; \}/);
});

test("the site header is fixed, carries the logo, and holds the version, download, and theme controls", () => {
  for (const markup of [template, app]) {
    // The header precedes the page wrapper, so the banners scroll beneath it.
    const header = markup.indexOf('<div class="site-header no-print">');
    const wrapper = markup.indexOf('<div class="wrap">');
    assert.ok(header >= 0, "the fixed site header is missing");
    assert.ok(header < wrapper, "the site header must come before the page wrapper");
    assert.match(markup, /<span class="site-logo" aria-hidden="true"><\/span>\s*<span class="site-title">EntropyLab<\/span>\s*<span class="site-version">/);
    for (const control of [/class="site-version-number">v\{\{VERSION\}\}</, /class="btn secondary download-html header-button"/, /class="btn secondary github-repo-link header-button"/, /id="theme-toggle"/]) {
      assert.match(markup.slice(header, wrapper), control, `the fixed header is missing ${control}`);
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
  assert.match(css, /\.site-version \{[^}]*flex: 0 0 auto; display: inline-flex; align-items: baseline; gap: 6px;/s);
  // The version echoes the kicker's accent and weight, but stays far below its
  // display tracking, which reads as spread-out in a row of controls.
  assert.match(css, /\.site-version \{[^}]*text-transform: uppercase; color: var\(--accent\); font-weight: 600;/s);
  const tracking = (rule) => Number(css.match(new RegExp(`${rule} \\{[^}]*letter-spacing: ([\\d.]+)em`, "s"))?.[1]);
  assert.ok(tracking("\\.site-version") < tracking("\\.kicker") / 2, "the header version kept the kicker's display tracking");
  // The uppercase stops at the version string, so its "v" prefix stays lower
  // case in the label the build stamps.
  assert.match(css, /\.site-version-number \{[^}]*text-transform: none;/);
  // online.js never fetches or rewrites the version label: the build-stamped
  // markup is the only source, and the app makes no runtime requests.
  assert.doesNotMatch(online, /fetch\s*\(|site-version|innerHTML/);
  // Content clears the fixed header on screen, and reclaims the space in print.
  assert.match(css, /\.wrap \{ max-width: 1000px; margin: 0 auto; padding: calc\(var\(--site-header-height\) \+ 20px\) 16px 0; \}/);
  assert.match(css, /@media print \{[\s\S]*?\.wrap \{ padding-top: 20px; \}/);
  assert.match(css, /html \{[^}]*scroll-padding-top: calc\(var\(--site-header-height\) \+ 12px\)/);
  // Every header control is one height, and the bar is sized to match it.
  assert.match(css, /\.header-button \{ min-height: 40px; font-size: 14px; \}/);
  assert.match(css, /--site-header-height: 52px;/);
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
    assert.equal((list.match(/<li>/g) || []).length, 4);
    assert.match(list, /<li>Save this air-gapped bitcoin calculator to a removable drive/);
    assert.match(list, /<li>Keep your private keys offline\.<\/li>/);
    // The prose it replaced is gone, not merely hidden.
    assert.doesNotMatch(markup, /A signing device is only required when you spend/);
  }
  // The list stands in for a paragraph, so it carries the space a paragraph
  // would have above it and leaves the card's padding to close it out.
  assert.match(css, /\.pitch-list \{ display: grid; gap: 7px; margin: var\(--space-component\) 0 0; padding-left: 20px; \}/);
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
  // Icon-only buttons match the theme toggle's 40px square.
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.download-controls \.btn:is\(\.download-html, \.github-repo-link\) \{ flex: 0 0 40px; width: 40px; padding: 0; justify-content: center; \}/);
  for (const markup of [template, app]) {
    // The version reads as plain text beside the logo; "v0.1.3" already says
    // what it is, so it never carries a control label.
    assert.doesNotMatch(markup, /version-picker|version-select|<span class="control-label">Version<\/span>/);
    // The glyph precedes the label at every width and stands alone once the
    // labels collapse, so it is never hidden.
    assert.match(markup, /<svg class="download-mark"[^>]*><path d="M12 3v12M7 11l5 5 5-5M5 21h14"\/><\/svg><span class="control-label">Download<\/span><\/a>/);
    assert.match(css, /\.download-mark \{ display: block; flex: 0 0 auto; \}/);
    assert.doesNotMatch(css, /@media \(max-width: 719px\) \{[\s\S]*?\.download-mark \{/);
    // One rule owns the icon-to-label gap for both buttons, so they cannot drift.
    assert.match(css, /\.download-controls > a \{ display: inline-flex; align-items: center; gap: 6px;/);
    assert.doesNotMatch(css, /\.download-controls \.github-repo-link \{ display: inline-flex/);
    // Centring the label's em box leaves its caps a pixel below the icon's
    // centre line, so the label carries an optical nudge back up.
    assert.match(css, /\.control-label \{ position: relative; top: -1px; \}/);
    assert.match(markup, /<span class="control-label">GitHub<\/span><\/a>/);
    // Each accessible name still contains its visible label (WCAG 2.5.3).
    assert.match(markup, /class="btn secondary download-html header-button"[^>]*aria-label="Download EntropyLab"/);
    // The "(Latest)" half of the version is the one thing narrow bars drop.
    assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.site-version-tag \{ display: none; \}/);
    assert.match(markup, /class="btn secondary github-repo-link header-button"[^>]*aria-label="View the EntropyLab GitHub repository in a new tab"/);
  }
});

test("PSBT amounts and fees are labeled as unverified claims", () => {
  assert.match(app, /BTC claimed/);
  assert.match(app, /Unverified fee \(PSBT witness UTXO claims\)/);
  assert.match(app, /Input amounts and any fee are unverified PSBT claims/);
  assert.doesNotMatch(app, /Fee \(from PSBT fields\)/);
});

test("seed-length selector offers all five BIP39 sizes", () => {
  for (const words of [12, 15, 18, 21, 24]) {
    assert.match(template, new RegExp(`data-seed-words="${words}"`), `${words} missing from src/index.html`);
    assert.match(app, new RegExp(`data-seed-words="${words}"`), `${words} missing from runtime markup in src/js/app.js`);
  }
});

test("D++ uses the published hexadecimal D16 transcript without a notation toggle", () => {
  assert.match(appSource, /let dplusFaces = \["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"\]/);
  assert.match(appSource, /D\+\+ rolls \(D8, D16, D16; then/);
  assert.doesNotMatch(appSource, /D\+\+ rolls \(D8 1\\u20138, D16 0\\u2013F/);
  assert.match(appSource, /D8 labeled 1\\u20138 and two hexadecimal D16 dice labeled 0\\u2013F/);
  assert.match(appSource, /100 selects abandon and 8FF selects zoo/);
  assert.doesNotMatch(appSource, /data-dplus-die|hodlDPlusNumberedD16|dplusNumberedD16|Decimal D16/);
  assert.doesNotMatch(css, /dplus-die-pad|dplus-key-decimal|dplus-key-face/);
});

test("dice rolls hide Pearson chi-squared fairness behind a text expand button", () => {
  assert.match(app, /id="dice-fairness-toggle"/);
  assert.match(app, /aria-controls="dice-fairness"/);
  assert.match(app, /class="dice-fairness-toggle"/);
  assert.match(app, /data-dice-fairness-glyph/);
  assert.match(app, / Die Distribution \/ Fairness Analysis<\/button>/);
  assert.match(appSource, /<div class="seed-word-copy-row">\$\{leading\}<span class="seed-phrase-copied"/);
  assert.match(css, /\.seed-word-copy-row \.dice-fairness-toggle \{ margin-right: auto; \}/);
  assert.match(app, /id="dice-fairness" class="dice-fairness" hidden role="status" aria-live="polite"/);
  assert.match(app, /function hodlSetDiceFairnessOpen\(open\)/);
  assert.match(app, /function hodlChiSquaredCdf\(/);
  assert.match(app, /function hodlDiceFairnessAssess\(rolls,\s*labels,\s*title\)/);
  assert.match(app, /function hodlRenderDiceFairness\(value,\s*method,\s*targetWords\s*=\s*hodlTargetWordCount\)/);
  assert.match(app, /hodlRenderDiceFairness\(input\.value,\s*hodlDiceMethod,\s*config\.words\)/);
  assert.match(app, /showDiceFairness:!1/);
  assert.match(app, /Looks pretty fair/);
  assert.match(app, /Looks biased/);
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

test("workspace tabs place BIP-85 between Keys and Multi Signature", () => {
  assert.match(appSource, /\["calc", "Keys", "Keys"\], \["bip85", "BIP-85", "BIP85"\], \["msig", "Multi Signature", "MultiSig"\], \["sp", "Silent Payments", "SP"\], \["psbt", "PSBT \/ Nonce", "PSBT"\], \["psbted", "PSBT Editor", "Editor"\]/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="bip85-card"/);
    assert.match(markup, /id="bip85-go"/);
    assert.match(markup, /Derive child/);
    assert.match(markup, /This does not invent entropy/);
  }
  assert.match(css, /#bip85-card\[hidden\]/);
});

test("PSBT Editor tab follows PSBT / Nonce and wires the rust-bitcoin editor", () => {
  assert.match(appSource, /\["psbt", "PSBT \/ Nonce", "PSBT"\], \["psbted", "PSBT Editor", "Editor"\]/);
  assert.match(appSource, /getElementById\("psbted-card"\)\.hidden = id !== "psbted"/);
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="psbted-card"/);
    assert.match(markup, /id="psbted-text"/);
    assert.match(markup, /id="psbted-load"/);
    assert.match(markup, /id="psbted-wipe"/);
    assert.match(markup, /id="psbted-network"/);
    assert.match(markup, /id="psbted-out"/);
    assert.match(markup, /id="psbted-error"/);
    assert.match(markup, /rust-bitcoin compiled to WebAssembly/);
    // The row must carry psbted-actions in both markups, or the flex stretch
    // pulls the Load/Clear buttons up to the network field's full height.
    assert.match(markup, /<div class="row psbt-actions psbted-actions">/);
  }
  assert.match(css, /\.psbted-actions \{ align-items: flex-end; \}/);
  assert.match(css, /\.psbted-actions \.btn \{ min-height: 0; padding: 6px 10px; \}/);
  assert.match(appSource, /import \{ initPsbtEditor \} from "\.\/psbt-editor\.js"/);
  assert.match(appSource, /initPsbtEditor\(\)/);
  assert.match(css, /#psbted-card\[hidden\]/);
});

test("BIP-85 entry point sits beside Derive Key and opens the BIP-85 tab", () => {
  for (const markup of [template, appSource]) {
    assert.match(markup, /id="go"[^>]*>Derive Key<\/button>[\s\S]*?id="bip85-open"[^>]*>Derive BIP-85 child<\/button>[\s\S]*?id="wipe"/);
  }
  assert.match(appSource, /getElementById\("bip85-open"\)/);
  assert.match(appSource, /open\.onclick = \(\) => \{\s*hodlShowWorkspace\("bip85"\)/);
  assert.match(appSource, /open\.onclick[\s\S]*?hodlPickBip85SessionKey\(hodlKeys\[hodlActiveKey\]\)/);
});

test("Silent Payments sits between Multi Signature and PSBT / Nonce", () => {
  const order = /Keys[\s\S]*Multi Signature[\s\S]*Silent Payments[\s\S]*PSBT \/ Nonce/;
  assert.match(template, order);
  assert.match(appSource, /\["calc", "Keys", "Keys"\], \["bip85", "BIP-85", "BIP85"\], \["msig", "Multi Signature", "MultiSig"\], \["sp", "Silent Payments", "SP"\], \["psbt", "PSBT \/ Nonce", "PSBT"\], \["psbted", "PSBT Editor", "Editor"\]/);
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

test("the workspace switcher keeps every tool on screen as a tab strip", () => {
  // The switcher is a nav holding one scrollable strip of tabs; it is neither
  // a segmented control nor a dropdown. Every tool is visible without asking.
  assert.match(template, /<nav class="workspace no-print" id="workspace">/);
  assert.match(appSource, /<nav class="workspace no-print" id="workspace"><\/nav>/);
  assert.doesNotMatch(template, /segmented-control" id="workspace"/);
  assert.match(template, /<div class="workspace-tabs" id="workspace-tabs" role="tablist" aria-label="Tool">/);
  // All five tools ship in the static markup, each with a full name and the
  // short form narrow screens show instead.
  for (const [full, short] of [["Keys", "Keys"], ["BIP-85", "BIP85"], ["Multi Signature", "MultiSig"], ["Silent Payments", "SP"], ["PSBT / Nonce", "PSBT"], ["PSBT Editor", "Editor"]]) {
    assert.ok(
      template.includes(`<span class="workspace-tab-full">${full}</span><span class="workspace-tab-short">${short}</span>`),
      `${full} is missing from the workspace strip`,
    );
    assert.match(appSource, new RegExp(`\\["[a-z0-9]+", "${full.replace("/", "\\/")}", "${short}"\\]`));
  }
  // One swaps for the other at the width the header drops its own labels.
  assert.match(css, /\.workspace-tab-short \{ display: none; \}/);
  assert.match(css, /@media \(max-width: 719px\) \{[\s\S]*?\.workspace-tab-full \{ display: none; \}\s*\.workspace-tab-short \{ display: inline; \}/);
  assert.match(appSource, /fullLabel\.textContent = label;\s*shortLabel\.textContent = short;/);
  // Hidden text leaves the accessibility tree, so the full name is stated on
  // the tab itself and assistive tech hears it at every width.
  assert.match(appSource, /button\.setAttribute\("aria-label", label\);/);
  for (const full of ["Keys", "BIP-85", "Multi Signature", "Silent Payments", "PSBT / Nonce"]) {
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
    for (const id of ["calc-card", "bip85-card", "msig-card", "sp-card", "psbt-card"]) {
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
  assert.match(appSource, /id="wallet-private-heading">Private recovery material/);
  assert.match(appSource, /These values can recreate or spend from the wallet\. Reveal them only while this file is running offline on an air-gapped computer\./);
  assert.match(appSource, /id="account-private-heading">Private account material/);
  assert.match(appSource, /id="account-watch-heading">Watch-only wallet data/);
  assert.match(appSource, /id="account-address-heading">Addresses/);
  assert.match(appSource, /Verify the first selected address on another trusted wallet or signing device before accepting bitcoin\./);
  assert.doesNotMatch(appSource, /id="account-receive-heading">Receive/);
  assert.match(appSource, /if \(state\) state\.reveal = hodlRevealPrivate;/);
  assert.match(appSource, /hodlBindWalletResultActions\(\);/);
});

test("every MS Station co-signer row can pick any session key, and key reuse offers a derivation path", () => {
  for (const markup of [template, appSource]) {
    assert.doesNotMatch(markup, /msig-station-key-source/);
    assert.doesNotMatch(markup, /id="msig-session-keys"/);
    assert.doesNotMatch(markup, /id="msig-reuse-session-keys"/);
    assert.doesNotMatch(markup, /id="msig-session-key-status"/);
  }
  assert.match(appSource, /function hodlSessionMsigKeys\(\) \{/);
  assert.match(appSource, /function hodlMatchingMsigExport\(result\) \{/);
  assert.match(appSource, /function hodlSyncMsigKeyAvatar\(row\) \{/);
  assert.match(appSource, /chips\.className = "msig-session-keys"/);
  assert.match(appSource, /button\.className = "msig-session-key"/);
  assert.match(appSource, /function hodlPickMsigSessionKey\(state, row\) \{/);
  assert.match(appSource, /button\.onclick = \(\) => hodlPickMsigSessionKey\(state, row\)/);
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
  assert.doesNotMatch(appSource, /hodlMsigKeyTarget|reuseSessionKeys/);
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
  assert.match(appSource, /function hodlFillStationKeyPicker\(id, selectedSource, onSelect\) \{/);
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, fingerprint\)/);
  assert.match(appSource, /function hodlPickBip85SessionKey\(state\) \{/);
  assert.match(appSource, /function hodlPickSpSessionKey\(state\) \{/);
  assert.match(appSource, /document\.getElementById\("bip85-key"\)\.value = rootXprv;/);
  assert.match(appSource, /document\.getElementById\("sp-key"\)\.value = state\.result\?\.mnemonic \|\| state\.result\?\.rootXprv \|\| "";/);
  assert.match(appSource, /document\.getElementById\("sp-pass"\)\.value = state\.result\?\.mnemonic \? state\.fields\?\.pass \|\| "" : "";/);
  assert.match(appSource, /document\.getElementById\("bip85-key"\)\.addEventListener\("input"/);
  assert.match(appSource, /document\.getElementById\("sp-key"\)\.addEventListener\("input", detachStationKey\)/);
  assert.match(css, /\.session-key-picker \{ display: flex; flex-wrap: wrap; gap: 8px; \}/);
  assert.match(css, /\.session-key-option\.active \{ border-color: var\(--accent\); \}/);
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
  assert.match(css, /#calc-card:not\(\[hidden\]\), #msig-card:not\(\[hidden\]\), #bip85-card:not\(\[hidden\]\), #sp-card:not\(\[hidden\]\) \{[^}]*border-radius: 0 0 20px 20px;/s);
  assert.match(css, /\.workspace-tab \{[^}]*border-radius: 10px 10px 0 0;/s);
  assert.match(appSource, /let lifehash = tab\.querySelector\("\.key-tab-lifehash"\);/);
  assert.doesNotMatch(appSource, /editor\.append\(hodlCreateKeyIcon\(state\.color\), input\)/);
});
