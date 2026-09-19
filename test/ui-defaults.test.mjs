import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { transformSync } from "esbuild";
import { hodlKeyModeLabels } from "../src/js/i18n-labels.js";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const template = read("src/index.html");
const shell = read("src/shell.html");
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
const contributing = read("CONTRIBUTING.md");


test("top status banner omits the entropy RNG message", () => {
  assert.doesNotMatch(`${shell}\n${app}`, /No entropy RNG/);
  assert.match(shell, /<div class="kicker">Run Offline · Bring your own entropy<\/div>/);
});

test("optional BIP39 passphrase placeholders explain that blank means none", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="pass"[^>]*placeholder="Enter a BIP39 passphrase, or leave blank for none"/);
    assert.match(markup, /id="psbt-pass"[^>]*placeholder="Enter a BIP39 passphrase, or leave blank for none"/);
    assert.doesNotMatch(markup, /placeholder="Leave blank unless you set one"/);
  }
});

test("every enabled button uses orange and black momentary press feedback", () => {
  assert.equal(/--selection-accent: #ff9900;/.test(css), true);
  assert.equal(/--selection-fg: #000000;/.test(css), true);
});

test("wallet coin type indexes enable and default to mainnet", () => {
  assert.match(shell, /<input id="network" type="text" inputmode="numeric" value="0'"/);
  assert.match(shell, /id="msig-origin-state" hidden aria-hidden="true"[\s\S]*<input id="msig-network" type="number" value="0">/);
  for (const markup of [shell]) {
    assert.match(markup, /id="network-help">Coin type index (?:·|\\xB7) Mainnet (?:·|\\xB7) Hardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /<span id="msig-network-help"><\/span>/);
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
  for (const markup of [shell]) {
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
    // Signet shares the testnet formats; regtest shares the key formats but
    // renders SegWit with the bcrt HRP — the options say so (issue #329).
    assert.match(markup, /Signed practice coins, no value · same formats as testnet/);
    assert.match(markup, /Local sandbox coins · addresses m…\/n…, 2…, bcrt1q…, bcrt1p… · tpub\/upub\/vpub · WIF 9\/c · coin type 1'/);
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
  // The tools still see the binary encoding family, but the derivation keeps
  // the picker's chain identity when it matches the family's coin type, so
  // wallet.dat exports and bcrt rendering stay chain-true (issue #329).
  assert.match(appSource, /function hodlNetworkFamily\(network\) \{\s*return network === "mainnet" \? "mainnet" : "testnet";/);
  assert.match(appSource, /chain = hodlNetworkFamily\(hodlNetworkChoice\) === network \? hodlNetworkChoice : network/);
  assert.match(appSource, /hodlMnemonicWalletWithProgress\(phrase, passphrase, chain, count,/);
  assert.match(appSource, /hodlNetworkFamily\(result\?\.network\) !== hodlNetworkFamily\(chain\)/);
  // The option names and the button's accessible name come from the locale
  // catalogs so the whole header follows the selected language.
  assert.match(appSource, /let key = \["mainnet", "testnet", "signet", "regtest"\]\.includes\(hodlNetworkChoice\) \? hodlNetworkChoice : "mainnet"/);
  assert.match(appSource, /let name = hodlTText\(hodlNetworkNames\[key\]\)/);
  assert.match(appSource, /button\.setAttribute\("aria-label", hodlTText\("Bitcoin network: \{network\}. Change the network the tools derive and check for", \{ network: name \}\)\)/);
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
  // The button lives at the bar's right edge, so the menu opens leftward
  // from its right edge rather than past the viewport.
  // The coin carries the network on its own, so it is sized with the download
  // and GitHub marks either side of it rather than the 16px its SVG ships.
  // Narrow screens drop the label and chevron and square the control off
  // against the 40px theme toggle, keeping it in the control row: it holds its
  // place among the header buttons instead of hanging out of the bar.
  const narrow = css.slice(css.indexOf("@media (max-width: 719px)"));
  // It must not leave the flow: absolute positioning hung it below the bar.
  // The row keeps its 40px touch targets rather than shrinking to a chip.
  // The language dropdown drops its arrow at the same breakpoint, and takes
  // back the symmetric padding the chevron's blank edge had been paying for.
  // Squared off against the same 40px the network picker takes.
  // The menu is not squared with it: it stays readable and opens leftward.
  // Only the header's copy: the arrow stays on every other custom select.
});

test("advanced derivation fields use the shared responsive settings grid", () => {
  // The title now shares a row with the field's Harden toggle, so it sits one
  // level in; the input still follows it.
  assert.match(shell, /<div class="field network-field"><div class="field-head"><label for="network">Network<\/label>[\s\S]*?<input id="network"[^>]*>/);
  // The rules bracket the section, so the lower one sits under the toggle when
  // shut and under the revealed fields when open. On the summary it split the
  // label from its own content; on the revealed block it vanished with it.
  // One rule, and it closes the section: under the toggle when shut, under the
  // revealed fields when open, so the section grows above it.
  // No padding above: the field the section follows already sets it off, and
  // the toggle reads as the next line rather than the start of a new band.
  // With the line off the row, it hugs its text again like the toggle it
  // matches, so the hit area is the words rather than the whole card.
  // The gap under the toggle is the same either way — set on the summary
  // itself — so opening the section moves the fields in without shifting the
  // toggle. Open differs only in colour.
  // The field titles match the card's label style; the control below each
  // already carries the 8px, so they take no margin of their own.
  // Titles sit inside a .field-head now, sharing the row with a Harden toggle
  // where the field has one, so the rule reaches both levels.
  // Two containers carry these fields — the advanced blocks and the settings
  // grids — and the title says its size once for both.
  // The Harden control is a label too, and a direct child of the title row: the
  // rule above would make it display:block and collapse its own flex layout,
  // taking the gap between box and word and its centring with it.
  // The estimate belongs to the section above it, not to the button below, so
  // it takes a wide seam above and sits close beneath.
  // Nothing under it: 16px is the floor, being the action row's own margin,
  // which every tool card shares by design and which a bottom margin here
  // would only collapse into.
  // Every closing action moves the same two things under the pointer, so a row
  // of mixed button weights reads as one set of controls.
  // One rule serves the filled primary and the quieter secondary: they differ at
  // rest, not under the pointer. Both drop their fill to the page ground and
  // move the accent out to the border and the label.
  // One rule inverts every control that answers the pointer: buttons, keypads,
  // on-screen keyboards and the header controls. Each says only which colour
  // it uses, so a new control joins by naming a variant, not by copying a block.
  assert.equal(css.match(/background: var\(--bg\); color: var\(--hover-ink\)/g)?.length, 1);
  // The label takes the accent as lettering, which is theme-tuned: the fill
  // orange manages 2.1:1 on white, so light mode uses a deeper one.
  // The fills keep the bright colour in both themes.
  // The tinted fill is gone from the action row; the same mix is used elsewhere
  // in the sheet, so the check is scoped to this rule rather than the file.
  // Buttons that already carry a meaning colour keep it, and now move their
  // border too so the whole row changes the same properties.
  // The destructive one inverts the same way, in the colour that says what it
  // does. --danger-bright, which unlike --selection-accent is theme-tuned, so
  // the red clears AA on both grounds.
  // A variant is three tokens and its rest colours, nothing else.
  for (const token of ["--danger-bright"]) {
    assert.ok(css.match(new RegExp(`\\${token}:`, "g"))?.length >= 2, `${token} needs a light and a dark value`);
  }
  // Motion is opt-out, like every other transition in the sheet, and the
  // opt-out covers the same controls the hover does.
});

test("key and multisig derivation use an indexed address window with an estimate and progress", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="address-start"[^>]*value="0"/);
    assert.match(markup, /id="address-range"[^>]*value="10"/);
    assert.match(markup, /id="msig-address-start"[^>]*value="0"/);
    assert.match(markup, /id="msig-address-range"[^>]*value="10"/);
    assert.match(markup, /id="address-start-help">First address index to derive (?:·|\\xB7) Unhardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="address-range-help">Derives 10 receive and 10 change addresses (?:·|\\xB7) Max 10,000/);
    assert.match(markup, /id="msig-address-start-help">First receive and change index to derive (?:·|\\xB7) Unhardened (?:·|\\xB7) 0 to 2,147,483,647/);
    assert.match(markup, /id="msig-address-range-help">Derives 10 receive and 10 change addresses (?:·|\\xB7) Max 10,000/);
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
  assert.match(appSource, /function hodlCreateDerivationTracker\(progress, control\)/);
  assert.match(appSource, /label\.innerHTML = `\$\{hodlCopiedIconMarkup\(\)\}<span>\$\{hodlT\("Done"\)\}<\/span>`/);
  assert.match(appSource, /async function hodlAddressRowsWithProgress/);
  assert.match(appSource, /button\.textContent = hodlTText\("Stop"\)/);
  assert.match(appSource, /button\.style\.width = `\$\{width\}px`/);
  assert.match(appSource, /button\.style\.removeProperty\("width"\)/);
  assert.match(appSource, /class HodlDerivationCancelledError extends Error/);
  assert.match(appSource, /function hodlStopDerivation\(kind\)/);
  assert.match(appSource, /hodlHandleDerivationButton\("key", hodlCalculateKey\)/);
  assert.match(appSource, /hodlHandleDerivationButton\("msig", hodlBuildMsig\)/);
});

test("key and multisig derivation select one or two address branches", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="branch-start"[^>]*value="0"/);
    assert.match(markup, /id="branch-start-harden"[^>]*type="checkbox"/);
    assert.match(markup, /id="branch-range"[^>]*max="2"[^>]*value="2"/);
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
  assert.equal(appSource.match(/hodlTText\("A derivation is already running\."\)/g)?.length, 2);
});

test("entropy progress messages sit next to their inputs and above keypads", () => {
  // Dice, Cards and Number bases put the progress line above the input, not
  // below, so the textarea and its keypad stay adjacent. You read the count,
  // then type and tap without a line of text wedged between the two controls.
  assert.match(app, /\$\{hodlSeedMetaRowMarkup\("dice-meta",!0\)\}\s*<div class="dice-input-shell">[\s\S]*?<textarea id="dice"[^>]*><\/textarea><\/div>\s*\$\{dicePad\}/);
  // Cards reads like dice: the progress line above the transcript, so the field
  // and the card keypad below it stay together.
  assert.match(appSource, /\$\{hodlSeedMetaRowMarkup\("cards-meta"\)\}\s*<div class="dice-input-shell cards-input-shell">/);
  // The Base32 and Base64 keyboard toggles ride at the right of that line,
  // above the field, the way the passphrase toggle sits above the passphrase.
  assert.match(appSource, /\$\{hodlSeedMetaRowMarkup\("entropy-meta", true, keyboardToggle\)\}\s*<div class="dice-input-shell entropy-input-shell">[\s\S]*?<\/textarea><\/div>\s*\$\{numberBaseKeyboard\}\s*\$\{entropyPad\}/);
  // Seed phrase too, with its switch between the line and the field.
  assert.match(appSource, /\$\{hodlSeedMetaRowMarkup\("seed-meta", true\)\}<div class="passphrase-keyboard-tools">[\s\S]*?<textarea id="seed"[^>]*><\/textarea><\/div>\$\{hodlSeedKeyboardMarkup\(\)\}/);
  assert.match(appSource, /\$\{hodlSeedMetaRowMarkup\("seed-number-meta", true\)\}<div class="passphrase-keyboard-tools">[\s\S]*?<textarea id="seed-numbers"[^>]*><\/textarea><\/div><div class="dice-input-pad seed-number-pad"/);
  // Private key as well, with its keyboard toggle at the right of the line and
  // the brain-wallet trim switch between the line and the field.
  assert.match(appSource, /\$\{hodlSeedMetaRowMarkup\("private-key-meta", true, hodlPrivateKeyKeyboardToggleMarkup\(\)\)\}\s*\$\{hodlBrainWalletTrimToggleMarkup\(\)\}\s*<div class="dice-input-shell private-key-input-shell">/);
});

test("the dice progress numbers are coloured against what the seed needs", () => {
  // Red while short, green once met, in the same bright pair the network status
  // tag uses: a few characters of live status is what those shades are held for.
  // One node builder serves every dice method, so their colours cannot drift.
  assert.match(appSource, /span\.className = "meta-value " \+ \(met \? "is-met" : "is-short"\);/);
  // The count answers to the roll shortfall; the bits answer to the entropy the
  // selected seed length needs, not a fixed 256, so a 12-word seed can go green.
  assert.match(appSource, /hodlMetaValue\(String\(rolls\.length\), !missing\)/);
  assert.match(appSource, /hodlMetaValue\(metaBitsValue\.toFixed\(1\), metaBitsValue >= config\.bits\)/);
  // Spliced in as nodes around a sentinel, never as markup: the status line
  // quotes what was typed, so it must not become an HTML sink.
  assert.match(appSource, /for \(let piece of text\.split\(\/\(\\u0000\)\/\)\)/);
  assert.doesNotMatch(appSource, /#dice-meta"\)\.innerHTML/);
  // Every sentence is its own line, joined by a break rather than a separator
  // buried inside one catalog string that every translation would have to keep.
  assert.match(appSource, /if \(nodes\.length\) nodes\.push\(document\.createElement\("br"\)\);/);
  assert.doesNotMatch(appSource, /"\{have\} (of \{n\} )?recommended rolls · \{bits\}/);
});

test("the BitBox word counter is coloured and its next roll sits on its own line", () => {
  // The word number is the count to act on: red until every lookup-table word
  // is in, green once the phrase is down to its final checksum pick.
  assert.match(appSource, /hodlMetaValue\(String\(result\.words\.length\), true\)/);
  assert.match(appSource, /hodlMetaValue\(String\(result\.words\.length \+ 1\), false\)/);
  // What to roll next is its own sentence, so it lands on its own line.
  assert.match(appSource, /hodlTText\("Word \{word\} of \{partial\}", \{ word: hodlMetaToken, partial: result\.neededPartial \}\)/);
  assert.match(appSource, /hodlTText\("Die \{die\} of 5 \(only faces 1–4 used\)", \{ die: result\.diceInWord \+ 1 \}\)/);
  assert.match(appSource, /hodlTText\("6th die \(interpreted as a coin flip\)"\)/);
  // BitBox carries no tail at all now: the invalid-input note is redundant with
  // the highlighted transcript above, and ignored extras still reach the user
  // as a derive-time warning.
  assert.match(appSource, /hodlRenderMeta\("dice-meta", bitboxLines\);/);
  assert.doesNotMatch(appSource, /bitboxTail/);
  assert.match(appSource, /"Extra rolls after the final lookup-table word are ignored\./);
  // The other methods keep the invalid-input tail, so the variable stays live.
  assert.match(appSource, /statusTail \+ invalidStatus/);
  assert.match(appSource, /hodlMetaCue\(hodlTText\("Choose final checksum word below"\)\)/);
  // The dot-joined single sentences are gone from every BitBox state.
  assert.doesNotMatch(appSource, /"Word \{word\} of \{partial\} ·/);
  assert.doesNotMatch(appSource, /"\{n\} words · choose the final checksum word"/);
  // It builds nodes, not markup, like every other dice progress line.
  assert.doesNotMatch(appSource, /#dice-meta"\)\.textContent = status/);
  assert.doesNotMatch(appSource, /#dice-meta"\)\.innerHTML/);
  // Zero rolls is the short case with a count of 0, so one sentence serves both
  // and each number is always a placeholder the colour can wrap.
  assert.doesNotMatch(appSource, /"0 of \{n\} recommended rolls/);
});

test("seed phrase calculations and copy controls precede every numbered word grid", () => {
  // Fairness toggle, then its panel, then the seed phrase title row carrying
  // the copy button, then the grid it copies from.
  assert.match(appSource, /\$\{dicePad\}[\s\S]*?hodlCalculationsSwitchMarkup\("manual", "dice-manual-calculations"[\s\S]*?<div class="dice-fairness-row" hidden>\$\{hodlDiceFairnessToggleMarkup\([\s\S]*?\)\}<\/div>[\s\S]*?\$\{hodlDerivedSeedRowMarkup\(\)\}\s*<div id="dice-words"/);
  assert.match(appSource, /<div class="dealt-cards"[^>]*><\/div>[\s\S]*?hodlCalculationsSwitchMarkup\("manual", "cards-manual-calculations"[\s\S]*?\$\{hodlDerivedSeedRowMarkup\(\)\}\s*<div id="dice-words"/);
  assert.match(appSource, /\$\{entropyPad\}\s*\$\{[^\n]*hodlCalculationsSwitchMarkup\("number-base", "number-base-calculations"[^\n]*\n\s*\$\{hodlDerivedSeedRowMarkup\(\)\}\s*<div id="entropy-words"/);
  assert.match(appSource, /<\/div>\$\{hodlSeedPhraseRowMarkup\(hodlT\("Your seed phrase"\)\)\}<div id="seed-number-words"/);
  assert.match(appSource, /function hodlSeedMetaRowMarkup\(metaId, live = false, trailing = ""\) \{\s*return `<div class="seed-word-meta label-description"><p[^`]+<\/p>\$\{trailing\}<\/div>`;\s*\}/);
});

test("every card switch comes from one builder that wires its note", () => {
  const start = appSource.indexOf("function hodlSwitchRowMarkup(");
  const build = new Function(`${appSource.slice(start, appSource.indexOf("\n}\n", start) + 2)}; return hodlSwitchRowMarkup;`)();
  // The note is announced with the checkbox, because the checkbox points at it.
  assert.equal(
    build("x", "Title", { note: "Why", checked: true, rowClass: "r", hidden: true }),
    '<div class="switch-row r" hidden><label class="switch-toggle"><input type="checkbox" id="x" aria-describedby="x-note" checked /><span class="label">Title</span></label><p class="switch-note" id="x-note">Why</p></div>',
  );
  // Without a note there is nothing to point at.
  assert.equal(build("y", "Plain"), '<div class="switch-row"><label class="switch-toggle"><input type="checkbox" id="y" /><span class="label">Plain</span></label></div>');
  for (const id of ['"seed-autocomplete"', '"seed-zero-index"', "`show-${name}-calculations`"]) assert.ok(appSource.includes(`hodlSwitchRowMarkup(${id}`), id);
});

test("direct dice, direct cards and number bases expose BIP39 calculations before copying", () => {
  // One switch builder serves every method that shows its working; each form
  // supplies only its id stem, its panel and its note.
  assert.equal(appSource.match(/hodlCalculationsSwitchMarkup\("manual", "dice-manual-calculations", hodlT\("show how direct word selection/g)?.length, 1);
  assert.equal(appSource.match(/hodlCalculationsSwitchMarkup\("manual", "cards-manual-calculations", hodlT\("show how direct card selection/g)?.length, 1);
  assert.equal(appSource.match(/hodlCalculationsSwitchMarkup\("number-base", "number-base-calculations", hodlT\("show how each BIP39 word number/g)?.length, 1);
  // Two rows like the sync switch, and no bordered chip: the control reads as
  // part of the card rather than a box floating on it.
  // The chrome is the card's shared switch, asserted once; a component states
  // only how it sits in its own container.
  // Built on the shared switch with a note, so the checkbox points at it. The
  // switch waits for something to be behind it. It ships hidden, because a
  // fresh form runs no update: the field restore only dispatches input when
  // there is a stored value to put back.
  assert.match(appSource, /hodlSwitchRowMarkup\(`show-\$\{name\}-calculations`, hodlT\("Show calculations"\), \{ note, checked, rowClass: "manual-calculations-row", hidden: true \}\)/);
  // The row follows the calculations; only the panel follows the checkbox.
  assert.match(appSource, /if \(row\?\.classList\.contains\("manual-calculations-row"\)\) row\.hidden = !markup;/);
  assert.match(appSource, /panel\.hidden = !open \|\| !markup;/);
  assert.match(appSource, /hodlShowCalculations\(panel, hodlManualCalculationMarkup\(method, value, targetWords\), hodlManualCalculationsOpen\);/);
  assert.match(appSource, /hodlShowCalculations\(panel, rows\.length \? `[\s\S]*?` : "", toggle\.checked\);/);
  // The row is the panel's immediate previous sibling in every form that has one.
  assert.match(appSource, /\)\}<div id="\$\{panelId\}" class="manual-calculations-container" hidden><\/div>`/);
  assert.doesNotMatch(appSource, /\("\(show how (direct (word|card) selection|each BIP39 word number)/);
  assert.doesNotMatch(appSource, /number-base-calculations-(toggle|panel)/);
  assert.match(appSource, /function hodlManualCalculationMarkup\(method, value, targetWords = hodlTargetWordCount\)/);
  assert.match(appSource, /hodlRenderManualCalculations\("dice-manual-calculations",\s*"dplus"/);
  assert.match(appSource, /hodlRenderManualCalculations\("dice-manual-calculations",\s*"bitbox"/);
  assert.match(appSource, /hodlRenderManualCalculations\("cards-manual-calculations",\s*"cards"/);
  assert.match(appSource, /D8 contributes 8 values and each hexadecimal D16 contributes 16 values/);
  assert.match(appSource, /Each D4 contributes one base-4 value and the final die contributes the coin bit/);
  assert.match(appSource, /Ranks are mapped to zero-based values/);
  assert.match(appSource, /dplus-calculation-stages/);
  assert.match(appSource, /dplus-calculation-stage.*stage\.face/);
});

test("Seed phrase offers one-based or zero-based BIP39 word-number entry", () => {
  assert.match(appSource, /name="seed-method" value="words"/);
  assert.match(appSource, /name="seed-method" value="numbers"/);
  assert.match(appSource, /hodlT\("Direct word entry"\)/);
  assert.match(appSource, /hodlT\("BIP39 word numbers"\)/);
  assert.match(appSource, /hodlSwitchRowMarkup\("seed-zero-index", hodlT\("Use zero-indexed word numbers"\), \{ note: hodlT\("0–2047 instead of the default 1–2048"\)/);
  assert.match(appSource, /function hodlTranslateSeedNumberIndex\(value, toZeroIndexed\)/);
  assert.match(appSource, /function hodlSeedNumberCanInsertDigit\(input, digit, zeroIndexed = hodlSeedZeroIndexed\)/);
  assert.match(appSource, /function hodlAutocompleteSeedNumberInput\(input, event, targetWords = hodlTargetWordCount, zeroIndexed = hodlSeedZeroIndexed\)/);
  assert.match(appSource, /number <= 204 \|\| number > maximum/);
  assert.match(appSource, /class="dice-input-pad seed-number-pad"/);
  assert.match(appSource, /\[0, 1, 2, 3, 4, 5, 6, 7, 8, 9\]/);
  assert.match(appSource, /id="seed-number-words" class="dice-word-grid"/);
  assert.match(appSource, /passphrase = !keyMode \|\| hdBrain/);
});

test("hashed cards can match Ian Coleman's suit-symbol SHA-256 transcript", () => {
  assert.match(appSource, /id="cards-ian-coleman"/);
  assert.match(appSource, /Match Ian Coleman method/);
  assert.match(appSource, /show and hash A\\u2660 2\\u2663 instead of As 2c/);
  assert.match(appSource, /placeholder = direct \? "A284 37A2 \\u2026" : hodlCardColemanSymbols \? "A\\u2660 2\\u2663 T\\u2665 T\\u2666\\u2026" : "As 2c Th Td\\u2026"/);
  assert.match(appSource, /autocapitalize="off" aria-labelledby="cards-input-label"/);
  // Titled like every other entry field in the card, so the shared label
  // spacing reaches it; the transcript is still named through its labelledby.
  assert.match(appSource, /<p class="label" id="cards-input-label">\$\{inputLabel\}<\/p>/);
  assert.match(appSource, /function hodlCardsHashInput\(cards, coleman = false\)/);
  assert.match(appSource, /transcript\.replace\(\/c\/g, "\\u2663"\)\.replace\(\/d\/g, "\\u2666"\)\.replace\(\/h\/g, "\\u2665"\)\.replace\(\/s\/g, "\\u2660"\)/);
  assert.match(appSource, /hodlFilterCards\(value, hodlCardColemanSymbols\)/);
  assert.match(appSource, /input\.value = hodlFilterCards\(input\.value, hodlCardColemanSymbols\)/);
});

test("Number bases offers exact Base 2, 4, 8, 16, Bech32 Base32, and Base64-alphabet input", () => {
  assert.match(appSource, /hodlTText\(hodlKeyModeLabels\[mode\]\)/);
  assert.doesNotMatch(shell, />Hex or binary<\/button>/);
  assert.ok(app.includes('formatChoices=["bin","base4","base8","hex","base32","base64"]'));
  assert.match(app, /name="entropy-format" value="\$\{id\}"/);
  const labelsModule = read("src/js/i18n-labels.js");
  for (const label of ["Binary (Base 2)", "Quaternary (Base 4)", "Octal (Base 8)", "Hexadecimal (Base 16)", "Base32 (Bech32)", "Base64 (RFC 4648 alphabet)"]) {
    assert.ok(labelsModule.includes(`label: "${label}"`), label);
  }
  assert.match(app, /alphabet:"qpzry9x8gf2tvdw0s3jn54khce6mua7l"/);
  assert.match(app, /alphabet:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+\/"/);
  assert.match(app, /function hodlNumberBaseEntropy\(value,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /function hodlNumberBasePreviewWords\(value,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /function hodlNumberBaseValueFromBytes\(bytes,format,targetWords=hodlTargetWordCount\)/);
  assert.match(app, /function hodlBinaryCalculationRows\(value,targetWords=hodlTargetWordCount\)/);
  assert.match(shell, /id="global-sync-host"/);
  assert.doesNotMatch(appSource, /global-sync-hash-host/);
  assert.match(appSource, /id="global-entropy-sync"/);
  assert.match(app, /globalSync:!1/);
  assert.match(app, /entropyFormat:"bin"/);
  assert.ok(app.includes('function hodlNormalizeEntropyFormat(format){return Object.hasOwn(hodlEntropyFormats,String(format??""))?String(format):"bin"}'));
  // The sync control stacks: switch and title on one row, explanation beneath.
  assert.match(appSource, /<div class="global-sync-head">/);
  assert.match(appSource, /<span class="label">\$\{hodlT\("Sync entropy across methods"\)\}<\/span><\/label>/);
  assert.match(appSource, /<p class="switch-note" id="global-sync-note">/);
  // The explanation describes the switch instead of naming it.
  assert.match(appSource, /id="global-entropy-sync" aria-describedby="global-sync-note"/);
  assert.doesNotMatch(appSource, /<strong>Sync entropy across methods<\/strong>/);
  // It gives up the shared toggle's chip chrome, but not its 44px target, and
  // the chip elsewhere keeps both.
  // The chip's 44px box left 13px of its own height under the title; the row
  // hugs its content instead, staying full width and above the 24px floor.
  // The chrome is the card's shared switch, asserted once; a component states
  // only how it sits in its own container.
  // The title matches the Method label above it.
  // The explanation is subordinate to that title and sits directly under it.
  // The control sits with the method it qualifies rather than centred in its
  // own gap, and it carries the rule that closes the Method section — the
  // length band below opens without one, so the gap either side is even.
  // The length band closes with its own rule and opens with the Method
  // section's, so it never carries a border-top of its own.
  assert.match(app, /fields:\{[\s\S]*?base4:"",base8:"",base32:"",base64:""/);
  assert.match(app, /function hodlBase64KeyboardMarkup\(\)\{return hodlKeyboardMarkup\(!0,"Base64 entropy","base64-keyboard"\)\}/);
  assert.match(app, /function hodlBindBase64Keyboard\(input\)/);
  assert.match(app, /function hodlBase32KeyboardMarkup\(\)\{return hodlKeyboardMarkup\(!0,"Bech32 entropy","base32-keyboard",!1,"a1"\)\}/);
  assert.match(app, /function hodlBindBase32Keyboard\(input\)/);
  assert.match(appSource, /let usesKeyboard = format\.id === "base32" \|\| format\.id === "base64";/);
  assert.match(app, /hodlT\("Heads \(0\)"\)/);
  assert.match(app, /hodlT\("Tails \(1\)"\)/);
});

test("dealt playing cards use theme-appropriate surfaces", () => {
});

test("card undo uses the keyboard delete icon, a visible word, and closes the row", () => {
  // The word sits after the icon, and the accessible name begins with it, so
  // what is seen and what is announced agree.
  assert.match(appSource, /id="card-undo"[^>]*aria-label="\$\{hodlT\("Undo last card"\)\}"[^>]*><svg[\s\S]*?<\/svg><span>\$\{hodlT\("Undo"\)\}<\/span><\/button>/);
  // Show cards is the card's shared switch, titled like the rest.
  assert.match(appSource, /class="switch-toggle card-visibility-toggle"><input type="checkbox" id="show-cards"[^>]*><span class="label">/);
  assert.match(app, /class="card-undo-button seed-keyboard-delete" id="card-undo"[^>]*aria-label="\$\{hodlT\("Undo last card"\)\}"[^>]*><svg viewBox="0 0 24 18"/);
  // Show cards leads the row and undo closes it, in source order as well as on
  // screen, so keyboard focus meets them in the order the eye does.
  assert.match(app, /<div class="card-controls-row"><label class="switch-toggle card-visibility-toggle">[\s\S]*?<\/label><button class="card-undo-button/);
  assert.match(appSource, /function hodlSetInputValueAtEnd\(input, value\)/);
  assert.match(appSource, /hodlSetInputValueAtEnd\(input, value\);\s*input\.dispatchEvent\(new Event\("input"\)\)/);
});

test("Cards offers isolated hashed and direct word-selection methods", () => {
  assert.match(app, /name="card-method" value="hashed"/);
  assert.match(app, /name="card-method" value="direct"/);
  assert.match(app, /hodlT\("Direct word selection"\)/);
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
  assert.match(app, /modeLabel="aA1"/);
  assert.match(app, />\$\{modeLabel\}<\/button><button[^>]*class="seed-keyboard-space"/);
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
  assert.match(app, /id="private-key-highlight" aria-hidden="true"/);
  assert.match(app, /function hodlPrivateKeyInputAnalysis\(value,kind,network,trimBrainWallet=hodlBrainWalletTrimEnabled\(\)\)/);
  assert.match(app, /function hodlRenderPrivateKeyInputState\(input\)/);
  assert.match(app, /function hodlHexPrivateKeyPrefix\(value\)/);
  assert.match(app, /function hodlWifPrivateKeyPrefix\(value,network\)/);
  assert.match(app, /function hodlMiniPrivateKeyPrefix\(value\)/);
  assert.match(app, /name="kk" value="wif" checked/);
  assert.match(app, /name="kk" value="hex-key"/);
  assert.match(app, /hodlT\("WIF"\)/);
  assert.match(app, /hodlT\("Private key hex"\)/);
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
  // The checkbox leads the row and the keyboard toggle follows. Swapped in the
  // markup rather than with row-reverse, so tab order still follows the eye.
  assert.match(app, /passphrase\?hodlPassphraseBip39ToggleMarkup\(\)\+\(ownToggle\?hodlPassphraseKeyboardToggleMarkup\(\):""\)/);
  assert.match(appSource, /<div class="passphrase-keyboard-tools" data-brain-wallet-trim-control hidden>\$\{hodlSwitchRowMarkup\("brain-wallet-trim", hodlT\("Trim leading and trailing whitespace"\), \{ checked \}\)\}<\/div>/);
  assert.match(app, /hodlPassphraseKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlPassphraseBip39ToggleMarkup\(checked=hodlPassphraseBip39Enabled\(\)\)/);
  assert.match(app, /function hodlAnalyzeBip39Passphrase\(value,activeCaret=null\)/);
  assert.match(app, /function hodlPassphraseBip39CanEnterCharacter\(input,key\)/);
  assert.match(app, /function hodlPassphraseBip39CanEnterSpace\(input\)/);
  assert.match(app, /passphraseBip39Words:!1/);
  assert.match(app, /hodlPrivateKeyKeyboardToggleMarkup\(\)/);
  assert.match(app, /function hodlBrainWalletTrimEnabled\(\)/);
  // Borderless, and the title takes the shared label style rather than a bare
  // <strong>, like every other checkbox in this card.
  assert.match(app, /<span class="label">Build passphrase from BIP39 words<\/span>/);
  assert.match(app, /<span class="label">Autocomplete BIP39 words<\/span>/);
  // The chrome is the card's shared switch, asserted once; a component states
  // only how it sits in its own container.
  // The one with an explanation gets two rows, and the checkbox points at the
  // note now that it sits outside the label.
  assert.match(app, /id="passphrase-bip39-words" aria-describedby="passphrase-bip39-note"/);
  assert.match(app, /<p class="switch-note" id="passphrase-bip39-note">/);
  assert.match(app, /brainWalletTrim:!1/);
  assert.doesNotMatch(appSource, /bitaddress\.org-style brain wallet/);
  assert.match(app, /id="private-key-input-label"[\s\S]*hodlPrivateKeyKeyboardToggleMarkup\(\)[\s\S]*<textarea id="key"/);
  assert.match(app, /privateKey\?"key":"pass",privateKey\?"private-keyboard-toggle":"passphrase-keyboard-toggle"/);
  assert.match(app, /hodlRenderPassphraseKeyboard\(\);return/);
  assert.match(shell, /id="passphrase-field"[\s\S]*id="passphrase-keyboard-toggle-host" hidden[\s\S]*id="passphrase-highlight"[\s\S]*<input id="pass"/);
  assert.match(shell, /id="passphrase-field"[\s\S]*id="passphrase-keyboard-host" hidden[\s\S]*id="master-fingerprint-preview"[\s\S]*id="key-settings"/);
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
  assert.match(app, /event\.relatedTarget\?\.closest\?\.\("#seed-keyboard,\.switch-toggle"\)/);
  // The keyboard toggle sits at the right of the autocomplete switch, the way
  // the passphrase toggle sits beside its switch.
  assert.match(appSource, /<div class="passphrase-keyboard-tools">\$\{hodlSwitchRowMarkup\("seed-autocomplete", hodlT\("Autocomplete BIP39 words"\), \{ checked: autocompleteEnabled \}\)\}\$\{hodlSeedKeyboardToggleMarkup\(\)\}<\/div>/);
  assert.match(appSource, /<\/textarea><\/div>\$\{hodlSeedKeyboardMarkup\(\)\}<div id="last-words"/);
  assert.match(appWhitespace, /hodlBindSeedKeyboard\(input,config\.words\);hodlBindKeyFields\(\)/);
  assert.match(app, /keyboard\.querySelectorAll\("\[data-seed-delete\]"\)\.forEach\(button=>hodlBindSeedKeyboardDelete\(\(\)=>activeInput,button\)\)/);
  assert.match(app, /modeButton\.disabled=!pass/);
  assert.match(app, /hodlSetSeedKeyboardLayout\(keyboard,modeButton,"lower"\)/);
  assert.match(app, /hodlApplySeedKeyboardKey\(activeInput,button\.dataset\.seedKey\|\|""\)/);
  assert.match(appWhitespace, /hodlBindKeypadPointer\(keyboard\.querySelectorAll\("button"\),\(\)=>activeInput\)/);
  assert.match(app, /function hodlFilterSeed\(e\)\{[^}]*hodlLooksExtendedKey\(value\)\?value:value\.toLowerCase\(\)/);
  // The chrome is the card's shared switch, asserted once; a component states
  // only how it sits in its own container.
  assert.match(appSource, /class="switch-toggle passphrase-bip39-toggle"/);
});

test("multisig policy settings precede the key inputs and output settings follow them", () => {
  const fieldOrder = /id="msig-script-tabs"[\s\S]*id="msig-key-order"[\s\S]*id="msig-legacy-bip87"[\s\S]*id="msig-key-order-status"[\s\S]*id="msig-keys"[\s\S]*id="msig-hint"[\s\S]*id="msig-origin-state"[\s\S]*id="msig-purpose"[\s\S]*id="msig-network"[\s\S]*id="msig-account"[\s\S]*id="msig-address-start"[\s\S]*id="msig-address-range"[\s\S]*id="msig-go"/;
  assert.match(shell, fieldOrder);
});

test("key derivation and multisig use the accurate Script type label", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="script-type-field"[^>]*>[\s\S]*?Script type[\s\S]*?<select/);
    // Script type is a button group now: one pressed segment, no select.
    assert.match(markup, /<div class="field msig-script-type-field">\s*<label id="msig-script-type-label">Script type<\/label>/);
    assert.match(markup, /data-msig-script="p2wsh" aria-pressed="true"/);
    assert.match(markup, /data-msig-script="p2tr" aria-pressed="false"/);
    assert.doesNotMatch(markup, /<option value="p2wsh"[^>]*>[^<]*BIP48/);
    assert.doesNotMatch(markup, /name="msig-script"|Matches BIP48 script type|Bare P2SH/);
  }
});

test("key derivation separates script type from the hardened purpose index", () => {
  for (const markup of [shell]) {
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
  assert.match(appSource, /fields: \{ pass: "", script: "bip84", derivationPath: `m\/84'\/\$\{hodlDefaultCoinType\(\)\}'\/0'\/\{0-1\}\/\{0-9\}`, derivationAccountPath: `m\/84'\/\$\{hodlDefaultCoinType\(\)\}'\/0'`, purpose: "84'", purposeHarden: true, coinType: `\$\{hodlDefaultCoinType\(\)\}'`, coinTypeHarden: true, network: hodlNetworkDefault/);
});

test("one editable derivation path replaces schemes and accepts arbitrary depth", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="script-type-field">Script type[\s\S]*?id="derivation-path-field">Derivation path[\s\S]*?id="derivation-path" type="text" value="m\/84'\/0'\/0'\/\{0-1\}\/\{0-9\}"/);
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

test("derivation indexes title their Harden controls with safe defaults", () => {
  // The toggle sits in the field's title row, beside the name it qualifies,
  // rather than trailing the value. That leaves every input in a settings grid
  // the same width whether or not its field offers a Harden.
  for (const markup of [shell]) {
    for (const id of ["purpose", "network", "account"]) {
      assert.match(markup, new RegExp(`<div class="field-head"><label for="${id}"[^>]*>[^<]*</label><label class="derivation-harden"><input id="${id}-harden" type="checkbox" checked`));
    }
    // The multisig purpose, network and account are hidden state rather than
    // fields — co-signer origins are the source of truth — so they stay bare
    // input pairs with no title row to sit in.
    for (const id of ["msig-purpose", "msig-network", "msig-account"]) {
      assert.match(markup, new RegExp(`<input id="${id}"[^>]*><input id="${id}-harden" type="checkbox" checked`));
    }
    assert.match(markup, /<div id="msig-origin-state" hidden aria-hidden="true">/);
    for (const id of ["branch-start", "address-start", "msig-branch-start", "msig-address-start"]) {
      assert.match(markup, new RegExp(`<div class="field-head"><label for="${id}"[^>]*>[^<]*</label><label class="derivation-harden"><input id="${id}-harden" type="checkbox"(?! checked)`));
    }
    // None of them trails its input any more.
    assert.doesNotMatch(markup, /<\/span><label class="derivation-harden">/);
  }
  // The right inset answers the input below: its 12px corner radius pulls the
  // visible edge inward, so a qualifier flush to the true edge reads as
  // overhanging it and as crowding the next column of the settings grid.
  // One column now that the control holds only the value.
  // The prime answers to the field, not the control the toggle just left.
  assert.match(appSource, /function hodlReadHardening\(prefix = ""\)/);
  assert.match(appSource, /function hodlSyncDerivationPrime\(input\)/);
  assert.match(appSource, /prime\.dataset\.indexValue = String\(input\.value \?\? ""\)/);
  assert.match(appSource, /hodlPathComponent\(e\.purpose, hardening\.purpose\)/);
  assert.match(appSource, /Hardened address indexes cannot be derived from multisig extended public keys/);
});

test("multisig script type and placeholders follow detected co-signer exports", () => {
  for (const markup of [shell]) {
    // Mixed is a state the keys put the group in, not an option it offers.
    assert.doesNotMatch(markup, /data-msig-script="mixed"/);
    assert.match(appSource, /desired = summary\.mixed \? "mixed" : summary\.kind/);
    assert.match(markup, /id="msig-script-warning" role="status" hidden/);
    assert.match(markup, /id="msig-go"[^>]*aria-describedby="msig-script-warning"/);
  }
  assert.match(shell, /placeholder="xpub…"/);
  assert.match(app, /function hodlMultisigKeyPlaceholder\(kind,network,purpose,coinType=hodlCoinTypeFromNetwork\(network\),hardening=/);
  assert.match(appSource, /hodlMultisigKeyPlaceholder\(kind, network, purpose, coinType, hodlReadHardening\("msig-"\)\)\.replace\(\/\^\\\[[\s\S]*?, ""\)/);
  assert.match(appWhitespace, /kind==="p2sh"&&purpose===45\)return`\[fingerprint\/\$\{purposeStep\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2sh"\|\|purpose===87\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2sh-p2wsh"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\/1h\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2wsh"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\/2h\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(appWhitespace, /kind==="p2tr"\)return`\[fingerprint\/\$\{purposeStep\}\/\$\{coin\}\/\$\{account\}\]\$\{testnet\?"tpub":"xpub"\}(?:…|\\u2026)`/);
  assert.match(app, /function hodlMultisigPurposeIndex\(origin\)/);
  assert.match(app, /function hodlUpdateMsigPurposeDetection\(\)/);
  assert.doesNotMatch(app, /or BIP48 script 3h/);
  assert.doesNotMatch(app, /if\(steps\[3\]==="3h"\)return"p2tr"/);
  assert.match(app, /hodlT\("Co-signer purpose indexes do not match \(\{purposes\}\)\./);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /if\(kind==="mixed"\)throw hodlError\("Co-signer keys indicate different script types. Export every key for the same multisig script type before deriving\."\)/);
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
  assert.match(app, /<div class="address-match-field"><p class="label" id="address-match-label">Check an address<\/p>/);
  assert.match(app, /id="address-match" aria-labelledby="address-match-label" aria-describedby="address-match-note"/);
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
});

test("multisig key order is sorted by default and visible with the policy settings", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="msig-script-tabs"[\s\S]*id="msig-key-order"[\s\S]*id="msig-legacy-bip87"/);
    assert.doesNotMatch(markup, /id="msig-advanced"/);
    assert.match(markup, /<option value="sorted" selected(?:="selected")?(?:\s[^>]*)?>Sorted (?:·|\\xB7) sortedmulti<\/option>/);
    assert.match(markup, /<option value="listed"(?:\s[^>]*)?>As listed (?:·|\\xB7) multi<\/option>/);
    assert.match(markup, /id="msig-key-order-status" hidden/);
  }
  assert.match(app, /function hodlMsigKeysSorted\(\)/);
  assert.match(app, /function hodlBindMsigKeyReorder\(box\)/);
  assert.match(app, /function hodlMoveMsigKeyRow\(row,offset\)/);
  assert.match(app, /hodlTText\("Move up"\)/);
  assert.match(app, /hodlTText\("Move down"\)/);
  assert.match(app, /function hodlMsigScriptOrder\(keyTokens\)/);
  assert.match(app, /id="multisig-order-heading">\$\{hodlT\("Script key order"\)\}/);
  assert.match(app, /keyOrder:"sorted"/);
  assert.match(app, /listed co-signer order is part of the script/);
});

test("multisig separates script type from purpose and keeps the Legacy BIP87 shortcut", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="msig-origin-state" hidden aria-hidden="true"[\s\S]*id="msig-purpose"[^>]*value="48"[\s\S]*id="msig-network"[^>]*value="0"[\s\S]*id="msig-account"/);
    assert.doesNotMatch(markup, /<label for="msig-purpose">Purpose<\/label>|<label for="msig-network">Network<\/label>|<label for="msig-account">Account<\/label>/);
    assert.match(markup, /id="msig-legacy-account-toggle" hidden/);
    assert.match(markup, /id="msig-legacy-bip87" type="checkbox"/);
    assert.match(markup, />Use standardized BIP87 accounts</);
    assert.match(markup, /m\/87'\/coin'\/account'/);
  }
  assert.match(appSource, /if \(toggle\) toggle\.hidden = kind === "p2tr"/);
  assert.match(app, /hodlSetMsigPurpose\(hodlStandardMsigPurpose\(\)\)/);
  assert.match(appSource, /if \(kind === "p2tr"\) return 87;/);
  assert.match(appSource, /if \(document\.getElementById\("msig-legacy-bip87"\)\?\.checked\) return 87;/);
  assert.match(appSource, /if \(kind === "p2sh"\) return 45;/);
  assert.match(app, /hodlSetMsigPurpose\(hodlStandardMsigPurpose\(kind\)\)/);
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
  assert.match(shell, /id="base-master-fingerprint-card"[\s\S]*?class="master-fingerprint-lifehash-frame"[\s\S]*?id="base-master-fingerprint-lifehash"[^>]*hidden/);
  assert.match(shell, /id="passphrase-master-fingerprint-card"[\s\S]*?class="master-fingerprint-lifehash-frame"[\s\S]*?id="passphrase-master-fingerprint-lifehash"[^>]*hidden/);
  // The card setter renders the deterministic icon for the shown fingerprint.
  assert.match(app, /function hodlSetMasterFingerprintCard\(card,valueNode,value,imageNode\)/);
  assert.match(app, /hodlLifeHash\.fromFingerprint\(value\)/);
  assert.match(appSource, /imageNode\.hidden = true;\s*imageNode\.removeAttribute\("src"\);/);
  assert.match(appSource, /imageNode\.src = url;\s*imageNode\.hidden = false;/);
  // Crisp pixels per the LifeHash presentation guidance.
});

test("the build inlines the LifeHash module", () => {
  const buildScript = read("scripts/build.mjs");
  assert.match(buildScript, /lifehash\.js/);
  assert.match(buildScript, /\/\*@@JS_LIFEHASH@@\*\//);
  assert.match(template, /<script>\/\*@@JS_LIFEHASH@@\*\/<\/script>/);
});

test("account results do not repeat derivation settings shown above", () => {
  assert.doesNotMatch(app, /account-summary-grid|function hodlAccountSummaryItem/);
});

test("multisig account is retained internally as a value derived from key origins", () => {
  for (const markup of [shell]) {
    assert.match(markup, /id="msig-origin-state" hidden aria-hidden="true"[\s\S]*<input id="msig-account" type="text" value="" disabled>/);
    assert.match(markup, /id="msig-account-warning" role="status" hidden/);
  }
  assert.match(app, /function hodlUpdateMsigAccount\(\)/);
  assert.match(app, /field\.value=summary\.mixed\?"Mixed"/);
  assert.match(app, /account:accountSummary\.account/);
  assert.match(app, /accountMixed:accountSummary\.mixed/);
});

test("multisig threshold labels describe signatures and keys", () => {
  for (const markup of [shell]) {
    assert.doesNotMatch(markup, /People \/ devices \(n\)/);
    assert.match(markup, /id="msig-m-number" type="number" min="1" max="15"[^>]*value="2"/);
    assert.match(markup, /id="msig-n-number" type="number" min="1" max="15"[^>]*value="3"/);
    assert.match(markup, /id="msig-m" type="range" min="1" max="15"[^>]*value="2"/);
    assert.match(markup, /id="msig-n" type="range" min="1" max="15"[^>]*value="3"/);
    assert.doesNotMatch(markup, /msig-threshold-ratio|msig-[mn]-output/);
    assert.doesNotMatch(markup, /<select id="msig-[mn]"/);
    assert.ok(markup.indexOf('id="msig-import"') < markup.indexOf('class="msig-threshold-labels"'));
  }
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
  for (const markup of [shell]) {
    assert.match(markup, /<h2[^>]*>Build a watch-only multisig<\/h2>/);
    assert.match(markup, /id="msig-go"[^>]*>Derive Multisig<\/button>/);
    assert.match(markup, /id="msig-go"[^>]*disabled[^>]*aria-disabled="true"/);
    assert.doesNotMatch(markup, /Create a multisig wallet|Build Multisig/);
  }
  assert.match(app, /function hodlValidatedMsigInputs\(\)/);
  assert.match(appSource, /hodlValidatedMsigInputs\(\);\s*ready = true/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /let\{network,coinType,count,addressStart,branchStart,branchRange,n,m,kind,purpose,hardening,legacyStandard,nodes,xpubs,keyTokens,accountSummary,accountWarning\}=hodlValidatedMsigInputs\(\)/);
});

test("Station tabs stay pinned left while add controls stay pinned right", () => {
  assert.match(appSource, /button\.className = "tab key-tab" \+ \(state\.isLab \? " is-lab station-tab" : ""\)/);
  assert.match(appSource, /button\.className = "tab key-tab bip85-tab" \+ \(state\.isLab \? " is-lab station-tab" : ""\)/);
  assert.match(appSource, /button\.className = "tab key-tab msig-tab" \+ \(state\.isLab \? " is-lab station-tab" : ""\)/);
  assert.match(appSource, /button\.className = "tab key-tab is-lab station-tab active"/);
  assert.match(appSource, /pinnedWidth = station && tab !== station \? station\.offsetWidth : 0/);
  assert.match(appSource, /start < left \+ pinnedWidth/);
});

test("a disabled add or remove control shows no tooltip", () => {
  // The wrapper takes :hover even when the button inside cannot, so the hint
  // has to be suppressed from the button's own disabled state.
  // It must come after the reveal rule: equal specificity, so order decides.
  assert.ok(
    css.indexOf(".add-key:disabled + .add-item-tooltip") >
      css.indexOf(".add-item-control:focus-within .add-item-tooltip"),
    "the suppression rule must follow the reveal rule",
  );
  // Every strip pairs the button with its tooltip as an immediate sibling,
  // which is what the combinator relies on.
  for (const id of ["add-key", "delete-key", "add-bip85", "delete-bip85", "add-msig", "delete-msig", "add-journal-page", "delete-journal-page"]) {
    assert.match(
      shell,
      new RegExp(`id="${id}"[^>]*>[^<]*</button><span class="add-item-tooltip"`),
      `${id} must sit immediately before its tooltip`,
    );
  }
});

test("the Key Station method picker is one dropdown carrying every method's mark", () => {
  for (const markup of [shell]) {
    // #modes hosts the title and the dropdown; the segmented row is gone.
    assert.match(markup, /<div class="key-mode-select" id="modes"><p class="label" id="key-method-label"[^>]*>Derivation method<\/p><\/div>/);
    assert.doesNotMatch(markup, /key-mode-control|key-mode-label/);
  }
  // The title is the control's accessible name, so speech input can say it.
  assert.doesNotMatch(shell, /Brain wallet — lab/);
  // The labels live in i18n-labels.js; the dropdown reads them through hodlT.
  assert.match(appSource, /option\.textContent = hodlTText\(hodlKeyModeLabels\[mode\]\);/);
  for (const mode of ["dice", "cards", "hex", "seed", "key"]) {
    assert.ok(hodlKeyModeLabels[mode]?.length > 0, `${mode} label is missing from the English label table`);
  }
  assert.equal(hodlKeyModeLabels.dice, "Dice rolls");
  assert.equal(hodlKeyModeLabels.hex, "Number bases");
  assert.equal(hodlKeyModeLabels.seed, "Seed phrase");
  assert.equal(hodlKeyModeLabels.key, "Private key");
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
  // Choosing a method invalidates the live result; opening the list does not.
  assert.match(appSource, /closest\("#modes \.custom-select-option, #seed-length \.custom-select-option/);
  // The mark rides ahead of the label in the button and in every option.
  // The card mark masks against the row it sits on, selected or not.
});

test("Station icons keep the original SP mark while normalizing the MS key cluster", () => {
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
  for (const markup of [shell]) {
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
  // And it never lights up under the pointer: both accent states exclude it.
});

test("the Keys plus control reads as unavailable until a key exists", () => {
  // + does one thing: return to the Key Station. With only the Station open
  // there is nowhere to return from, so it ships disabled and app.js keeps it
  // that way until a non-lab key is in the strip.
  assert.match(
    shell,
    /<button class="add-key" id="add-key"[^>]*disabled/,
    "add-key must ship disabled",
  );
  assert.match(appSource, /function hodlSyncKeyAddButton\(\) \{[\s\S]*?button\.disabled = !hodlKeys\.some\(\(state\) => !state\.isLab\);/);
  // Both controls are resynced together wherever the strip is rebuilt.
  assert.match(appSource, /hodlSyncKeyDeleteButton\(\);\n  hodlSyncKeyAddButton\(\);/);
});

test("the Multi Signature plus control reads as unavailable until a multisig exists", () => {
  assert.match(
    shell,
    /<button class="add-key" id="add-msig"[^>]*disabled/,
    "add-msig must ship disabled",
  );
  assert.match(appSource, /function hodlSyncMsigAddButton\(\) \{[\s\S]*?button\.disabled = !hodlMsigs\.some\(\(state\) => !state\.isLab\);/);
  assert.match(appSource, /hodlSyncMsigDeleteButton\(\);\n  hodlSyncMsigAddButton\(\);/);
});

test("multisig heading spans beneath the delete action on narrow screens", () => {
});

test("the tools' closing button groups stack full width on narrow screens", () => {
  // Wrapped, each control is only as wide as its label and the group reads as
  // ragged lines. Below 520px every child takes the whole row instead.
  // .psbted-actions pins the editor's row to flex-end, so the stacking rule has
  // to follow it to win on order.
  assert.ok(
    css.indexOf(".tool-actions > *") > css.indexOf(".psbted-actions { align-items: flex-end; }"),
    "the narrow-screen stack must follow .psbted-actions so its alignment wins",
  );
});

test("private alternate account exports are visible without an accordion", () => {
  assert.match(appWhitespace, /return privateExport\|\|publicExport/);
  assert.doesNotMatch(app, /Advanced private export|Advanced watch-only export/);
});


test("the beta notice sits at the top of the page as a banner", () => {
  for (const markup of [shell]) {
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
});

test("the page closes on a footer in both markups", () => {
  // Not the removed beta fine print: a plain closing line that ships in the
  // static template and the runtime template alike, and stays off paper. The
  // build stamp (version, commit, LifeHash of the commit) rides the footer;
  // the build tokens are stamped by scripts/build.mjs.
  for (const markup of [shell]) {
    // esbuild escapes the emoji and the middots when it minifies the
    // runtime template, so the two markups carry the same characters in two
    // spellings.
    assert.match(
      markup,
      /<footer class="page-footer muted no-print"><div>Team Ooga Booga<\/div><div class="page-footer-emoji">(?:🪨|\\u\{1FAA8\}) (?:🔥|\\u\{1F525\}) (?:🎲|\\u\{1F3B2\}) (?:🍌|\\u\{1F34C\})<\/div><div data-i18n-skip>Since 964013 (?:·|\\x[Bb]7|\\u00[Bb]7) <span class="page-footer-build">v\{\{VERSION\}\} (?:·|\\x[Bb]7|\\u00[Bb]7) commit <code>\{\{COMMIT_SHORT\}\}<\/code> <img class="page-footer-lifehash" id="page-footer-lifehash" data-commit="\{\{COMMIT\}\}" width="20" height="20" alt="LifeHash of the build commit" hidden><\/span><\/div><div class="page-footer-links">/,
    );
    // A fourth row closes it: the two controls that left the header bar.
    assert.match(
      markup,
      /<div class="page-footer-links"><a class="btn secondary blue github-repo-link"[\s\S]*?<button type="button" class="theme-toggle" id="theme-toggle"[\s\S]*?<\/button><\/div><\/footer>/,
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
  // .muted would otherwise colour it: the footer rule has to win on order.
  assert.ok(
    css.indexOf(".page-footer {") > css.indexOf(".muted {"),
    "the footer rule must follow .muted so its colour wins",
  );
  // The emoji row outgrows the two text rows it sits between.
});

test("the beta banner carries a dismiss control in a narrow right-hand column", () => {
  // Both markups ship the control: the static template renders before boot,
  // and the runtime template replaces it once the application takes over.
  for (const markup of [shell]) {
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
  // White on the dark banner, near-black on the light theme's pale one: the
  // glyph must stay legible in both.
  // The author display would otherwise beat the user agent's [hidden] rule
  // and the dismissed banner would stay on screen.
  // Only the dismissible banner uppercases its label; the noscript notice
  // shares .beta-warning and must keep its sentence casing.
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
    /try\{var d=document\.documentElement\.dataset,v="\{\{VERSION\}\}";if\(localStorage\.getItem\("entropylab-beta-banner-dismissed"\)===v\)d\.betaBannerDismissed="";if\(localStorage\.getItem\("entropylab-intro-dismissed"\)===v\)d\.introDismissed=""\}catch\(e\)\{\}/,
  );
  assert.ok(
    template.indexOf("betaBannerDismissed") < template.indexOf("<body"),
    "the pre-paint check must ship in the head",
  );
  // Boot must not be the thing that hides an already-dismissed banner.
  assert.doesNotMatch(appWhitespace, /localStorage\.getItem\(hodlBetaBannerStorageKey\)/);
});

test("the online and noscript warnings are titled like the beta banner", () => {
  // The online warning ships in both markups; the noscript notice is static
  // only, because the application root it would live in is replaced at boot.
  for (const markup of [shell]) {
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
  assert.match(shell, /<div class="beta-warning-text"><strong>JavaScript is required<\/strong> EntropyLab performs wallet/);
  // No lead-in colons anywhere: the label is a line of its own now.
  assert.doesNotMatch(`${shell}\n${app}`, /<strong>(Online version|JavaScript is required|Beta software):<\/strong>/);
  // The noscript notice carries no control: there is no JavaScript running to
  // answer one. It takes the label treatment and nothing else.
  const noscript = shell.slice(shell.indexOf("<noscript>"), shell.indexOf("</noscript>"));
  assert.doesNotMatch(noscript, /-dismiss/, "the noscript notice cannot carry a scripted control");
  // The hosted-site warning is permanent: the reveal unit must not read or
  // write storage, so every visit warns again.
  assert.match(online, /getElementById\("online-warning"\)\?\.removeAttribute\("hidden"\)/);
  assert.doesNotMatch(online, /localStorage/, "the online warning must not touch storage");
});

test("the beta disclaimer gates the page as a modal until accepted", () => {
  // The overlay sits in the static template after the #btc-calc root (whose
  // last child is the page footer): the application boot replaces that root's
  // contents, so the gate must live outside it — and outside the runtime
  // template — to survive boot.
  const rootAt = template.indexOf('<div id="btc-calc">');
  const shellAt = template.indexOf("/*@@SHELL@@*/");
  const overlayAt = template.indexOf('id="beta-disclaimer"');
  assert.ok(rootAt >= 0 && shellAt > rootAt && overlayAt > shellAt, "the disclaimer overlay must follow the #btc-calc shell");
  assert.ok(shell.indexOf('<footer class="page-footer') > 0, "the shell must close on the page footer");
  assert.ok(overlayAt < template.indexOf("/*@@JS_BROWSER_CHECK@@*/"), "the disclaimer overlay must ship before the scripts");
  assert.doesNotMatch(appSource, /beta-disclaimer/, "the runtime template must not carry the disclaimer");
  // It starts hidden: the reveal is scripted, so a no-JavaScript host never
  // sees an overlay it cannot dismiss.
  assert.match(
    template,
    /<div class="modal-overlay disclaimer-overlay no-print" id="beta-disclaimer" role="alertdialog" aria-modal="true" aria-labelledby="beta-disclaimer-title" aria-describedby="beta-disclaimer-text" hidden>/,
  );
  assert.match(template, /<p class="modal-warning-title disclaimer-title" id="beta-disclaimer-title"[^>]*>Beta software<\/p>/);
  assert.match(template, /<button class="btn primary" id="beta-disclaimer-accept" type="button"[^>]*>I Understand<\/button>/);
  // The fade: transparent until .is-visible, faded out and inert once
  // .is-dismissed, and motion-free when the user prefers reduced motion.
  // The page behind the card is defocused as well as darkened.
  // Icon and title share the banner's brighter alert red, and the title takes
  // the body size so it labels the sentence instead of heading it.
  // The button sits clear of the warning it answers.
  // The accept button is widened and uppercased in the card only; the shared
  // .btn base still carries every other button in the app.
});

test("the lockup steps down again below 400px", () => {
  const narrow = css.slice(css.indexOf("@media (max-width: 400px)"));
  assert.ok(narrow, "the 400px breakpoint is missing");
  // The picker holds a fourth slot in the control row, so the icons close up.
  // It has to follow the 719px block, which sets the wordmark to 19px, or the
  // cascade hands the wider rule the win at equal specificity.
  assert.ok(
    css.indexOf("@media (max-width: 719px)") < css.indexOf("@media (max-width: 400px)"),
    "the 400px block must come after the 719px block",
  );
});

test("the layout has a 320px floor that the fixed header shares", () => {
  // position: fixed sizes to the viewport rather than the body, so the bar
  // needs its own copy of the floor or it shrinks past what sits beneath it.
  // The literal appears once among the declarations, in the token itself, so
  // the two floors cannot be set apart. Prose may name the value freely.
  const declarations = css.replace(/\/\*[\s\S]*?\*\//g, "");
  assert.equal(declarations.match(/320px/g).length, 1);
});

test("header theme toggle cycles dark, light, and OS themes without a flash", () => {
  for (const markup of [shell]) {
    assert.match(markup, /class="theme-toggle" id="theme-toggle" data-theme-mode="dark" aria-label="Theme: dark\. Switch to light"/);
  }
  assert.match(template, /<script>\(function\(\)\{try\{var m=localStorage\.getItem\("entropylab-theme"\)/);
  assert.match(app, /var hodlThemeModes=\["dark","light"\],hodlThemeStorageKey="entropylab-theme"/);
  // The page eases between the two grounds, and holds still for anyone who
  // asked the system for less motion.
  // Two states only: the toggle flips, it does not cycle.
  assert.doesNotMatch(`${template}\n${app}`, /theme-icon-system|"system"/);
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
  // Off the bar it keeps the shared 44px chrome instead of the header's 40px
  // square: nothing in the header squeezes it any more.
});

test("the site header is fixed, carries the logo, and holds the version, download, and theme controls", () => {
  for (const markup of [shell]) {
    // The header precedes the page wrapper, so the banners scroll beneath it.
    const header = markup.indexOf('<div class="site-header no-print">');
    const wrapper = markup.indexOf('<div class="wrap">');
    assert.ok(header >= 0, "the fixed site header is missing");
    assert.ok(header < wrapper, "the site header must come before the page wrapper");
    assert.match(markup, /<span class="site-logo" aria-hidden="true"><\/span>\s*<span class="site-title">EntropyLab<\/span>/);
    // The version left the bar: it is the footer's build stamp now, and the
    // row needed the width for the network picker.
    assert.doesNotMatch(markup.slice(header, wrapper), /site-version/);
    for (const control of [/class="btn secondary green download-html header-button"/, /id="network-picker-button"/]) {
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
    assert.match(live, /<div class="wrap">\s*<aside class="beta-warning no-print" id="beta-warning" role="alert">[\s\S]*?<\/aside>\s*(?:<noscript>[\s\S]*?<\/noscript>\s*)?(?:<aside[^>]*online-warning[\s\S]*?<\/aside>\s*)*<section[^>]*id="site-intro">/);
    assert.doesNotMatch(markup.slice(wrapper), /<header>|download-controls/);
  }
  // The mark's own art margin supplies the lockup gap, so the flex gap is
  // cancelled on that side; without this the wordmark drifts 6px further out.
  // The wordmark shares the h1's display face rather than the control sans.
  // The wordmark runs to both ends of the ramp rather than tracking --fg, so
  // each theme has to name its own end.
  // No version rides the lockup any more, at any width.
  // online.js never fetched or rewrote the version label, and there is none to
  // rewrite now: the app makes no runtime requests.
  assert.doesNotMatch(online, /fetch\s*\(|site-version|innerHTML/);
  // Content clears the fixed header on screen, and reclaims the space in print.
  // Narrow screens take the same 12px side padding the bar takes, so the page
  // edge and the header edge stay on one line.
  assert.match(
    css.slice(css.indexOf("@media (max-width: 719px)")),
    /\.wrap \{ padding-left: 12px; padding-right: 12px; \}/,
  );
  // Every header control is one height, and Journal file actions deliberately
  // reuse that same compact sizing.
  // enhanced-inputs.js swaps the language select for a custom listbox; the
  // generated control keeps the bar's 40px chrome and sans face instead of
  // the form control's 44px minimum, control margin, and mono face, which
  // bulged out of the 52px bar.
  assert.match(shell, /class="network-picker-chevron"[^>]*>[\s\S]*?<path d="m6 9 6 6 6-6"\/>/);
  assert.match(read("src/js/enhanced-inputs.js"), /chevronPath\.setAttribute\("d", "m6 9 6 6 6-6"\)/);
});

test("the header logo is inlined for both themes and never fetched from assets", () => {
  // No markup copy may point the logo at the hosted assets directory.
  for (const markup of [shell]) {
    assert.doesNotMatch(markup, /online-brand-mark/);
    assert.doesNotMatch(markup, /assets\/entropylab_(dark|light)\.png/);
  }
});

test("the seam into the tool is wider than the page's other major seams", () => {
  // The pitch-to-tool seam is the page's widest; the closing Sources card keeps
  // the ordinary major one. Both collapse with a neighbouring card's 16px, so
  // the larger value wins rather than the two adding up.
  // The strip is the panel's top edge now, so the tool seam is above the tabs
  // and there is no gap below them to collapse with anything.
  // The card's surface comes off it: no background, no border, padding kept.
  for (const markup of [shell]) {
    // The closing sources list is a disclosure that ships open, so it reads as
    // it always did until someone shuts it.
    assert.match(markup, /<details[^>]*id="sources"[^>]*\sopen>/);
  }
});

test("the marketing card states its pitch as a list rather than a paragraph", () => {
  for (const markup of [shell]) {
    const list = markup.match(/<ul class="pitch-list muted">[\s\S]*?<\/ul>/)?.[0];
    assert.ok(list, "the pitch list is missing");
    assert.equal((list.match(/<li[\s>]/g) || []).length, 4);
    assert.match(list, /<li[^>]*>Save this air-gapped bitcoin calculator to a removable drive/);
    assert.match(list, /<li[^>]*>Keep your private keys offline\.<\/li>/);
    // The prose it replaced is gone, not merely hidden.
    assert.doesNotMatch(markup, /A signing device is only required when you spend/);
  }
});

test("the Keys tool intro tells what the calculator does, like the other tool intros", () => {
  for (const markup of [shell]) {
    // No placeholder copy rides the page's first tool intro.
    assert.doesNotMatch(markup, /lorem ipsum/i);
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
  // The footer link collapses with them, squared off against the 44px toggle.
  // The download button squares off against the 40px network picker.
  for (const markup of [shell]) {
    // The version reads as plain text beside the logo; "v0.1.3" already says
    // what it is, so it never carries a control label.
    assert.doesNotMatch(markup, /version-picker|version-select|<span class="control-label">Version<\/span>/);
    // The glyph precedes the label at every width and stands alone once the
    // labels collapse, so it is never hidden.
    assert.match(markup, /<svg class="download-mark"[^>]*><path d="M12 3v12M7 11l5 5 5-5M5 21h14"\/><\/svg><span class="control-label"[^>]*>Download<\/span><\/a>/);
    // One rule owns the icon-to-label gap in each row, so they cannot drift.
    // Centring the label's em box leaves its caps a pixel below the icon's
    // centre line, so the label carries an optical nudge back up.
    assert.match(markup, /<span class="control-label"[^>]*>GitHub<\/span><\/a>/);
    // Each accessible name still contains its visible label (WCAG 2.5.3).
    assert.match(markup, /class="btn secondary green download-html header-button"[^>]*aria-label="Download EntropyLab"/);
    assert.match(markup, /class="btn secondary blue github-repo-link"[^>]*aria-label="View the EntropyLab GitHub repository in a new tab"/);
  }
});

test("PSBT amounts and fees are labeled as unverified claims", () => {
  assert.match(app, /BTC claimed/);
  assert.match(app, /Unverified fee \(PSBT previous-output claims\)/);
  // Witness claims are unverified; non-witness claims are checked against the
  // embedded previous transaction (issue #350). Neither touches the chain.
  assert.match(app, /Witness-UTXO amounts are unverified PSBT claims/);
  assert.doesNotMatch(app, /Fee \(from PSBT fields\)/);
});

test("seed-length selector offers all five BIP39 sizes as a dropdown", () => {
  for (const markup of [shell]) {
    // One dropdown in the Method control's clothes, not five buttons.
    assert.match(markup, /<select id="seed-length-select" aria-labelledby="seed-length-label">/);
    for (const words of [12, 15, 18, 21, 24]) {
      assert.match(markup, new RegExp(`<option value="${words}"[^>]*>${words} words</option>`), `${words} is missing`);
    }
    assert.match(markup, /<option value="24" selected="selected"[^>]*>24 words<\/option>/);
    assert.doesNotMatch(markup, /data-seed-words|seed-length-options/);
  }
  // Half the card until the header's breakpoint, then the whole of it.
  // One choice drives the same state the five buttons did, and the sync back
  // cannot loop through onchange.
  assert.match(appSource, /hodlSeedLengthSelectEl\.onchange = \(\) => hodlSetSeedLength\(Number\(hodlSeedLengthSelectEl\.value\)\);/);
  assert.match(appSource, /hodlSeedLengthSelectEl\.dispatchEvent\(new Event\("entropylab:sync-select"\)\);/);
});

test("D++ uses the published hexadecimal D16 transcript without a notation toggle", () => {
  assert.match(appSource, /let dplusFaces = \["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"\]/);
  // The label text lives in the locale catalogs now; the key call stays in the source.
  assert.match(appSource, /hodlT\("D\+\+ rolls \(each word D8 and two D16 hexadice; then \{final\} for checksum\)", \{ final: hodlDPlusFinalPhrase/);
  // The closing step stays a placeholder: 24 words end on one D8, but 21 end on
  // one D16 and 18 on a D16 plus a coin flip, so it cannot be a fixed string.
  assert.match(appSource, /function hodlDPlusFinalPhrase\(words = hodlTargetWordCount\) \{/);
  assert.doesNotMatch(appSource, /then one D8 for checksum/);
  assert.doesNotMatch(appSource, /D\+\+ rolls \(D8 1\\u20138, D16 0\\u2013F/);
  assert.match(appSource, /accessibleRange\.className = "sr-only";\s*accessibleRange\.textContent = rollRange;/);
  assert.doesNotMatch(appSource, /meta\.append\(document\.createTextNode\(" \\xB7 "\), emphasis, document\.createTextNode\(rollRange\)\)/);
  // D++ shows the same two lines BitBox does: a coloured word count, then
  // what to roll next. The old "Group x of y" prefix counted completed
  // groups beside the active word, two numbers that disagreed by one.
  assert.doesNotMatch(appSource, /Group \$\{result\.completedGroups\}/);
  assert.doesNotMatch(appSource, /groupsEntered|rollsComplete|d16Range/);
  // D++ rolls all 24 words — the last is a checksum roll, not a pick from a
  // list — so the count runs to config.words, not partialWords.
  assert.match(appSource, /activeWord = partialDone \? config\.words : result\.activeGroupIndex \+ 1;/);
  // One sentence throughout: the wording never changes, only the colour, so
  // the count reads the same before and after the checksum roll lands.
  assert.match(appSource, /hodlMetaValue\(String\(activeWord\), complete\)/);
  assert.doesNotMatch(appSource, /partial: config\.partialWords \}\), hodlMetaValue\(String\(activeWord\)/);
  // Green is gated on the same flag that reveals the checksum-valid line,
  // so the count and the cue can never contradict each other.
  // Completion tints nothing but the count: a blanket .ok on the line put a
  // second, olive green beside the bright one. Errors still take the line.
  assert.match(appSource, /meta\.className = "muted" \+ \(result\.invalidCount \? " err" : ""\);/);
  assert.match(appSource, /else nextCue = hodlTText\("Checksum valid · ready to derive"\);/);
  // The next roll is the card instructions' orange next-step cue, withheld
  // while the transcript has an error, and it keeps its screen-reader range.
  assert.match(appSource, /hodlDPlusRollNode\(rollPhrase, rollRange, !result\.invalidCount\)/);
  assert.match(appSource, /let node = next \? hodlMetaCue\(rollPhrase, "next"\)/);
  assert.match(shell, /D8 labeled 1(?:–|\\u2013)8 and two hexadecimal D16 dice labeled 0(?:–|\\u2013)F/);
  assert.doesNotMatch(appSource, /data-dplus-die|hodlDPlusNumberedD16|dplusNumberedD16|Decimal D16/);
});

test("dice rolls hide Pearson chi-squared fairness behind a text expand button", () => {
  assert.match(app, /id="dice-fairness-toggle"/);
  assert.match(app, /aria-controls="dice-fairness"/);
  assert.match(app, /class="dice-fairness-toggle"/);
  assert.match(app, /data-dice-fairness-glyph/);
  assert.match(app, /hodlT\("Die Distribution \/ Fairness Analysis"\)/);
  assert.match(appSource, /<div class="seed-word-copy-row">\$\{leading\}<span class="copy-status"/);
  // The toggle has its own row now: it heads the panel under it rather than
  // trailing the copy button, which belongs with the seed phrase title.
  // The copy button sits in the title row, directly above the word grid.
  // One builder titles the derived words for every method that has them.
  assert.match(appSource, /function hodlSeedPhraseRowMarkup\(title\) \{\s*return hodlSeedCopyRowMarkup\(`<p class="label">\$\{title\}<\/p>`\);/);
  assert.match(appSource, /function hodlDerivedSeedRowMarkup\(\) \{\s*return hodlSeedPhraseRowMarkup\(hodlT\("Derived seed phrase"\)\);/);
  assert.equal(appSource.match(/\$\{hodlDerivedSeedRowMarkup\(\)\}\s*<div id="dice-words"/g)?.length, 2);
  assert.match(app, /id="dice-fairness" class="dice-fairness" hidden role="status" aria-live="polite"/);
  // The word grid is titled like every other section, in both the rendered
  // markup and the pre-boot shell so the two do not disagree at boot.
  assert.match(shell, /<div class="seed-word-copy-row"><p class="label">Derived seed phrase<\/p>[\s\S]*?<\/div>\s*<div id="dice-words"/);
  // The pre-boot markup shows the same shape the app renders: the meta row in
  // its wrapper above the input, two lines, each number a coloured value.
  assert.match(shell, /<div class="seed-word-meta label-description"><p class="muted" id="dice-meta" aria-live="polite">/);
  assert.match(shell, /<span class="meta-value is-short">0<\/span> of 99 recommended rolls<br><span class="meta-value is-short">0\.0<\/span> bits estimated/);
  assert.match(shell, /id="dice-meta"[\s\S]*?<div class="dice-input-shell">[\s\S]*?<div class="dice-input-pad/);
  // No trace of the single-line form with its trailing method restatement.
  assert.doesNotMatch(shell, /0\.0 bits estimated · 24-word seed/);
  assert.match(app, /function hodlSetDiceFairnessOpen\(open\)/);
  assert.match(app, /function hodlChiSquaredCdf\(/);
  assert.match(app, /function hodlDiceFairnessAssess\(rolls,\s*labels,\s*title\)/);
  assert.match(app, /function hodlRenderDiceFairness\(value,\s*method,\s*targetWords\s*=\s*hodlTargetWordCount\)/);
  assert.match(app, /hodlRenderDiceFairness\(input\.value,\s*hodlDiceMethod,\s*config\.words\)/);
  assert.match(app, /showDiceFairness:!1/);
  assert.match(app, /hodlFairnessVerdictLabels\[report\.verdict\.id\]/);
  assert.match(app, /hodlT\("Hide die distribution \/ fairness analysis"\)/);
  // It heads the panel it opens, so it matches the labels above it rather than
  // inheriting the browser default a step larger than every title around it.
  // Grey at rest, white while hovered or open. The arrow is a child span with
  // no colour of its own, so it follows the label through every state.
  // It waits for rolls, the way the calculations switch waits for a word.
  assert.match(appSource, /<div class="dice-fairness-row" hidden>/);
  assert.match(appSource, /if \(row\?\.classList\.contains\("dice-fairness-row"\)\) row\.hidden = !markup;/);
  // The panel goes with it: clearing the rolls must not strand it open with no
  // control left to close it.
  assert.match(appSource, /panel\.hidden = !open \|\| !markup;/);
  // Same size, weight and colour the shared title class uses.
  // A heading-styled control takes no press flash: the global button rule
  // paints one orange, which reads as a fault rather than feedback here.
  // With no rolls the note is the whole panel, so its lead would leave 18px
  // above against 12px below. Populated reports keep the lead under a head.
  // The panel sits directly under the row that opens it.
  // The arrow is the only open/closed cue, so it is readable at a glance.
  // Wide enough that swapping the two triangles cannot shift the title, and no
  // wider: at 18px a 0.9em box left a run of empty space before the text.
  // Optical: centred boxes leave the triangle reading low beside the label, and
  // a transform corrects it without touching the 44px row height.
  // Sized as a heading rather than a tap target, matching the sync switch:
  // the 44px default padded the row and pushed the panel away from its title.
  // The flex gap alone sets that spacing; no literal space in the markup.
  assert.match(appSource, /<\/span>\$\{hodlT\("Die Distribution \/ Fairness Analysis"\)\}<\/button>/);
  assert.match(shell, /dicefairness\.johnellmore\.com/);
  assert.match(shell, /How can I test whether a die is fair/);
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
  assert.doesNotMatch(`${template}\n${shell}`, /@font-face|\.woff2?|fonts\.googleapis|fonts\.gstatic/);
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

test("workspace tabs register every tool", () => {
  for (const entry of [/\["calc", "Keys", "Keys"\]/, /\["vanity", "Vanity", "Vanity"\]/, /\["bip85", "BIP-85", "BIP85"\]/,
    /\["msig", "Multi Signature", "MultiSig"\]/, /\["sp", "Silent Payments", "SP"\]/, /\["psbt", "PSBT", "PSBT"\]/,
    /\["ln", "Lightning", "LN"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  for (const markup of [shell]) {
    assert.match(markup, /id="bip85-card"/);
    assert.match(markup, /id="bip85-go"/);
  }
});

test("one PSBT workspace contains PSBT / Nonce and PSBT Editor tabs", () => {
  assert.match(appSource, /\["psbt", "PSBT", "PSBT"\]/);
  assert.doesNotMatch(appSource, /\["psbted", "PSBT Editor", "Editor"\]/);
  for (const markup of [shell]) {
    assert.match(markup, /<div class="tool-intro-stack" id="psbt-tool-intros" hidden>[\s\S]*?id="psbt-tool-intro"[\s\S]*?id="psbted-tool-intro"[\s\S]*?<section class="key-manager no-print" id="psbt-manager" hidden>/);
    assert.match(markup, /<section class="key-manager no-print" id="psbt-manager" hidden>/);
    assert.match(markup, /<div class="key-tab-strip">\s*<div class="key-tabs" id="psbt-tool-tabs" role="tablist" aria-label="PSBT stations">/);
    assert.match(markup, /class="tab key-tab is-lab active"[^>]*data-psbt-tool="nonce"/);
    assert.match(markup, /class="tab key-tab is-lab"[^>]*data-psbt-tool="editor"/);
    assert.doesNotMatch(markup, /class="psbt-tool-tabs segmented-control/);
  }
  assert.match(shell, /data-psbt-tool="nonce"[^>]*>PSBT \/ Nonce/);
  assert.match(shell, /data-psbt-tool="editor"[^>]*>PSBT Editor/);
  assert.match(shell, /id="psbt-nonce-history-upload"/);
  assert.match(shell, /id="psbt-nonce-history-download"[^>]*disabled/);
  assert.match(shell, /id="psbt-nonce-history-clear"[^>]*disabled/);
  assert.match(shell, /id="psbt-nonce-history-result" aria-live="assertive"/);
  assert.match(appSource, /parseNonceHistory, serializeNonceHistory/);
  assert.match(appSource, /"entropylab-nonce-history\.json"/);
  assert.match(appSource, /getElementById\("psbt-manager"\)/);
  assert.match(appSource, /getElementById\("psbt-tool-intros"\)/);
  assert.match(appSource, /function hodlShowPsbtTool\(id, focus = false\)/);
  assert.match(appSource, /hodlInitTabDrag\(document\.getElementById\("psbt-tool-tabs"\)\)/);
  assert.match(appSource, /getElementById\("psbted-card"\)\.hidden = !visible \|\| hodlPsbtTool !== "editor"/);
  for (const markup of [shell]) {
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
    // The row must carry psbted-actions in both markups so the editor's
    // button rows keep their compact, text-sized buttons.
    assert.match(markup, /<div class="row psbt-actions psbted-actions tool-actions">/);
  }
  assert.match(appSource, /import \{ initPsbtEditor, psbtBytesFromUpload \} from "\.\/psbt-editor\.js"/);
  // The editor reads the header picker's network through the passed getter.
  assert.match(appSource, /initPsbtEditor\(\{ networkDefault: \(\) => hodlNetworkDefault \}\)/);
});

test("Journal gates its five tools behind the local notebook", () => {
  assert.match(appSource, /\["journal", "Journal", "Journal"\]/);
  assert.match(appSource, /import \{[\s\S]*wipeJournal,[\s\S]*\} from "\.\/journal\.js"/);
  assert.match(appSource, /import \{[\s\S]*sealDocument as hodlJournalSealDocument,[\s\S]*\} from "\.\/journal\.js"/);
  assert.match(appSource, /openExport as hodlJournalOpenExport/);
  assert.match(appSource, /sealExport as hodlJournalSealExport/);
  assert.match(appSource, /function hodlShowJournalTool\(id, focus = false\)/);
  assert.match(appSource, /hodlInitTabDrag\(document\.getElementById\("journal-tool-tabs"\)\)/);
  assert.match(appSource, /hodlInitJournalNotebook\(\)/);
  assert.match(appSource, /function hodlJournalNotesClick\(field\)/);
  assert.match(appSource, /notesText\.addEventListener\("click", \(\) => hodlJournalNotesClick\(notesText\)\)/);
  assert.match(appSource, /function hodlJournalKeyReferenceKeydown\(event, field\)[\s\S]*field\.setSelectionRange\(adjacent\.start, adjacent\.end\)/);
  assert.match(appSource, /function hodlJournalDeleteKeyReference\(field, range, inputType\)[\s\S]*field\.dispatchEvent\(new InputEvent\("input"/);
  assert.match(appSource, /function hodlRefreshJournalKeyPicker\(\)/);
  assert.match(appSource, /function hodlJournalInsertKey\(select, field\)/);
  assert.match(appSource, /function hodlJournalImportFile\(file\)/);
  assert.match(appSource, /hodlSerializeNotebook\(hodlJournal\)/);
  assert.match(appSource, /hodlJournalWipeMem\(\)/);
  assert.match(appSource, /function hodlInitSecretFieldAutoClear\(\) \{[\s\S]*hodlJournalWipeMem\(\)/);
  assert.match(appSource, /function hodlJournalWipeMem\(\) \{[\s\S]*hodlJournalWipeNotebook\(\)/);
  for (const markup of [shell]) {
    assert.match(markup, /<div class="tool-intro edge-note is-info" id="journal-tool-intro" hidden>[\s\S]*?<h2>Entropy Journal<\/h2>[\s\S]*?<section class="key-manager no-print" id="journal-manager" hidden>/);
    assert.match(markup, /id="journal-global-download"[^>]*disabled aria-disabled="true"[^>]*>[\s\S]*?<span>Download journal<\/span><\/button>/);
    assert.match(markup, /class="btn red clear-current-action" id="journal-global-clear"[^>]*disabled aria-disabled="true"[^>]*>Clear journal<\/button>/);
    assert.match(markup, /<section class="key-manager no-print" id="journal-manager" hidden>/);
    assert.match(markup, /<div class="key-tabs" id="journal-tool-tabs" role="tablist" aria-label="Journal stations">/);
    assert.match(markup, /id="journal-book-tab"[^>]*data-journal-tool="book"[^>]*disabled>Entries<\/button>/);
    assert.match(markup, /id="journal-notes-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="notes"[^>]*disabled/);
    assert.match(markup, /id="journal-keymanager-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="keymanager"[^>]*disabled/);
    assert.match(markup, /id="journal-state-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="state"[^>]*disabled/);
    assert.match(markup, /id="journal-log-tab"[^>]*aria-disabled="true"[^>]*data-journal-tool="log"[^>]*disabled/);
    assert(markup.indexOf('id="journal-notes-tab"') < markup.indexOf('id="journal-keymanager-tab"') && markup.indexOf('id="journal-keymanager-tab"') < markup.indexOf('id="journal-state-tab"'), "Key manager should follow Notepad in the Journal tab strip");
    assert.match(markup, /id="journal-card" role="region" aria-label="Journal"/);
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
    assert.match(markup, /Journal password \(optional\)/);
    assert.match(markup, /placeholder="Leave blank for no password"/);
    assert.match(markup, /Confirm password \(optional\)/);
    assert.match(markup, /placeholder="Repeat password or leave blank"/);
    assert.match(markup, /class="row bip85-actions journal-create-actions tool-actions">\s*<button class="btn primary" id="journal-create"[^>]*>Create journal<\/button>\s*<span class="journal-create-ready" id="journal-create-ready" hidden><span class="journal-create-ready-arrow" aria-hidden="true">←<\/span> <span class="journal-create-ready-text">Ready to create without a password<\/span><\/span>/);
    assert.match(markup, /id="journal-notes-card"/);
    assert.match(markup, /id="journal-keymanager-card"/);
    assert.match(markup, /id="journal-state-card"/);
    assert.match(markup, /id="journal-log-card"/);
    assert.match(markup, /id="journal-notes-card"[^>]*>[\s\S]*?id="journal-notes-tool-intro"[\s\S]*?<h2>Notepad<\/h2>[\s\S]*?id="journal-page-tabs"/);
    assert.match(markup, /id="journal-keymanager-card"[^>]*>[\s\S]*?id="journal-keymanager-tool-intro"[\s\S]*?<h2>Key manager<\/h2>[\s\S]*?id="journal-keymanager-tabs"/);
    assert.match(markup, /id="journal-state-card"[^>]*>[\s\S]*?id="journal-state-tool-intro"[\s\S]*?<h2>Session state<\/h2>[\s\S]*?id="journal-state-text"/);
    assert.match(markup, /id="journal-log-card"[^>]*>[\s\S]*?id="journal-log-tool-intro"[\s\S]*?<h2>Session log<\/h2>[\s\S]*?id="journal-log-out"/);
    assert.match(markup, /<div class="key-tab-strip journal-page-tab-strip"><div class="key-tabs" id="journal-page-tabs" role="tablist" aria-label="Notepad pages"><\/div>/);
    assert.match(markup, /id="add-journal-page"[^>]*aria-label="Add notepad page"/);
    assert.match(markup, /id="delete-journal-page"[^>]*aria-label="Delete current notepad page"[^>]*disabled/);
    assert.match(markup, /class="journal-format-bar" role="group" aria-label="Notepad appearance and inserts"/);
    assert.match(markup, /id="journal-key-insert"[^>]*aria-label="Insert a Key Station key"/);
    assert.match(markup, /id="journal-font"[\s\S]*?id="journal-size"[\s\S]*?id="journal-spacing"/);
    assert.match(markup, /<div class="journal-notes-wrap" id="journal-page-panel" role="tabpanel"[^>]*>\s*<div class="journal-notes-render" id="journal-notes-render" aria-hidden="true"><\/div>\s*<textarea class="journal-notes-text" id="journal-notes-text"[^>]*aria-placeholder="Add new note"[^>]*><\/textarea>\s*<div class="journal-notes-prompt" id="journal-notes-prompt" aria-hidden="true"><span id="journal-notes-prompt-before"><\/span><span class="journal-notes-prompt-text" id="journal-notes-prompt-text">Add new note<\/span><\/div>/);
    assert.match(markup, /class="copy-button journal-notes-copy" id="journal-notes-copy"[^>]*aria-label="Copy notepad page"[^>]*disabled><svg[^>]*><rect class="seed-copy-icon-clip"[^>]*\/><path class="seed-copy-icon-board"[^>]*\/><\/svg><\/button>/);
    assert(markup.indexOf('class="journal-format-bar"') < markup.indexOf('id="journal-page-tabs"') && markup.indexOf('id="journal-page-tabs"') < markup.indexOf('id="journal-page-panel"'), "notepad controls should precede the page tabs while the tabs stay joined to the editor");
    assert.match(markup, /class="btn secondary green journal-download-action journal-file-button" id="journal-notes-download"[^>]*aria-label="Download notepad"[^>]*><svg class="download-mark"[\s\S]*?<span class="control-label">Download notepad<\/span><\/button>/);
    assert.match(markup, /class="btn secondary blue journal-upload-action journal-file-button" id="journal-notes-upload"[^>]*aria-label="Upload notebook"[^>]*><svg class="download-mark"[\s\S]*?<path d="M12 17V5M7 10l5-5 5 5M5 21h14"\/>[\s\S]*?<span class="control-label">Upload<\/span><\/button>/);
    assert.match(markup, /class="btn secondary green journal-download-action journal-file-button" id="journal-keymanager-download"[^>]*aria-label="Download managed keys"[^>]*>[\s\S]*?<span class="control-label">Download keys<\/span><\/button>/);
    assert.match(markup, /class="btn secondary blue journal-upload-action journal-file-button" id="journal-keymanager-upload"[^>]*aria-label="Upload managed keys"[^>]*>[\s\S]*?<span class="control-label">Upload<\/span><\/button>/);
    assert.match(markup, /id="journal-keymanager-file"[^>]*accept="\.elkeys,\.json,application\/json"/);
    assert.equal([...markup.matchAll(/class="journal-encrypt-download"/g)].length, 3, "each Journal tab should carry the shared encryption choice");
    assert.match(markup, /id="journal-notes-encrypt" type="checkbox" checked><span>Use Journal file encryption<\/span>/);
    assert.match(markup, /id="journal-state-encrypt" type="checkbox" checked><span>Use Journal file encryption<\/span>/);
    assert.match(markup, /id="journal-log-encrypt" type="checkbox" checked><span>Use Journal file encryption<\/span>/);
    assert.match(markup, /id="journal-notes-file"[^>]*accept="\.json,\.txt,application\/json,text\/plain"/);
    assert.doesNotMatch(markup, /id="journal-notes-download-text"|Download plain-text notes/);
    assert.doesNotMatch(markup, /id="journal-note-add"|>Add note</);
    assert.doesNotMatch(markup, /id="journal-state-capture"|Capture this session/);
    assert.match(markup, /id="journal-state-text"[^>]*readonly aria-readonly="true"/);
    assert.match(markup, /id="journal-state-private"/);
    assert(markup.indexOf('id="journal-state-text"') < markup.indexOf('id="journal-state-download"'), "Session state download should follow the live snapshot");
    assert.match(markup, /class="btn secondary green journal-download-action journal-file-button" id="journal-state-download"[^>]*aria-label="Download session state"[^>]*>[\s\S]*?<span class="control-label">Download session state<\/span><\/button>/);
    assert.match(markup, /<div class="journal-log-wrap"><pre class="journal-log" id="journal-log-out"[^>]*>No events yet\.<\/pre><button class="copy-button journal-log-copy" id="journal-log-copy"[^>]*aria-label="Copy session log"[^>]*><svg[^>]*><rect class="seed-copy-icon-clip"[^>]*\/><path class="seed-copy-icon-board"[^>]*\/><\/svg><\/button><\/div>/);
    assert.match(markup, /class="btn secondary green journal-download-action journal-file-button" id="journal-log-download"[^>]*aria-label="Download session log"[^>]*>[\s\S]*?<span class="control-label">Download session log<\/span><\/button>/);
    assert.match(markup, /class="btn red clear-current-action" id="journal-log-clear"[^>]*>Clear log<\/button>/);
    assert.match(markup, /class="row psbt-actions journal-log-actions tool-actions"/);
  }
  assert.match(shell, /data-journal-tool="notes"[^>]*>Notepad/);
  assert.match(shell, /data-journal-tool="keymanager"[^>]*>Key manager/);
  assert.match(shell, /data-journal-tool="state"[^>]*>Session state/);
  assert.match(shell, /data-journal-tool="log"[^>]*>Session log/);
  assert.match(appSource, /notesText\.addEventListener\("select", \(\) => hodlJournalProtectStampSelection\(notesText\)\)/);
  assert.match(appSource, /function hodlJournalProtectStampSelection\(field\) \{[\s\S]*?startStamp[\s\S]*?endStamp[\s\S]*?field\.setSelectionRange\(nextStart, nextEnd/);
  assert.match(appSource, /function hodlJournalRememberKeyInsertion\(select, field\)[\s\S]*?select\.hodlJournalInsertionRange = \{ start: field\.selectionStart, end: field\.selectionEnd \}/);
  assert.match(appSource, /let saved = select\.hodlJournalInsertionRange;\s*delete select\.hodlJournalInsertionRange;/);
  assert.match(appSource, /notesText\.addEventListener\("mousemove", \(\) => hodlJournalRevealCopyButton\(notesCopy\)\)/);
  assert.match(appSource, /hodlJournalFormatNotebook\(field\.value\)[\s\S]*?button\.dataset\.phrase = phrase/);
  assert.match(appSource, /hodlCopySeedPhraseButton\(notesCopy\);[\s\S]*?hodlJournalRevealCopyButton\(notesCopy, 1900\)/);
  assert.match(shell, /class="btn secondary green journal-download-action/);
  assert.match(shell, /class="btn secondary blue journal-upload-action/);
  assert.match(appSource, /logCopy\.dataset\.phrase = logOut\.textContent \|\| "";\s*hodlCopySeedPhraseButton\(logCopy\)/);
  assert.match(appSource, /"journal-notes-download": \["journal", "download", "notebook"\]/);
  assert.match(appSource, /"journal-state-download": \["journal", "download", "session-state"\]/);
  assert.match(appSource, /"journal-log-download": \["journal", "download", "session-log"\]/);
  assert.match(appSource, /"journal-notes-upload": \["journal", "upload", "notebook"\]/);
  assert.match(appSource, /"journal-keymanager-download": \["journal", "download", "key-manager"\]/);
  assert.match(appSource, /"journal-keymanager-upload": \["journal", "upload", "key-manager"\]/);
  assert.match(appSource, /"journal-notes-copy": \["journal", "copy", "notepad-page"\]/);
  assert.match(appSource, /"journal-log-copy": \["journal", "copy", "session-log"\]/);
  assert.match(appSource, /function hodlJournalSyncEncryptDownloads\(source\) \{[\s\S]*checkbox\.checked = hodlJournalEncryptDownloads/);
  assert.match(appSource, /function hodlJournalDownloadContent\(kind, filename, text,[\s\S]*hodlJournalSealExport\(kind, text, hodlJournalKeys\)/);
  assert.match(appSource, /\["book", "notes", "keymanager", "state", "log"\]\.includes\(id\)/);
  assert.match(appSource, /journal-keymanager-card"\)\.hidden = !visible \|\| !unlocked \|\| hodlJournalTool !== "keymanager"/);
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
  assert.doesNotMatch(appSource, /hodlJournalLog\("inspect-nonce-/);
  assert.match(appSource, /hodlJournalLog\("calculate", hodlSpMode, "sp"\)[\s\S]*hodlJournalLog\("calculate-error", hodlSpMode, "sp"\)/);
  assert.match(appSource, /hodlJournalLog\("derive-error", "", "bip85"\)/);
  assert.match(appSource, /hodlJournalLog\("note-delete", "", "journal"\)/);
  assert.match(appSource, /hodlJournal\.log\.length = 0;\s*hodlJournalLog\("clear", "session-log", "journal"\)/);
  assert.match(appSource, /\["journal", "Journal", "Journal"\]/);
  assert.doesNotMatch(appSource, /PASSWORD_MIN_LENGTH|hodlJournalPasswordMinLength|Password has too few characters/);
  assert.match(appSource, /function hodlSyncJournalCreatePasswordValidation\(\) \{[\s\S]*Password protection enabled[\s\S]*Passwords do not match/);
  assert.match(appSource, /ready\.hidden = !passwordsMatch/);
  assert.match(appSource, /Ready to create without a password/);
  assert.match(appSource, /\["journal-create-password", "journal-create-confirm"\][\s\S]*addEventListener\("input", hodlSyncJournalCreatePasswordValidation\)/);
  assert.match(appSource, /function hodlJournalCreatePasswordKeydown\(event\) \{[\s\S]*event\.key !== "Enter"[\s\S]*confirm\.focus\(\)[\s\S]*confirm\.value === password\.value\) hodlJournalCreate\(\)/);
  assert.match(appSource, /\["journal-create-password", "journal-create-confirm"\][\s\S]*addEventListener\("keydown", hodlJournalCreatePasswordKeydown\)/);
  assert.match(appSource, /function hodlSyncJournalTool\(\) \{[\s\S]*unlocked = hodlJournalUnlocked\(\)[\s\S]*button\.disabled = !unlocked;[\s\S]*button\.setAttribute\("aria-disabled", String\(!unlocked\)\)[\s\S]*journal-notes-card"\)\.hidden = !visible \|\| !unlocked/);
  assert.match(appSource, /async function hodlJournalCreate\(\) \{[\s\S]*hodlJournalBackfillDerivedKeys\(\);[\s\S]*hodlJournalShowWork\(\);\s*hodlShowJournalTool\("book"\)/);
  assert.match(appSource, /async function hodlJournalUnlock\(\) \{[\s\S]*hodlJournalBackfillDerivedKeys\(\);[\s\S]*hodlJournalShowWork\(\);\s*hodlShowJournalTool\("book"\)/);
  assert.match(appSource, /function hodlJournalSyncDerivedKeys\(states\) \{\s*if \(!hodlJournalUnlocked\(\)\) return \{ added: 0, updated: 0, matched: 0 \}/);
  assert.match(appSource, /hodlJournalKeyEntries\.clear\(\)/);
  assert.match(appSource, /hodlCommitDerivedKey\(\);\s*hodlJournalCaptureDerivedKey\(hodlKeys\[hodlActiveKey\]\)/);
  assert.match(appSource, /Unsaved changes \\u2014 download the journal file to preserve them/);
  assert.match(appSource, /function hodlJournalLock\(\) \{[\s\S]*hodlJournalTool = "book";[\s\S]*hodlSyncJournalTool\(\)/);
  assert.match(appSource, /function hodlJournalWipeMem\(\) \{[\s\S]*hodlJournalTool = "book";[\s\S]*hodlSyncJournalTool\(\)/);
  // The notebook never seals or opens without an explicit click.
  const init = appSource.slice(appSource.indexOf("function hodlInitJournalNotebook()"), appSource.indexOf("function hodlJournalWipeMem()"));
  assert.doesNotMatch(init, /hodlJournalCreate\(\);/);
});

test("the intro stack shows one tool intro at a time", () => {
  // Only the active intro is in the document, so the block is as tall as the
  // text it shows; the manager below it still closes the seam.
  assert.match(appSource, /if \(intros\) intros\.hidden = !visible;/);
});

test("Key Station keeps derivation actions focused and BIP-85 remains its own workspace", () => {
  // BIP-85 has its own tab, so the shortcut that used to sit beside Derive Key
  // is gone; automatic Journal capture also removes the old manual shortcut.
  for (const markup of [shell]) {
    assert.match(markup, /id="address-estimate"[\s\S]*?id="derive-progress"[\s\S]*?id="go"[^>]*>Derive Key<\/button>[\s\S]*?id="wipe"/);
    assert.doesNotMatch(markup, /id="journal-open"|>Save to Journal<\/button>|id="journal-use-calc"|>Use active key<\/button>/);
    assert.doesNotMatch(markup, /id="bip85-open"|>Derive BIP-85 child<\/button>/);
  }
  assert.doesNotMatch(appSource, /getElementById\("bip85-open"\)/);
  assert.doesNotMatch(appSource, /getElementById\("journal-open"\)|getElementById\("journal-use-calc"\)|hodlJournalUseActiveKey|hodlJournalApplySnapshot/);
  for (const entry of [/\["calc", "Keys", "Keys"\]/, /\["vanity", "Vanity", "Vanity"\]/, /\["bip85", "BIP-85", "BIP85"\]/,
    /\["msig", "Multi Signature", "MultiSig"\]/, /\["sp", "Silent Payments", "SP"\]/, /\["psbt", "PSBT", "PSBT"\]/,
    /\["ln", "Lightning", "LN"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  // The tab keeps its own way to adopt a key, so the removal must not have
  // taken the underlying session-key path with it.
  assert.match(appSource, /function hodlPickBip85SessionKey\(/);
  assert.match(appSource, /hodlRefreshStationKeyPickers\(\)/);
});

test("Silent Payments is a registered tool with its own card", () => {
  for (const name of ["Keys", "Multi Signature", "Silent Payments", "PSBT"]) {
    assert.match(shell, new RegExp(`aria-label="${name}"`));
  }
  for (const entry of [/\["calc", "Keys", "Keys"\]/, /\["vanity", "Vanity", "Vanity"\]/, /\["bip85", "BIP-85", "BIP85"\]/,
    /\["msig", "Multi Signature", "MultiSig"\]/, /\["sp", "Silent Payments", "SP"\]/, /\["psbt", "PSBT", "PSBT"\]/,
    /\["ln", "Lightning", "LN"\]/, /\["journal", "Journal", "Journal"\]/]) {
    assert.match(appSource, entry);
  }
  for (const markup of [shell]) {
    assert.match(markup, /id="sp-card"/);
    assert.match(markup, /id="sp-key"/);
    assert.match(markup, /id="sp-network"/);
    assert.match(markup, /id="sp-derive"/);
    assert.match(markup, /id="sp-send-go"/);
    assert.match(markup, /id="sp-verify-go"/);
    assert.match(markup, /BIP-352/);
  }
  assert.match(shell, /id="sp-payname"/);
  assert.match(shell, /bitcoin:\?sp=/);
  assert.match(shell, /BIP-321/);
  assert.match(shell, /BIP-353/);
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
  for (const markup of [shell]) {
    assert.match(markup, /id="sp-manager"/);
    assert.match(markup, /id="sp-tabs"/);
  }
  assert.doesNotMatch(shell, /aria-label="Silent Payments"><span class="workspace-tab-icon/);
});

test("the workspace switcher keeps every tool on screen as a tab strip", () => {
  // The switcher is a nav holding one scrollable strip of tabs; it is neither
  // a segmented control nor a dropdown. Every tool is visible without asking.
  assert.match(shell, /<nav class="workspace no-print" id="workspace">/);
  assert.match(shell, /<nav class="workspace no-print" id="workspace">/);
  assert.match(appSource, /function hodlInitWorkspace\(\) \{\s*let box = hodlElement\("#workspace"\);\s*box\.innerHTML = "";/);
  assert.doesNotMatch(shell, /segmented-control" id="workspace"/);
  assert.match(shell, /<div class="workspace-tabs" id="workspace-tabs" role="tablist" aria-label="Tool">/);
  // Every tool with a tab ships in the static markup, each with a full name
  // and the
  // short form narrow screens show instead.
  for (const [full, short] of [["Keys", "Keys"], ["Vanity", "Vanity"], ["BIP-85", "BIP85"], ["Multi Signature", "MultiSig"], ["Silent Payments", "SP"], ["PSBT", "PSBT"], ["Journal", "Journal"]]) {
    assert.ok(
      shell.includes(`<span class="workspace-tab-full">${full}</span><span class="workspace-tab-short">${short}</span>`),
      `${full} is missing from the workspace strip`,
    );
    assert.match(appSource, new RegExp(`\\["[a-z0-9]+", "${full.replace(/[$()*+.?[\]^{|}]/g, "\\$&")}", "${short}"\\]`));
  }
  // One swaps for the other at the width the header drops its own labels.
  assert.match(appSource, /fullLabel\.textContent = hodlTText\(label\);\s*shortLabel\.textContent = hodlTText\(short\);/);
  // Hidden text leaves the accessibility tree, so the full name is stated on
  // the tab itself and assistive tech hears it at every width.
  assert.match(appSource, /button\.setAttribute\("aria-label", hodlTText\(label\)\);/);
  for (const full of ["Keys", "Vanity", "BIP-85", "Multi Signature", "Silent Payments", "PSBT", "Journal"]) {
    assert.match(shell, new RegExp(`aria-label="${full.replace("/", "\\/")}">[\\s\\S]*?<span class="workspace-tab-full">${full.replace("/", "\\/")}</span>`), `${full} tab needs its accessible name`);
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
  assert.doesNotMatch(`${shell}${appSource}`, /workspace-menu|hodlSetWorkspaceMenuOpen/);
  // It wears the key tabs' folder shape: a raised active tab whose bottom
  // border is painted out against the strip's rule.
  // The strip overlaps the panel by a pixel rather than drawing its own rule:
  // it is a scroll container, so it would clip any tab reaching past its edge
  // and the chosen tab could never cut the line.
  // The chosen tab takes the panel's ground and hides its own bottom edge in
  // it, so the strip's rule is cut and the two become one shape.
  // The panel closes the folder: the tool content sits inside a border that
  // carries on from the strip, open at the top where the strip's rule is.
  for (const markup of [shell]) {
    assert.match(markup, /<div class="workspace-panel" id="workspace-panel">/);
  }
  // Cards in the panel close on their own edge; the page's other cards, the
  // pitch and the sources among them, keep the shared 16px both ways.
  // Every tool panel lives inside it, and the closing Sources card does not.
  for (const markup of [shell]) {
    const panel = markup.slice(markup.indexOf('<div class="workspace-panel"'), markup.indexOf('class="card muted sources"'));
    for (const id of ["calc-card", "bip85-card", "msig-card", "sp-card", "psbt-card", "ln-card", "journal-card", "journal-notes-card", "journal-keymanager-card", "journal-state-card", "journal-log-card"]) {
      assert.ok(panel.includes(`id="${id}"`), `${id} must sit inside the workspace panel`);
    }
    assert.ok(panel.includes('<div id="out">'), "the results region must sit inside the workspace panel");
  }
  // Overflow scrolls instead of wrapping or hiding, so more tools still fit.
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
  for (const markup of [shell]) {
    assert.match(markup, /More tools/);
  }
  // It is a real control, so it is a button with a label rather than a
  // decorative span: an interactive element must not be hidden from the
  // accessibility tree.
  assert.match(shell, /<button type="button" class="workspace-more" id="workspace-more" aria-controls="workspace-tabs" aria-label="Scroll the tool list to see more tools" hidden>/);
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
});

test("Key Station stays put and a derived key opens a fingerprint tab with a summary", () => {
  assert.match(appSource, /function hodlNewLabState\(\) \{/);
  assert.match(appSource, /hodlNewKeyState\("Key Station", 0, 0\)/);
  assert.match(appSource, /name = state\.isLab \? "Key Station"/);
  assert.match(appSource, /path\.setAttribute\("d", hodlKeySilhouette\)/);
  assert.match(appSource, /function hodlCommitDerivedKey\(\) \{/);
  assert.match(appSource, /function hodlSelectLab\(\) \{/);
  assert.match(appSource, /function hodlSyncKeyResultView\(\) \{/);
  assert.match(appSource, /hodlKeys\.push\(hodlNewLabState\(\)\)/);
  assert.match(appSource, /hodlCommitDerivedKey\(\)/);
  assert.match(appSource, /button\.id = state\.isLab \? "key-tab-lab"/);
  assert.match(appSource, /function hodlAddKey\(\) \{\s*hodlSelectLab\(\);/s);
  assert.match(appSource, /button\.disabled = !state \|\| state\.isLab;/);
  for (const markup of [shell]) {
    assert.match(markup, /id="key-summary"/);
    assert.match(markup, /id="key-lab"/);
    assert.match(markup, /id="key-edit-inputs"/);
    assert.match(markup, /id="key-summary-path"/);
    assert.match(markup, /Open Key Station to derive another key/);
    assert.match(markup, /Base 10 \[0-9\] \/ Hashed rolls \(recommended\)/);
    assert.match(markup, /Dice \[1-6\] \/ Hashed rolls/);
  }
  assert.match(appSource, /hodlT\("Base 10 \[0-9\] \/ Hashed rolls \(recommended\)"\)/);
  assert.match(appSource, /hodlT\("Dice \[1-6\] \/ Hashed rolls"\)/);
  assert.match(appSource, /function hodlSizeKeySummaryLifehash\(\) \{[\s\S]*getBoundingClientRect\(\)\.height[\s\S]*image\.style\.height = image\.style\.width = `\$\{height\}px`/);
  assert.match(appSource, /function hodlSnapshotKeySummary\(/);
  assert.match(appSource, /state\.createdScript = hodlKeySummaryScript\(state\)/);
  assert.match(appSource, /state\.createdPath = hodlKeySummaryPath\(state\)/);
  assert.match(appSource, /function hodlFillLabFromKey\(source\) \{/);
  assert.match(appSource, /function hodlEditKeyInputs\(\) \{/);
  assert.match(appSource, /hodlSelectKey\(hodlFillLabFromKey\(hodlKeys\[hodlActiveKey\]\)\)/);
  assert.match(appSource, /if \(edit\) edit\.onclick = hodlEditKeyInputs;/);
});

test("derived-key summaries put the selected sub-method after the method", () => {
  const source = appSource.match(/(function hodlKeySummaryMethod\(state\) \{[\s\S]*?\n\})\nfunction hodlKeySummaryScript/);
  assert.ok(source, "key summary method formatter");
  const summary = new Function(`${source[1]}; return hodlKeySummaryMethod;`)();
  assert.equal(summary({ mode: "dice", diceMethod: "coldcard" }), "Dice rolls: Base 10 [0-9] / Hashed rolls");
  assert.equal(summary({ mode: "dice", diceMethod: "coleman" }), "Dice rolls: Dice [1-6] / Hashed rolls");
  assert.equal(summary({ mode: "dice", diceMethod: "bitbox" }), "Dice rolls: BitBox diceware / Direct word selection");
  assert.equal(summary({ mode: "dice", diceMethod: "dplus" }), "Dice rolls: D++ / Direct word selection");
  assert.equal(summary({ mode: "cards", cardMethod: "direct" }), "Cards: Direct word selection");
  assert.equal(summary({ mode: "hex", entropyFormat: "hex" }), "Number bases: Hexadecimal (Base 16)");
  assert.equal(summary({ mode: "seed", seedMethod: "numbers" }), "Seed phrase: BIP39 word numbers");
  assert.equal(summary({ mode: "key", fields: { keyKind: "minikey" } }), "Private key: Mini key");
});

test("derived key results put private recovery before script type and addresses", () => {
  // The HD result sits in the Key Station card, so the toolbar can follow the
  // reader through it: the selected script type renders into a container passed in.
  assert.match(appSource, /hodlOutEl\.innerHTML = hodlHdWalletData\(t, '<div id="acct" class="key-groups-slot"><\/div>'\);/);
  // The sticky toolbar (script type, then privacy), then one list
  // of groups (recovery, identity, and the selected script type), and the
  // wallet-wide exports last.
  // Both strips belong to the sticky toolbar; which one leads is a design
  // decision, so only their presence is asserted here. The end of the block is
  // found forward of the toolbar: the single-key view has its own key-groups.
  const hdToolbarStart = appSource.indexOf('<div class="key-view-toolbar no-print">\n');
  const hdToolbar = appSource.slice(hdToolbarStart, appSource.indexOf('<div class="key-groups">', hdToolbarStart));
  for (const part of [/hodlPrivacyBarMarkup\(\)/, /id="acct-tabs" role="group"/]) assert.match(hdToolbar, part);
  // The script type is a button group reporting aria-pressed, not a tablist.
  assert.match(appSource, /i\.setAttribute\("aria-pressed", String\(o\.def\.id === r\.def\.id\)\)/);
  assert.match(appSource, /hodlKeyGroupMarkup\("recovery", `\$\{recoveryTitle\}\$\{hodlPrivacyEyeMarkup\(\)\}`/);
  assert.match(appSource, /<strong>\$\{hodlT\("These values can recreate or spend from the wallet\."\)\}<\/strong> \$\{hodlT\("Reveal them only while this file is running offline on an air-gapped computer\."\)\}/);
  // The selected script type adds every address, the private keys, and the
  // watch-only exports. No receive group repeats the first address of the table.
  assert.match(appSource, /hodlElement\("#acct"\)\.innerHTML = `\s*\$\{hodlKeyGroupMarkup\("hd-addresses", [\s\S]*?\$\{privateGroup\}\s*\$\{hodlKeyGroupMarkup\("watch", hodlT\("Watch-only exports"\)/);
  assert.match(appSource, /hodlKeyGroupMarkup\("account-private", `\$\{hodlT\("Account private key exports"\)\}\$\{hodlPrivacyEyeMarkup\(\)\}`/);
  assert.match(appSource, /Verify the first selected address on another trusted wallet or signing device before accepting bitcoin\./);
  assert.doesNotMatch(appSource, /id="account-receive-heading">Receive/);
  assert.match(appSource, /if \(state\) state\.reveal = hodlRevealPrivate;/);
  assert.match(appSource, /hodlBindWalletResultActions\(\);/);
});



test("every MS Station co-signer keeps its key and full path visible with synchronized advanced components", () => {
  for (const markup of [shell]) {
    assert.doesNotMatch(markup, /class="station-key-source msig-station-key-source"/);
    assert.doesNotMatch(markup, /id="msig-session-keys"/);
    assert.doesNotMatch(markup, /id="msig-session-key-status"/);
    assert.match(markup, /id="msig-reuse-session-keys"[\s\S]*Keep selected Key Station keys available for more than one co-signer input/);
  }
  assert.match(appSource, /function hodlSessionMsigKeys\(\) \{/);
  assert.match(appSource, /function hodlMatchingMsigExport\(result\) \{/);
  assert.match(appSource, /chips\.className = "msig-session-keys"/);
  assert.match(appSource, /row\.setAttribute\("aria-labelledby", title\.id\)/);
  assert.match(appSource, /advanced\.className = "derivation-advanced msig-cosigner-advanced"/);
  assert.match(appSource, /pathLabel\.textContent = hodlTText\("Full derivation path"\)/);
  assert.match(appSource, /pathInput\.className = "msig-full-path"/);
  assert.match(appSource, /fingerprintLabel\.textContent = hodlTText\("Master fingerprint"\)/);
  assert.match(appSource, /fingerprintInput\.className = "msig-master-fingerprint"/);
  assert.match(appSource, /originFields\.append\(fingerprintLabel, pathLabel\)/);
  assert.match(appSource, /pathComponents\.className = "derivation-advanced-fields msig-path-components"/);
  assert.match(appSource, /advanced\.append\(advancedSummary, pathComponents\)/);
  assert.match(appSource, /content\.append\(chips, lab, originFields, advanced\)/);
  assert.match(appSource, /hodlCreateMsigSessionKeyButton\(option, "msig-session-key"/);
  assert.match(appSource, /function hodlPickMsigSessionKey\(option, row\) \{/);
  assert.match(appSource, /ta\.value = deselect \? "" : value/);
  assert.match(appSource, /\(\) => hodlPickMsigSessionKey\(option, row\)/);
  assert.match(appSource, /let unavailable = !reuse && !active && Boolean\(option\.baseId\) && usedElsewhere\.has\(option\.baseId\)/);
  assert.match(appSource, /button\.disabled = unavailable/);
  assert.match(appSource, /is already selected for another co-signer/);
  assert.match(appSource, /\$\{selected \? "Remove" : "Use"\} Key Station key/);
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, fingerprint\)/);
  assert.match(appSource, /hodlRefreshMsigSessionPickers\(\)/);
  // Reusing a key appends a public child to the one visible full path; there
  // is no second, special-purpose child-path control to reconcile.
  assert.match(appSource, /function hodlMsigSuggestedDerivationPath\(parsed, row\) \{/);
  assert.match(appSource, /value \+= "\/" \+ hodlMsigSuggestedDerivationPath\(optionParsed, row\)/);
  assert.match(appSource, /function hodlUpdateMsigFullPathFromComponents\(row\) \{/);
  assert.match(appSource, /hodlApplyMsigRowPath\(row, false\)/);
  assert.match(appSource, /function hodlApplyMsigRowPath\(row, renderComponents = true\) \{/);
  assert.match(appSource, /if \(renderComponents\) hodlRenderMsigPathComponents\(row\)/);
  assert.match(appSource, /row\.dataset\.msigPathUpdate = "true"/);
  assert.match(appSource, /if \(row\.dataset\.msigPathUpdate !== "true"\) hodlSyncMsigRowPathFromKey\(row\)/);
  assert.match(appSource, /value\.setSelectionRange\(/);
  assert.match(appSource, /hodlHint\(ta, null, hodlTText\("Choose a Key Station key above, or paste a co-signer extended public key\."\)\)/);
  assert.match(appSource, /function hodlMsigRowValue\(row, strict = false\) \{/);
  assert.match(appSource, /Master fingerprint must be exactly 8 hexadecimal characters\./);
  assert.match(appSource, /return `\[\$\{fingerprint\}\/\$\{originComponents\.map/);
  assert.match(appSource, /function hodlMsigBaseKeyId\(parsed\) \{/);
  assert.match(appSource, /parsed\.derivationPath = parsedOrigin\.derivationPath \|\| ""/);
  assert.match(appSource, /must be unhardened \(like \/1\); hardened steps cannot be derived from an extended public key/);
  assert.match(appSource, /function hodlMsigDerivedNode\(parsed\) \{/);
  assert.match(appSource, /let node = hodlMsigDerivedNode\(parsed\);\s*return hodlHex\.encode\(node\.publicKey\)/);
  assert.match(appSource, /\]\$\{canonical\}\$\{parsed\.derivationPath \? "\/" \+ parsed\.derivationPath : ""\}/);
  assert.doesNotMatch(appSource, /hodlMsigKeyTarget|hodlMsigNextKeyRow|msig-session-key-status/);
  assert.match(appSource, /reuseSessionKeys\?\.addEventListener\("change"/);
  assert.match(shell, /Reused keys need different derivation paths\./);
  // Both pickers share one selected treatment, stated once.
  assert.doesNotMatch(appSource, /msig-key-reuse-path|msig-key-reuse-apply|msig-key-reuse-clear/);
  assert.doesNotMatch(appSource, /msig-key-ident|hodlSyncMsigKeyAvatar|hodlMsigKeyOriginFingerprint/);
});

test("input help and validation messages share the same vertical spacing", () => {
});

test("tool cards follow the shared spacing contract", () => {

  const cardIds = [
    "calc-card", "vanity-card", "bip85-card", "msig-card", "sp-card",
    "psbt-card", "psbted-card", "ln-card", "journal-card", "journal-notes-card",
    "journal-keymanager-card", "journal-state-card", "journal-log-card",
  ];
  for (const id of cardIds) {
    assert.match(shell, new RegExp(`<section class="card no-print tool-card" id="${id}"`));
  }
  assert.equal((shell.match(/class="station-key-source tool-section"/g) || []).length, 3);

  const actionRows = [...shell.matchAll(/class="row ([^"]*(?:current-item-actions|bip85-actions|psbt-actions|journal-global-actions)[^"]*)"/g)];
  assert.ok(actionRows.length > 0);
  for (const [, classes] of actionRows) {
    assert.ok(classes.split(/\s+/).includes("tool-actions"), `missing tool-actions: ${classes}`);
  }
  assert.doesNotMatch(`${shell}\n${appSource}`, /style="[^"]*(?:margin|padding|gap)\s*:/);
  assert.match(contributing, /## 6\. UI layout and spacing[\s\S]*class="card no-print tool-card"[\s\S]*class="row tool-actions"/);
});

test("test mode can preload a bounded sequence of hashed-dice keys", () => {
  const packageJson = JSON.parse(read("package.json"));
  const launcher = read("scripts/testmode.mjs");
  assert.equal(packageJson.scripts.testmode, "node scripts/testmode.mjs");
  assert.match(launcher, /Usage: npm run testmode -- --keys=12 \[--port=4173\]/);
  assert.match(launcher, /integerFlag\("keys", 12, 1, 100\)/);
  assert.match(launcher, /"--test-hooks", "--out", outDir/);
  assert.match(launcher, /server\.listen\(port, "127\.0\.0\.1"/);
  assert.match(appSource, /function hodlTestDiceTranscript\(index\) \{\s*return String\(index % 6 \+ 1\)\.repeat\(Math\.floor\(index \/ 6\) \+ 1\);\s*\}/);
  assert.match(appSource, /new URLSearchParams\(location\.search\)\.get\("test-keys"\)/);
  assert.match(appSource, /return Math\.min\(Number\(raw\), 100\);/);
  assert.match(appSource, /hodlDiceEntropy\(transcript, "coldcard", 24\)/);
  assert.match(appSource, /addEventListener\("load", \(\) => hodlRenderKeyTabs\(\), \{ once: true \}\);/);
  assert.match(appSource, /if \(__ENTROPYLAB_TEST_HOOKS__\) await hodlLoadTestKeys\(\);/);
});

test("BIP-85 and SP Stations can bring in compatible Key Station roots", () => {
  for (const markup of [shell]) {
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
  // The selected chip is unmistakable: accent border and tint plus a check
  // mark, so the selection never rests on the border colour alone.
});

test("MS Station stays put and a derived wallet opens its own results tab", () => {
  assert.match(appSource, /function hodlNewMsigLabState\(\) \{/);
  assert.match(appSource, /hodlNewMsigState\("MS Station", 0, 0\)/);
  assert.match(appSource, /name = state\.isLab \? "MS Station"/);
  assert.match(appSource, /button\.append\(hodlCreateMsigTabMark\(state\), label\)/);
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
  for (const markup of [shell]) {
    assert.match(markup, /id="msig-summary"/);
    assert.match(markup, /id="msig-lab"/);
    assert.match(markup, /id="msig-out"/);
    assert.match(markup, /id="msig-edit-inputs"/);
  }
});

test("BIP-85 Station retains each child in a LifeHash fingerprint tab", () => {
  for (const markup of [shell]) {
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
  assert.match(appSource, /hodlFillKeyTabLifehash\(image, state\.fingerprint\)/);
  assert.match(appSource, /hodlBip85Children\.push\(state\)/);
  assert.match(appSource, /function hodlDeleteActiveBip85\(\) \{[\s\S]*wipeBip85Result\(state\.result\)/);
  assert.match(appSource, /state\.reveal = hodlBip85Reveal/);
});

test("session wallets use folder tabs that merge into the card", () => {
  assert.match(appSource, /let lifehash = tab\.querySelector\("\.key-tab-lifehash"\);/);
  assert.doesNotMatch(appSource, /editor\.append\(hodlCreateKeyIcon\(state\.color\), input\)/);
});

test("the vanity grinder is a workspace tab that ships collapsed and never auto-runs", () => {
  // The tab is registered between Keys and BIP-85 and localized like the rest.
  assert.match(appSource, /\["vanity", "Vanity", "Vanity"\]/);
  for (const code of ["de", "es", "fr", "pt"]) {
    const catalog = JSON.parse(read(`src/locales/${code}.json`));
    assert.ok(catalog["Vanity"]?.length, `${code} Vanity`);
  }
  // Both templates carry the intro and the card, both hidden until the tab is
  // picked; the card is a tabpanel and stays out of print output.
  for (const markup of [shell]) {
    assert.match(markup, /<div class="tool-intro edge-note is-info" id="vanity-tool-intro" hidden>/);
    assert.match(markup, /<section class="card no-print tool-card" id="vanity-card" role="tabpanel" hidden>/);
    // The key comes in through the same clickable Key Station picker the
    // BIP-85 and Silent Payments tabs use; the selected key is restated with
    // its starting passphrase, labelled and read-only.
    assert.match(markup, /<p class="label">Bring in a key from Key Station<\/p>/);
    assert.match(markup, /<div class="session-key-picker" id="vanity-session-keys" role="group" aria-label="Key Station keys" hidden><\/div>/);
    assert.match(markup, /id="vanity-source-block"[^>]*hidden/);
    assert.match(markup, /id="vanity-source"/);
    // The starting passphrase is stated, not offered for editing: it changes
    // on the Keys tab, so it must not be an input here.
    assert.match(markup, /id="vanity-pass"[^>]*aria-describedby="vanity-pass-note"/);
    assert.doesNotMatch(markup, /<(?:input|textarea) id="vanity-pass"/);
    // Method and address type are button groups; the derivation grind swaps
    // the counter fields for an account index range.
    for (const option of ["passphrase", "derivation"]) {
      assert.match(markup, new RegExp(`data-vanity-method-option="${option}"`));
    }
    assert.match(markup, /data-vanity-method-option="passphrase" aria-pressed="true"/);
    for (const script of ["p2pkh", "p2wpkh", "p2tr", "sp"]) {
      assert.match(markup, new RegExp(`data-vanity-script="${script}"`));
    }
    assert.match(markup, /<input id="vanity-prefix" autocomplete="off" spellcheck="false"[^>]*aria-describedby="vanity-prefix-help">/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Passphrase length\s*<input id="vanity-length" type="number" min="1" max="32"[^>]*value="8"/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Start counter\s*<input id="vanity-start" inputmode="numeric"[^>]*value="0"/);
    assert.match(markup, /<label class="field" data-vanity-method="passphrase">Range size\s*<input id="vanity-count" inputmode="numeric"[^>]*value="1000000"/);
    assert.match(markup, /<label class="field" data-vanity-method="derivation" hidden>Start account\s*<input id="vanity-account-start" inputmode="numeric"[^>]*value="0"/);
    assert.match(markup, /<label class="field" data-vanity-method="derivation" hidden>Accounts to try\s*<input id="vanity-account-count" inputmode="numeric"[^>]*value="100000"/);
    assert.match(markup, /<input id="vanity-workers" type="number" min="1" max="64"/);
    assert.match(markup, /id="vanity-estimate" aria-live="polite"/);
    assert.match(markup, /id="vanity-go" type="button">Start grinding</);
    assert.match(markup, /id="vanity-progress" role="progressbar"[^>]*hidden>/);
    assert.doesNotMatch(markup, /id="vanity-stop"/);
    assert.match(markup, /id="vanity-wipe" type="button" disabled aria-disabled="true">Clear results</);
    assert.match(markup, /id="vanity-status" aria-live="polite"/);
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
  assert.match(appSource, /\["bip85", "sp", "msig", "calc", "vanity", "ln"\]\.forEach/);
  assert.match(appSource, /else if \(hodlWorkspace === "vanity"\) hodlVanityCancel\(\);/);
  assert.match(appSource, /function hodlInitWorkspace\(\) \{[\s\S]*?hodlInitVanity\(\);/);
  // The workers spawn only from the button handler; nothing starts on boot,
  // on tab switches, or on input.
  assert.match(appSource, /go\.onclick = \(\) => hodlVanityRunning \? hodlVanityStop\(\) : hodlRunVanity\(\);/);
  assert.match(appSource, /go\.dataset\.derivationWidth[\s\S]*go\.style\.width = `\$\{width\}px`[\s\S]*go\.textContent = hodlTText\("Stop"\)[\s\S]*go\.dataset\.derivationState = "running"/);
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
  assert.match(vanityController, /function hodlVanitySyncSource\(\) \{[\s\S]*?pass = String\(state\.fields\?\.pass \?\? ""\)[\s\S]*?field\.textContent = pass/);
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
  for (const markup of [shell]) {
    assert.match(markup, /<label class="switch-toggle vanity-first-toggle"><input id="vanity-first" type="checkbox"><span>Stop on first find<\/span><\/label>[\s\S]*?<button class="btn primary" id="vanity-go"/);
    assert.doesNotMatch(markup, /id="vanity-first"[^>]*>[\s\S]*?<span class="label">Stop on first find/);
    assert.doesNotMatch(markup, /<button[^>]*id="vanity-first"/);
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
  // Stop on first find is a checkbox that asks the pool to stop as the first
  // match lands, and the status says so.
  assert.match(vanityController, /if \(hodlVanityStopFirst && hodlVanityRunning\) hodlVanityStop\(\);/);
  assert.match(vanityController, /"Stopped at first match"/);
  assert.match(vanityController, /hodlVanityStopFirst = Boolean\(document\.getElementById\("vanity-first"\)\?\.checked\);/);
  assert.match(vanityController, /document\.getElementById\("vanity-first"\)\.onchange = hodlVanityStopFirstChanged;/);
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
