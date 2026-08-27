import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const template = read("src/index.html");
const app = read("src/js/app.js");
const css = read("src/css/styles.css");

test("all wallet network selectors enable and default to mainnet", () => {
  for (const id of ["network", "msig-network", "psbt-network"]) {
    const selectedMainnet = new RegExp(
      `<select id="${id}"><option value="mainnet" selected(?:="selected")?>Bitcoin mainnet</option>`,
    );
    assert.match(template, selectedMainnet);
    assert.match(app, selectedMainnet);
  }
  assert.doesNotMatch(`${template}\n${app}`, /option value="mainnet"[^>]*disabled/);
  assert.doesNotMatch(app, /hodlForceTestnet|temporarily disabled/);
  assert.match(app, /network:"mainnet"/);
});

test("single-key network selector is half width on wide screens and full width on narrow screens", () => {
  assert.match(template, /<label class="field network-field">Network\s*<select id="network">/);
  assert.match(app, /<label class="field network-field">Network\s*<select id="network">/);
  assert.match(css, /\.key-settings\.single-key-mode \.network-field \{ width: 100%; max-width: 50%; \}/);
  assert.match(
    css,
    /@media \(max-width: 520px\) \{[\s\S]*?\.key-settings\.single-key-mode \.network-field \{ max-width: none; \}/,
  );
});

test("multisig derivation settings follow the key inputs", () => {
  const fieldOrder = /id="msig-keys"[\s\S]*id="msig-hint"[\s\S]*id="msig-script-type"[\s\S]*id="msig-network"[\s\S]*id="msig-account"[\s\S]*id="msig-count"[\s\S]*id="msig-go"/;
  assert.match(template, fieldOrder);
  assert.match(app, fieldOrder);
});

test("key derivation and multisig use the accurate Script type label", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /id="script-type-field">Script type\s*<select/);
    assert.match(markup, /<label class="field">Script type\s*<select id="msig-script-type"[^>]*>/);
    assert.match(markup, /<option value="p2wsh" selected(?:="selected")?>Native SegWit · BIP48<\/option>/);
    assert.doesNotMatch(markup, /name="msig-script"|Matches BIP48 script type|Bare P2SH/);
    assert.doesNotMatch(markup, />Address type</);
  }
});

test("multisig script type and placeholders follow detected co-signer exports", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /option value="mixed" disabled data-custom-select-placeholder="true">Mixed · incompatible keys/);
    assert.match(markup, /id="msig-script-warning" role="status" hidden/);
    assert.match(markup, /id="msig-go"[^>]*aria-describedby="msig-script-warning"/);
  }
  assert.match(template, /placeholder="\[fingerprint\/48h\/0h\/0h\/2h\]Zpub…"/);
  assert.match(app, /function hodlMultisigKeyPlaceholder\(kind,network,legacyStandard="bip45"\)/);
  assert.match(app, /kind==="p2sh"\)return`\[fingerprint\/45h\]\$\{testnet\?"tpub":"xpub"\}…`/);
  assert.match(app, /kind==="p2sh"&&legacyStandard==="bip87"\)return`\[fingerprint\/87h\/\$\{coin\}\/0h\]\$\{testnet\?"tpub":"xpub"\}…`/);
  assert.match(app, /testnet\?"Upub":"Ypub"/);
  assert.match(app, /testnet\?"Vpub":"Zpub"/);
  assert.match(app, /summary\.legacyMixed\?"Legacy co-signer exports mix BIP45 and BIP87/);
  assert.match(app, /summary\.legacyScriptConflict\?"BIP87 account keys are script-agnostic/);
  assert.match(app, /BIP87 keys do not encode a script type\. Select Legacy P2SH/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /if\(kind==="mixed"\)throw new Error\("Co-signer keys indicate different script types/);
});

test("key derivation shows the relevant paste-ready multisig co-signer exports", () => {
  assert.match(app, /function hodlBuildMultisigCosignerExports\(root,network,accountIndex,masterFingerprint\)/);
  assert.match(app, /accountId:"bip44",kind:"p2sh",standard:"bip45",label:"Legacy · BIP45 · No account",family:"x",accountPath:"m\/45'",originPath:"45h"/);
  assert.match(app, /accountId:"bip44",kind:"p2sh",standard:"bip87",label:`Legacy · BIP87 · Account \$\{accountIndex\}`,family:"x",accountPath:`m\/87'\/\$\{coinType\}'\/\$\{accountIndex\}'`,originPath:`87h\/\$\{coinType\}h\/\$\{accountIndex\}h`/);
  assert.match(app, /accountId:"bip49",kind:"p2sh-p2wsh",label:"Nested SegWit · BIP48",family:"y",scriptIndex:1/);
  assert.match(app, /accountId:"bip84",kind:"p2wsh",label:"Native SegWit · BIP48",family:"z",scriptIndex:2/);
  assert.doesNotMatch(app, /accountId:"bip86"/);
  assert.match(app, /accountPath=definition\.accountPath\|\|`m\/48'\/\$\{coinType\}'\/\$\{accountIndex\}'\/\$\{definition\.scriptIndex\}'`/);
  assert.match(app, /value:`\[\$\{masterFingerprint\}\/\$\{originPath\}\]\$\{publicKey\}`/);
  assert.match(app, /multisigCosignerExports:root\.privateKey\?hodlBuildMultisigCosignerExports\(root,network,accountIndex,masterFingerprint\):\[\]/);
  assert.match(app, /function hodlRenderMultisigCosignerExport\(exports,accountId\)/);
  assert.match(app, /exports\.filter\(candidate=>candidate\.accountId===accountId\)/);
  assert.match(app, /items\.map\(item=>ye\(`Multisig co-signer \$\{item\.prefix\} · \$\{item\.label\}`,item\.value\)\)\.join\(""\)/);
  assert.match(app, /\$\{ye\(`Account \$\{account\.primaryPublicLabel\}`,account\.primaryPublic\)\}\s*\$\{hodlRenderMultisigCosignerExport\(re\.multisigCosignerExports,account\.def\.id\)\}/);
  assert.doesNotMatch(`${app}\n${css}`, /account-multisig-exports/);
  assert.match(app, /Legacy P2SH requires the depth-1 BIP45 purpose key at m\/45h/);
  assert.match(app, /receiveSuffix=bip45\?"\/0\/0\/\*":"\/0\/\*"/);
  assert.match(app, /Legacy BIP45 addresses use co-signer branch 0/);
  assert.match(app, /Legacy P2SH uses the selected BIP87 account paths/);
});

test("Legacy multisig defaults to BIP45 and offers BIP87 accounts only for Legacy", () => {
  for (const markup of [template, app]) {
    assert.match(markup, /id="msig-legacy-account-toggle" hidden/);
    assert.match(markup, /id="msig-legacy-bip87" type="checkbox"/);
    assert.match(markup, />Use standardized BIP87 accounts</);
    assert.match(markup, /m\/87h\/coinh\/accounth/);
  }
  assert.match(css, /\.msig-legacy-account-toggle\[hidden\] \{ display: none !important; \}/);
  assert.match(app, /legacy=hodlScriptKind\(\)==="p2sh"/);
  assert.match(app, /if\(toggle\)toggle\.hidden=!legacy/);
  assert.match(app, /checkbox\?\.checked\?"Legacy · BIP87":"Legacy · BIP45"/);
  assert.match(app, /legacyBip87:!1/);
  assert.match(app, /scriptStandard:kind==="p2sh"\?legacyStandard:"bip48"/);
  assert.match(app, /legacyScriptConflict=standards\.includes\("bip87"\)&&summary\.kinds\.some\(kind=>kind!=="p2sh"\)/);
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
  }
  assert.match(css, /\.msig-threshold-number\s*\{[^}]*appearance: textfield[^}]*text-align: center/s);
  assert.match(css, /@media \(max-width: 520px\)[\s\S]*\.msig-threshold-labels label \{ flex-direction: column; justify-content: flex-end;/);
  assert.match(css, /\.msig-threshold-track span\s*\{[^}]*background: var\(--selection-accent\)/s);
  assert.match(css, /\.msig-threshold-thumb\s*\{[^}]*background: linear-gradient\(#858585, #5f5f5f\)/s);
  assert.match(css, /--msig-slider-inset: 14px/);
  assert.match(css, /\.msig-threshold-slider\s*\{[^}]*margin: 14px var\(--msig-slider-inset\) 0/s);
  assert.match(css, /\.msig-threshold-ticks\s*\{[^}]*margin: 0 var\(--msig-slider-inset\)/s);
  assert.match(css, /\.msig-threshold-ticks span\s*\{[^}]*left: var\(--msig-tick-position\)[^}]*transform: translateX\(-50%\)/s);
  assert.match(app, /hodlMsigSliderBaseMax=9,hodlMsigSliderLimit=15/);
  assert.match(app, /drag\.handle=delta<0\?"m":"n"/);
  assert.match(app, /visibleMax=Math\.max\(hodlMsigSliderBaseMax,n\)/);
  assert.match(app, /mNumber\.max=String\(hodlMsigSliderLimit\)/);
  assert.match(app, /nNumber\.min="1"/);
  assert.match(app, /n=hodlClampMsigThreshold\(nValue,1,hodlMsigSliderLimit\)/);
  assert.match(app, /m>=1&&n>=1&&m<=n&&n<=15/);
  assert.match(app, /if\(moveOther\)\{if\(changed==="m"\)n=Math\.max\(n,m\);else if\(changed==="n"\)m=Math\.min\(m,n\)\}/);
  assert.match(app, /hodlChangeMsigThreshold\(handle,raw,!0\)/);
  assert.match(app, /bindNumber\(mNumber,"m"\);bindNumber\(nNumber,"n"\)/);
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
  assert.match(app, /hodlValidatedMsigInputs\(\);ready=!0/);
  assert.match(app, /button\.disabled=!ready/);
  assert.match(app, /let\{network,count,n,m,kind,legacyStandard,nodes,xpubs,keyTokens,accountSummary,accountWarning\}=hodlValidatedMsigInputs\(\)/);
});

test("multisig heading spans beneath the delete action on narrow screens", () => {
  assert.match(
    css,
    /@media \(max-width: 520px\)[\s\S]*#msig-card \.key-panel-head \{ display: grid; grid-template-columns: minmax\(0, 1fr\) auto; \}[\s\S]*#msig-card \.key-panel-head > div:first-child \{ grid-column: 1 \/ -1; grid-row: 2; width: 100%; \}[\s\S]*#msig-card \.key-panel-head > \.delete-key \{ grid-column: 2; grid-row: 1; justify-self: end; \}/,
  );
});

test("private alternate account exports are visible without an accordion", () => {
  assert.match(app, /if\(includePrivate\)return`<div class="wallet-advanced">\$\{privateExport\}<\/div>`/);
  assert.doesNotMatch(app, /Advanced private export/);
});

test("top banners share one consistent gap", () => {
  assert.match(
    css,
    /\.beta-warning, \.online-warning, \.network-warning\s*\{[^}]*margin: 0 0 12px;/s,
  );
});

test("every entropy form has a click keypad with an optional shuffle", () => {
  assert.match(app, /padShuffle:!1,showKeyboard:!1/);
  assert.match(app, /class="virtual-keyboard-panel" \$\{hodlKeyboardVisible\(\)\?"":"hidden"\}/);
  assert.match(app, /class="coin-button pad-fixed" data-d="H"/);
  assert.match(app, /class="coin-button pad-fixed" data-d="T"/);
  assert.match(app, /hodlKeyboardPanel\(\[\.\.\."abcdefghijklmnopqrstuvwxyz"\],"seed-keyboard"/);
  assert.match(app, /hodlKeyboardPanel\(\[\.\.\."0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\],"key-keyboard"/);
  assert.match(css, /\.dice-input-pad\.virtual-keyboard \{/);
});
