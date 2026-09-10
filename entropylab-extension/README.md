# EntropyLab — Chrome extension (Manifest V3)

The single-file `entropylab.html` app, repackaged as an unpacked Chrome extension.
Clicking the toolbar icon opens the calculator in a full browser tab.

## Load it

1. Go to `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. **Load unpacked** → select this folder
4. Pin the icon; click it to open EntropyLab in a tab

To distribute: zip the folder contents, or `chrome://extensions` → **Pack extension**
for a `.crx` + private key. Chrome only installs `.crx` files from the Web Store or
enterprise policy, so for anyone else, unpacked or Web Store are the practical routes.

## What changed from the .html file

| Change | Why |
|---|---|
| All 10 inline `<script>` blocks moved to `js/*.js`, loaded in the same order | MV3 forbids inline script on extension pages. Nothing else about them was edited. |
| Vanity-search worker source written to `js/vanity-worker.js`; the spawn now uses `chrome.runtime.getURL()` | Blob-URL workers are unreliable under the extension CSP. The original blob path is kept as a fallback, so the bundle still runs as a plain web page. |
| Page `<meta>` CSP: `script-src` gained `'self'` | Otherwise the newly external scripts would be blocked by the page's own policy. `connect-src 'none'` is untouched — the page still cannot make a network request of any kind. |
| Service-worker registration block removed | It only ever ran on `https://entropylab.online`. |
| `<link rel="manifest">` and `apple-touch-icon` removed | Those files don't exist here; they'd log 404s. |
| Icons generated from the app's own embedded 180px favicon | 16/32/48/128 px. |

The online-warning banner script was left alone: it self-gates to `entropylab.online`
and a local preview, so it stays hidden under `chrome-extension://`.

## Manifest posture

- `"permissions": []` and `"host_permissions": []` — the extension asks for nothing.
  Chrome will show "This extension can't read or change any of your data".
  `chrome.tabs.create` needs no permission.
- `extension_pages` CSP is `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'`.
  `wasm-unsafe-eval` is required: the secp256k1 and PSBT engines are WebAssembly
  compiled from embedded base64. Without it the browser sanity check fails at startup.
- The tight air-gap policy (`default-src 'none'`, `connect-src 'none'`) lives in the
  page's meta CSP. Both policies are enforced together, so the intersection applies.

## Notes

- `js/03-entropylab-app.js` is 4.6 MB, mostly base64 WASM. Chrome handles it fine;
  first paint is a beat slower than the inlined version because it's a separate fetch
  from disk.
- Data written to `localStorage` (theme, journal, dismissed banner) is scoped to the
  extension's origin, so it is separate from anything stored by the hosted site.
- Downloads (recovery sheet, `wallet.dat`, PSBT, journal JSON) go through the normal
  Chrome download flow from `blob:` URLs. If Chrome ever asks where to save, that's
  the standard prompt, not a network operation.
