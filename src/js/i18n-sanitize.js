// Catalog strings are the one place translated — and machine-drafted — text
// can carry markup into the page, and some of it lands in innerHTML. Rather
// than trust the catalogs, every markup-bearing value is rebuilt from an
// allowlist before it can be used: only these elements survive, with only
// these attribute forms at exactly these values, and everything else —
// unknown tags, extra attributes, comments, script — is emitted as escaped
// text, so a bad string is visible on screen but can never run. HTML and
// plain-text sinks get separate renderings: HTML text is entity-escaped,
// while the text form drops allowlisted formatting tags and is safe for
// textContent/setAttribute. The output alphabet is closed: tag names and
// attributes come from the table below, never from the input, which is what
// makes this a boundary rather than a check.
//
// Each tag maps to a list of complete allowed attribute forms: a tag survives
// only when its attributes exactly equal one form — every attribute present
// at the fixed value, and no others. The anchor forms are exactly the links
// the committed English sources carry: the offline-download self-link and the
// fixed external references (BIPs, upstream attribution, further reading),
// every one with its URL pinned so a translation can never swap the target.
// A source string that needs a new link must extend this table first —
// scripts/i18n-sync.mjs fails the build on any source markup outside it.
export const hodlCatalogAllowedTags = Object.freeze({
  code: Object.freeze([Object.freeze({})]),
  em: Object.freeze([Object.freeze({})]),
  strong: Object.freeze([Object.freeze({})]),
  span: Object.freeze([Object.freeze({ class: "mono" })]),
  a: Object.freeze([
    Object.freeze({ href: "entropylab.html", download: "entropylab.html" }),
    ...[
      "https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki",
      "https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki",
      "https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki",
      "https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki",
      "https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki",
      "https://github.com/iancoleman/bip39",
      "https://github.com/pointbiz/bitaddress.org",
      "https://blog.bitbox.swiss/en/roll-the-dice-generate-your-own-seed/",
      "https://blog.blockstream.com/anti-exfil-stopping-key-exfiltration/",
      "https://thesimplestbitcoinbook.net/wp-content/uploads/2023/09/Roll-Your-Own-Seed-Phrase-PDF.pdf",
      "https://rpg.stackexchange.com/questions/70802/how-can-i-test-whether-a-die-is-fair",
      "https://dicefairness.johnellmore.com/",
      "https://docs.ordinals.com/inscriptions.html",
    ].map((href) => Object.freeze({ href, target: "_blank", rel: "noopener noreferrer" })),
  ]),
});

// A '<' only starts markup when a letter, '/', '!' or '?' follows it; a bare
// "<0;1>" is text to an HTML parser and stays text here.
export function hodlCatalogHasMarkup(value) {
  return /<[A-Za-z/!?]/.test(String(value ?? ""));
}

const hodlControlSource = "[" + [[0, 8], [11, 12], [14, 31], [127, 159], [0x061c, 0x061c], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x2069], [0xfeff, 0xfeff]]
  .map(([from, to]) => String.fromCodePoint(from) + "-" + String.fromCodePoint(to)).join("") + "]";

export function hodlCatalogHasControlCharacters(value) {
  return new RegExp(hodlControlSource).test(String(value ?? ""));
}

const hodlNeutralizeControls = (value) => String(value ?? "").replace(new RegExp(hodlControlSource, "g"), "\uFFFD");

// Preserve only the entities this function emits itself, making sanitization
// idempotent. Every other ampersand is escaped, including numeric and named
// character references that a browser could decode into bidi/invisible text.
export function hodlEscapeHtmlText(value) {
  return hodlNeutralizeControls(value)
    .replace(/&(?!(?:amp|lt|gt|quot|#39);)/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Split a value into text runs and tag-like tokens. Each token records the raw
// source (for escaping when rejected), the lowercased tag name, whether it is
// a closing tag, and its attributes as parsed. Anything that starts like a tag
// but never closes, or is a comment or processing instruction, is a token with
// no name so it can only ever be escaped.
export function hodlCatalogTokens(value) {
  let source = String(value ?? ""), tokens = [], index = 0;
  while (index < source.length) {
    let open = source.indexOf("<", index);
    if (open < 0 || !/[A-Za-z/!?]/.test(source[open + 1] ?? "")) {
      let next = open < 0 ? source.length : open + 1;
      tokens.push({ text: source.slice(index, next) });
      index = next;
      continue;
    }
    if (open > index) tokens.push({ text: source.slice(index, open) });
    let close = hodlFindTagEnd(source, open);
    if (close < 0) {
      tokens.push({ raw: source.slice(open), name: "" });
      break;
    }
    let raw = source.slice(open, close + 1), match = /^<(\/?)([A-Za-z][A-Za-z0-9-]*)([\s\S]*?)\/?>$/.exec(raw);
    tokens.push(match ? { raw, closing: match[1] === "/", name: match[2].toLowerCase(), attrs: hodlCatalogAttributes(match[3]) } : { raw, name: "" });
    index = close + 1;
  }
  return tokens;
}

function hodlFindTagEnd(source, open) {
  let quote = "";
  for (let index = open + 1; index < source.length; index++) {
    let character = source[index];
    if (quote) {
      if (character === quote) quote = "";
    } else if (character === '"' || character === "'") quote = character;
    else if (character === ">") return index;
  }
  return -1;
}

function hodlCatalogAttributes(text) {
  let attrs = {}, pattern = /([^\s=/"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g, match;
  while ((match = pattern.exec(text))) attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
  return attrs;
}

// The fixed attribute form a parsed tag matches exactly, if any: every
// attribute present at its fixed value and no others. Closing tags carry no
// attributes.
export function hodlCatalogTagForm(token) {
  let forms = hodlCatalogAllowedTags[token.name];
  if (!forms) return null;
  if (token.closing) return Object.keys(token.attrs).length === 0 ? forms[0] : null;
  let names = Object.keys(token.attrs);
  return forms.find((form) => {
    let fixed = Object.keys(form);
    return fixed.length === names.length && names.every((name) => Object.hasOwn(form, name) && form[name] === token.attrs[name]);
  }) ?? null;
}

// True when the parsed tag is on the allowlist with exactly one of its fixed
// attribute forms. Extra or altered attributes reject the whole tag; it is
// then emitted as text.
export function hodlCatalogTagAllowed(token) {
  return hodlCatalogTagForm(token) !== null;
}

// Render the matched form's attributes from the table — never from the input.
// Token-safe values (no spaces) emit unquoted, which keeps almost all output
// quote-free so even a misrouted tHtml() value cannot end a quoted host
// attribute. A value with a space must be quoted, so the table is asserted
// quote-free: the only quoted bytes the sanitizer can ever emit wrap a fixed,
// known-inert value (today: the attribution link's rel), never input text.
function hodlRenderOpenTag(name, form) {
  let rendered = Object.entries(form).map(([attribute, value]) => {
    if (value === "" || /["'`<>]/.test(value)) throw new Error(`Unsafe fixed catalog attribute value for ${name}.${attribute}`);
    return /^[A-Za-z0-9._:/-]+$/.test(value) ? ` ${attribute}=${value}` : ` ${attribute}="${value}"`;
  }).join("");
  return `<${name}${rendered}>`;
}

export function hodlSanitizeCatalogHtml(value) {
  let source = String(value ?? "");
  let output = "", stack = [];
  for (let token of hodlCatalogTokens(source)) {
    if (token.text !== undefined) {
      output += hodlEscapeHtmlText(token.text);
      continue;
    }
    let form = hodlCatalogTagForm(token);
    if (!form) {
      output += hodlEscapeHtmlText(token.raw);
      continue;
    }
    if (!token.closing) {
      output += hodlRenderOpenTag(token.name, form);
      stack.push(token.name);
      continue;
    }
    let depth = stack.lastIndexOf(token.name);
    if (depth < 0) continue;
    while (stack.length > depth) output += `</${stack.pop()}>`;
  }
  while (stack.length) output += `</${stack.pop()}>`;
  return output;
}

// Produce the companion representation for DOM text sinks from the same
// allowlist decision. Allowed formatting tags disappear; rejected markup stays
// visible as text. Character references remain literal because textContent and
// setAttribute do not parse them.
export function hodlSanitizeCatalogText(value) {
  let output = "";
  for (let token of hodlCatalogTokens(value)) {
    if (token.text !== undefined) output += hodlNeutralizeControls(token.text);
    else if (!hodlCatalogTagAllowed(token)) output += hodlNeutralizeControls(token.raw);
  }
  return output;
}

// Catalog text placed inside a quoted attribute in an HTML template needs a
// separate encoding boundary: the markup allowlist intentionally leaves plain
// text, including quotes, unchanged.
export function hodlEscapeAttribute(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export function hodlSanitizeCatalog(catalog) {
  let clean = {};
  for (let [key, value] of Object.entries(catalog ?? {})) clean[key] = typeof value === "string" ? hodlSanitizeCatalogHtml(value) : value;
  return clean;
}

export function hodlSanitizeTextCatalog(catalog) {
  let clean = {};
  for (let [key, value] of Object.entries(catalog ?? {})) clean[key] = typeof value === "string" ? hodlSanitizeCatalogText(value) : value;
  return clean;
}
