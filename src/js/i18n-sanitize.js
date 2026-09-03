// Catalog strings are the one place translated — and machine-drafted — text
// can carry markup into the page, and some of it lands in innerHTML. Rather
// than trust the catalogs, every markup-bearing value is rebuilt from an
// allowlist before it can be used: only these elements survive, with only
// these attributes at exactly these values, and everything else — unknown
// tags, extra attributes, comments, script — is emitted as escaped text, so a
// bad string is visible on screen but can never run. HTML and plain-text sinks
// get separate renderings: HTML text is entity-escaped, while the text form
// drops allowlisted formatting tags and is safe for textContent/setAttribute.
// The output alphabet is closed: tag names and attributes come from the table
// below, never from the input, which is what makes this a boundary rather than
// a check.
export const hodlCatalogAllowedTags = Object.freeze({
  code: Object.freeze({}),
  em: Object.freeze({}),
  strong: Object.freeze({}),
  span: Object.freeze({ class: "mono" }),
  a: Object.freeze({ href: "entropylab.html", download: "entropylab.html" }),
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

// True when the parsed tag is on the allowlist with nothing but allowed
// attributes at their allowed values. Extra or altered attributes reject the
// whole tag; it is then emitted as text.
export function hodlCatalogTagAllowed(token) {
  let allowed = hodlCatalogAllowedTags[token.name];
  if (!allowed) return false;
  if (token.closing) return Object.keys(token.attrs).length === 0;
  return Object.entries(token.attrs).every(([name, value]) => Object.hasOwn(allowed, name) && allowed[name] === value);
}

function hodlRenderOpenTag(name, attrs) {
  let allowed = hodlCatalogAllowedTags[name];
  let rendered = Object.keys(allowed).filter((attribute) => Object.hasOwn(attrs, attribute)).map((attribute) => {
    let value = allowed[attribute];
    if (!/^[A-Za-z0-9._-]+$/.test(value)) throw new Error(`Unsafe fixed catalog attribute value for ${name}.${attribute}`);
    // Token-safe fixed values need no quote delimiter. Keeping the sanitizer's
    // entire output quote-free means even a misrouted tHtml() value cannot end
    // either kind of quoted host attribute.
    return ` ${attribute}=${value}`;
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
    if (!hodlCatalogTagAllowed(token)) {
      output += hodlEscapeHtmlText(token.raw);
      continue;
    }
    if (!token.closing) {
      output += hodlRenderOpenTag(token.name, token.attrs);
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
