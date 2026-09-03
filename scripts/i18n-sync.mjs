import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { hodlEscapeAttribute, hodlSanitizeCatalogHtml } from "../src/js/i18n-sanitize.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sourceFiles = ["src/index.html", "src/js/app.js"];
const voidElements = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);

function findTagEnd(source, start) {
  let quote = "";
  for (let index = start + 1; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (char === quote) quote = "";
    } else if (char === '"' || char === "'") quote = char;
    else if (char === ">") return index + 1;
  }
  return -1;
}

function parseAttributes(source, from, to) {
  const attributes = new Map();
  let index = from;
  while (index < to) {
    while (index < to && /\s/.test(source[index])) index += 1;
    if (index >= to || source[index] === "/") break;
    const nameStart = index;
    while (index < to && !/[\s=/>]/.test(source[index])) index += 1;
    if (index === nameStart) { index += 1; continue; }
    const name = source.slice(nameStart, index).toLowerCase();
    while (index < to && /\s/.test(source[index])) index += 1;
    let value = null;
    let valueStart = -1;
    let valueEnd = -1;
    let quote = "";
    if (source[index] === "=") {
      index += 1;
      while (index < to && /\s/.test(source[index])) index += 1;
      if (source[index] === '"' || source[index] === "'") {
        quote = source[index];
        index += 1;
        valueStart = index;
        while (index < to && source[index] !== quote) index += 1;
        valueEnd = index;
        value = source.slice(valueStart, valueEnd);
        if (index < to) index += 1;
      } else {
        valueStart = index;
        while (index < to && !/[\s>]/.test(source[index])) index += 1;
        valueEnd = index;
        value = source.slice(valueStart, valueEnd);
      }
    }
    attributes.set(name, { name, value, valueStart, valueEnd, quote });
  }
  return attributes;
}

export function i18nMarkupTokens(source) {
  const tokens = [];
  let index = 0;
  while (index < source.length) {
    const start = source.indexOf("<", index);
    if (start === -1) break;
    if (source.startsWith("<!--", start)) {
      const commentEnd = source.indexOf("-->", start + 4);
      index = commentEnd === -1 ? source.length : commentEnd + 3;
      continue;
    }
    let cursor = start + 1;
    let closing = false;
    if (source[cursor] === "/") { closing = true; cursor += 1; }
    const nameMatch = /^[A-Za-z][A-Za-z0-9:-]*/.exec(source.slice(cursor));
    if (!nameMatch) { index = start + 1; continue; }
    const name = nameMatch[0].toLowerCase();
    const nameEnd = cursor + nameMatch[0].length;
    const end = findTagEnd(source, start);
    if (end === -1) break;
    const attributes = closing ? new Map() : parseAttributes(source, nameEnd, end - 1);
    tokens.push({ start, end, name, closing, attributes, selfClosing: !closing && (voidElements.has(name) || /\/\s*>$/.test(source.slice(start, end))) });
    index = end;
  }
  return tokens;
}

function decodeHtmlAttribute(value) {
  return value.replace(/&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));/gi, (entity, decimal, hex, named) => {
    if (decimal) return String.fromCodePoint(Number(decimal));
    if (hex) return String.fromCodePoint(Number.parseInt(hex, 16));
    return ({ amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" })[named.toLowerCase()] ?? entity;
  });
}

function interpolate(value, vars) {
  if (!vars) return value;
  return value.replace(/\{(\w+)\}/g, (_, name) => (vars[name] == null ? `{${name}}` : String(vars[name])));
}

function escapeHtmlText(value) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function escapeTemplateLiteral(value) {
  return value.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");
}

function renderedSourceValue(value, mode, javascriptTemplate) {
  let rendered;
  if (mode === "html") rendered = hodlSanitizeCatalogHtml(value);
  else if (mode === "attribute") rendered = hodlEscapeAttribute(value);
  else rendered = escapeHtmlText(value);
  return javascriptTemplate ? escapeTemplateLiteral(rendered) : rendered;
}

function matchingClose(tokens, openIndex) {
  const open = tokens[openIndex];
  let depth = 1;
  for (let index = openIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.name !== open.name) continue;
    if (token.closing) depth -= 1;
    else if (!token.selfClosing) depth += 1;
    if (depth === 0) return token;
  }
  return null;
}

function readVars(token, fileName, problems) {
  const attr = token.attributes.get("data-i18n-vars");
  if (!attr) return undefined;
  try {
    const parsed = JSON.parse(decodeHtmlAttribute(attr.value ?? ""));
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("not an object");
    return parsed;
  } catch {
    problems.push(`${fileName}: invalid data-i18n-vars at byte ${token.start}`);
    return undefined;
  }
}

function catalogValue(catalog, keyAttr, vars, fileName, token, references, problems) {
  const key = decodeHtmlAttribute(keyAttr.value ?? "");
  references.add(key);
  if (!key || typeof catalog[key] !== "string") {
    problems.push(`${fileName}: unknown English key ${key || "(empty)"} at byte ${token.start}`);
    return null;
  }
  return interpolate(catalog[key], vars);
}

export function syncI18nSource(source, catalog, { fileName = "source", javascriptTemplate = false } = {}) {
  const tokens = i18nMarkupTokens(source);
  const replacements = [];
  const references = new Set();
  const problems = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.closing) continue;
    const textKey = token.attributes.get("data-i18n");
    const htmlKey = token.attributes.get("data-i18n-html");
    const vars = readVars(token, fileName, problems);
    if (textKey && htmlKey) problems.push(`${fileName}: element has both data-i18n and data-i18n-html at byte ${token.start}`);

    const contentKey = htmlKey ?? textKey;
    if (contentKey) {
      if (token.selfClosing) problems.push(`${fileName}: ${token.name} cannot have translated content at byte ${token.start}`);
      else {
        const close = matchingClose(tokens, index);
        if (!close) problems.push(`${fileName}: no closing </${token.name}> for translation at byte ${token.start}`);
        else {
          const value = catalogValue(catalog, contentKey, vars, fileName, token, references, problems);
          if (value !== null) replacements.push({ start: token.end, end: close.start, value: renderedSourceValue(value, htmlKey ? "html" : "text", javascriptTemplate) });
        }
      }
    }

    for (const [keyName, targetName] of [["data-i18n-aria", "aria-label"], ["data-i18n-placeholder", "placeholder"], ["data-i18n-title", "title"], ["data-i18n-alt", "alt"]]) {
      const keyAttr = token.attributes.get(keyName);
      if (!keyAttr) continue;
      const target = token.attributes.get(targetName);
      if (!target || target.valueStart < 0) {
        problems.push(`${fileName}: ${keyName} needs an existing ${targetName} fallback at byte ${token.start}`);
        continue;
      }
      const value = catalogValue(catalog, keyAttr, vars, fileName, token, references, problems);
      if (value !== null) replacements.push({ start: target.valueStart, end: target.valueEnd, value: renderedSourceValue(value, "attribute", javascriptTemplate) });
    }
  }

  for (const match of source.matchAll(/\bhodlT(?:Text|Attr)?\(\s*(["'])([^"']+)\1(?=\s*[,)]\s*)/g)) {
    references.add(match[2]);
    if (typeof catalog[match[2]] !== "string") problems.push(`${fileName}: hodlT references unknown English key ${match[2]}`);
  }

  replacements.sort((a, b) => b.start - a.start || b.end - a.end);
  for (let index = 1; index < replacements.length; index += 1) {
    if (replacements[index - 1].start < replacements[index].end) {
      problems.push(`${fileName}: nested translated fallbacks overlap at byte ${replacements[index].start}`);
    }
  }
  let output = source;
  if (!problems.length) {
    for (const replacement of replacements) output = output.slice(0, replacement.start) + replacement.value + output.slice(replacement.end);
  }
  return { output, references: [...references].sort(), problems, changed: output !== source };
}

export function runI18nSync(argv = process.argv.slice(2)) {
  const check = argv.includes("--check");
  const catalog = JSON.parse(readFileSync(join(root, "src/locales/en.json"), "utf8"));
  let failed = false;
  for (const file of sourceFiles) {
    const path = join(root, file);
    const source = readFileSync(path, "utf8");
    const result = syncI18nSource(source, catalog, { fileName: file, javascriptTemplate: file.endsWith(".js") });
    for (const problem of result.problems) console.error(problem);
    if (result.problems.length) { failed = true; continue; }
    if (check && result.changed) {
      console.error(`${relative(root, path)}: English fallback text is out of sync; run npm run i18n:sync`);
      failed = true;
    } else if (!check && result.changed) {
      writeFileSync(path, result.output);
      console.log(`Updated ${relative(root, path)}`);
    }
  }
  if (failed) process.exitCode = 1;
  else if (check) console.log("English catalog references and inline fallbacks are in sync.");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) runI18nSync();
