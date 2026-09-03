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
  const expectedVars = [...new Set([...catalog[key].matchAll(/(?<!\$)\{(\w+)\}/g)].map((match) => match[1]))].sort();
  const providedVars = Object.keys(vars ?? {}).sort();
  if (JSON.stringify(expectedVars) !== JSON.stringify(providedVars)) {
    problems.push(`${fileName}: ${key} expects variables [${expectedVars.join(", ")}] but received [${providedVars.join(", ")}] at byte ${token.start}`);
  }
  return interpolate(catalog[key], vars);
}

function firstCallArgument(source, openParen) {
  let parens = 0, brackets = 0, braces = 0;
  for (let index = openParen + 1; index < source.length; index += 1) {
    const char = source[index];
    if (char === '"' || char === "'" || char === "`") {
      const quote = char;
      for (index += 1; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === quote) break;
      }
      continue;
    }
    if (char === "/" && source[index + 1] === "/") {
      const end = source.indexOf("\n", index + 2);
      index = end === -1 ? source.length : end;
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      const end = source.indexOf("*/", index + 2);
      index = end === -1 ? source.length : end + 1;
      continue;
    }
    if (char === "(") parens += 1;
    else if (char === ")") {
      if (!parens && !brackets && !braces) return source.slice(openParen + 1, index);
      parens -= 1;
    } else if (char === "[") brackets += 1;
    else if (char === "]") brackets -= 1;
    else if (char === "{") braces += 1;
    else if (char === "}") braces -= 1;
    else if (char === "," && !parens && !brackets && !braces) return source.slice(openParen + 1, index);
  }
  return null;
}

function matchingOuterParen(expression) {
  let depth = 0;
  for (let index = 0; index < expression.length; index += 1) {
    const char = expression[index];
    if (char === '"' || char === "'" || char === "`") {
      const quote = char;
      for (index += 1; index < expression.length; index += 1) {
        if (expression[index] === "\\") index += 1;
        else if (expression[index] === quote) break;
      }
      continue;
    }
    if (char === "(") depth += 1;
    else if (char === ")" && --depth === 0) return index;
  }
  return -1;
}

function topLevelConditional(expression) {
  let parens = 0, brackets = 0, braces = 0, question = -1, nested = 0;
  for (let index = 0; index < expression.length; index += 1) {
    const char = expression[index];
    if (char === '"' || char === "'" || char === "`") {
      const quote = char;
      for (index += 1; index < expression.length; index += 1) {
        if (expression[index] === "\\") index += 1;
        else if (expression[index] === quote) break;
      }
      continue;
    }
    if (char === "(") parens += 1;
    else if (char === ")") parens -= 1;
    else if (char === "[") brackets += 1;
    else if (char === "]") brackets -= 1;
    else if (char === "{") braces += 1;
    else if (char === "}") braces -= 1;
    else if (!parens && !brackets && !braces && char === "?" && expression[index - 1] !== "?" && expression[index + 1] !== "?" && expression[index + 1] !== ".") {
      if (question === -1) question = index;
      else nested += 1;
    } else if (!parens && !brackets && !braces && char === ":" && question !== -1) {
      if (nested) nested -= 1;
      else return [question, index];
    }
  }
  return null;
}

function staticKeyCandidates(expression) {
  expression = expression.trim();
  while (expression.startsWith("(") && matchingOuterParen(expression) === expression.length - 1) {
    expression = expression.slice(1, -1).trim();
  }
  const literal = /^(["'])([^"']+)\1$/.exec(expression);
  if (literal) return [{ value: literal[2], prefix: false }];
  const template = /^`([A-Za-z0-9._-]+)`$/.exec(expression);
  if (template) return [{ value: template[1], prefix: false }];
  const conditional = topLevelConditional(expression);
  if (conditional) {
    return [
      ...staticKeyCandidates(expression.slice(conditional[0] + 1, conditional[1])),
      ...staticKeyCandidates(expression.slice(conditional[1] + 1)),
    ];
  }
  const concatenated = /^(["'])([A-Za-z0-9._-]*\.)\1\s*\+/.exec(expression);
  if (concatenated) return [{ value: concatenated[2], prefix: true }];
  const interpolated = /^`([A-Za-z0-9._-]*\.)\$\{/.exec(expression);
  if (interpolated) return [{ value: interpolated[1], prefix: true }];
  return [];
}

function collectStaticCallReferences(source, catalog, fileName, references, unvalidatedCalls, problems) {
  for (const call of source.matchAll(/\b(?:hodlT(?:Text|Attr)?|hodlNote|hodlError)\s*\(/g)) {
    const openParen = call.index + call[0].lastIndexOf("(");
    const argument = firstCallArgument(source, openParen);
    if (argument === null) {
      problems.push(`${fileName}: unterminated translation helper call at byte ${call.index}`);
      continue;
    }
    const candidates = staticKeyCandidates(argument);
    if (!candidates.length) unvalidatedCalls.push(`${fileName}: byte ${call.index}: ${argument.trim().replace(/\s+/g, " ").slice(0, 120)}`);
    for (const candidate of candidates) {
      if (candidate.prefix) {
        problems.push(`${fileName}: hodlT dynamic key prefix must enumerate complete English keys: ${candidate.value}`);
      } else {
        references.add(candidate.value);
        if (typeof catalog[candidate.value] !== "string") problems.push(`${fileName}: hodlT references unknown English key ${candidate.value}`);
      }
    }
  }
}

export function syncI18nSource(source, catalog, { fileName = "source", javascriptTemplate = false } = {}) {
  const tokens = i18nMarkupTokens(source);
  const replacements = [];
  const references = new Set();
  const unvalidatedCalls = [];
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

    for (const [keyName, targetName] of [["data-i18n-aria", "aria-label"], ["data-i18n-aria-placeholder", "aria-placeholder"], ["data-i18n-placeholder", "placeholder"], ["data-i18n-title", "title"], ["data-i18n-alt", "alt"], ["data-i18n-copy-label", "data-copy-label"], ["data-i18n-copied-label", "data-copied-label"]]) {
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

  collectStaticCallReferences(source, catalog, fileName, references, unvalidatedCalls, problems);

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
  return { output, references: [...references].sort(), unvalidatedCalls, problems, changed: output !== source };
}

export function runI18nSync(argv = process.argv.slice(2)) {
  const check = argv.includes("--check");
  const catalog = JSON.parse(readFileSync(join(root, "src/locales/en.json"), "utf8"));
  let failed = false;
  for (const file of sourceFiles) {
    const path = join(root, file);
    const source = readFileSync(path, "utf8");
    const result = syncI18nSource(source, catalog, { fileName: file, javascriptTemplate: file.endsWith(".js") });
    if (result.unvalidatedCalls.length) console.warn(`${file}: ${result.unvalidatedCalls.length} runtime-derived translation key call(s) require behavioral coverage.`);
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
