// Catalog text interpolated into a quoted HTML-template attribute must use
// hodlTAttr(). Plain hodlT() is safe for DOM setAttribute(), but a quote in its
// result can end a quoted attribute assembled through innerHTML.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function skipQuoted(source, start, quote) {
  for (let index = start + 1; index < source.length; index++) {
    if (source[index] === "\\") index++;
    else if (source[index] === quote) return index + 1;
  }
  return source.length;
}

function updateHtmlState(state, character) {
  if (state.attributeQuote) {
    if (character === state.attributeQuote) state.attributeQuote = "";
    return;
  }
  if (!state.inTag) {
    if (character === "<") state.inTag = true;
    return;
  }
  if (character === ">") state.inTag = false;
  else if (character === '"' || character === "'") state.attributeQuote = character;
}

// Walk JavaScript strings and comments so only real template interpolations are
// inspected. Each template keeps its HTML attribute state across line breaks and
// earlier interpolations, while nested templates get an independent state.
function templateInterpolations(source) {
  const interpolations = [];

  function skipLineComment(start) {
    const end = source.indexOf("\n", start + 2);
    return end < 0 ? source.length : end + 1;
  }

  function skipBlockComment(start) {
    const end = source.indexOf("*/", start + 2);
    return end < 0 ? source.length : end + 2;
  }

  function scanExpression(start) {
    let depth = 1;
    for (let index = start; index < source.length;) {
      const character = source[index];
      if (character === '"' || character === "'") {
        index = skipQuoted(source, index, character);
      } else if (character === "`") {
        index = scanTemplate(index);
      } else if (source.startsWith("//", index)) {
        index = skipLineComment(index);
      } else if (source.startsWith("/*", index)) {
        index = skipBlockComment(index);
      } else if (character === "{") {
        depth++;
        index++;
      } else if (character === "}") {
        if (--depth === 0) return { end: index, next: index + 1 };
        index++;
      } else {
        index++;
      }
    }
    return { end: source.length, next: source.length };
  }

  function scanTemplate(start) {
    const htmlState = { inTag: false, attributeQuote: "" };
    for (let index = start + 1; index < source.length;) {
      const character = source[index];
      if (character === "\\") {
        if (index + 1 < source.length && source[index + 1] !== "\n" && source[index + 1] !== "\r") {
          updateHtmlState(htmlState, source[index + 1]);
        }
        index += 2;
      } else if (character === "`") {
        return index + 1;
      } else if (character === "$" && source[index + 1] === "{") {
        const expression = scanExpression(index + 2);
        interpolations.push({
          start: index,
          end: expression.end,
          insideQuotedAttribute: Boolean(htmlState.attributeQuote),
        });
        index = expression.next;
      } else {
        updateHtmlState(htmlState, character);
        index++;
      }
    }
    return source.length;
  }

  for (let index = 0; index < source.length;) {
    const character = source[index];
    if (character === '"' || character === "'") index = skipQuoted(source, index, character);
    else if (character === "`") index = scanTemplate(index);
    else if (source.startsWith("//", index)) index = skipLineComment(index);
    else if (source.startsWith("/*", index)) index = skipBlockComment(index);
    else index++;
  }
  return interpolations.sort((left, right) => left.start - right.start);
}

function sourceLocation(source, index) {
  const before = source.slice(0, index);
  const lastNewline = before.lastIndexOf("\n");
  return {
    line: before.split("\n").length,
    column: index - lastNewline,
  };
}

// Inspect every interpolation independently instead of skipping to the end of
// an outer expression. That is important for HTML templates nested inside
// expressions such as items.map(() => `<button aria-label="${...}">`).
export function attributeContextCalls(source) {
  const found = [];
  for (const interpolation of templateInterpolations(source)) {
    if (!interpolation.insideQuotedAttribute) continue;
    const expression = source.slice(interpolation.start + 2, interpolation.end);
    for (const match of expression.matchAll(/\bhodlT\(/g)) {
      const callIndex = interpolation.start + 2 + match.index;
      const location = sourceLocation(source, callIndex);
      found.push({
        ...location,
        snippet: source.slice(Math.max(0, callIndex - 40), callIndex + 30).replace(/\s+/g, " ").trim(),
      });
    }
  }
  return found;
}

export function javascriptFiles(directory, prefix = "") {
  const files = [];
  const entries = readdirSync(directory, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const entry of entries) {
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    const absolutePath = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...javascriptFiles(absolutePath, relativePath));
    else if (entry.isFile() && entry.name.endsWith(".js")) files.push({ absolutePath, relativePath });
  }
  return files;
}

test("the guard recognizes direct, conditional, prefixed, and nested attribute calls", () => {
  const count = (source) => attributeContextCalls(source).length;
  assert.equal(count('`<div aria-label="${hodlT("k")}">x</div>`'), 1);
  assert.equal(count('`<input placeholder="${hodlT("k", { n: 1 })}" title=\'${hodlT("j")}\'>`'), 2);
  assert.equal(count('`<div aria-label="${condition ? hodlT("a") : hodlT("b")}">`'), 2);
  assert.equal(count('`<div aria-label="Prefix ${hodlT("k")} suffix">`'), 1);
  assert.equal(count('`<div>${items.map(() => `<button aria-label="${hodlT("k")}">x</button>`)}</div>`'), 1);
  assert.equal(count('`<div aria-label="prefix\n${hodlT("k")}\nsuffix">x</div>`'), 1);
  assert.equal(count('`<div aria-label="${\n  condition ? hodlT("a") : hodlT("b")\n}">x</div>`'), 2);
});

test("the guard allows safe attribute helpers, element content, and DOM APIs", () => {
  const count = (source) => attributeContextCalls(source).length;
  assert.equal(count('`<div aria-label="${hodlTAttr("k")}">x</div>`'), 0);
  assert.equal(count('`<p class="x">${hodlT("k")}</p>`'), 0);
  assert.equal(count('`<div>${items.map(() => `<button aria-label="${hodlTAttr("k")}">x</button>`)}</div>`'), 0);
  assert.equal(count('`<p class="x">\n${hodlT("k")}\n</p>`'), 0);
  assert.equal(count('const markup = `<div aria-label="safe">`; const plain = "${hodlT(\'k\')}";'), 0);
  assert.equal(count('element.setAttribute("aria-label", hodlT("k"));'), 0);
});

test("the source walk includes JavaScript files in nested directories", () => {
  const directory = mkdtempSync(join(tmpdir(), "entropylab-i18n-guard-"));
  try {
    mkdirSync(join(directory, "nested"));
    writeFileSync(join(directory, "root.js"), "");
    writeFileSync(join(directory, "nested", "child.js"), "");
    writeFileSync(join(directory, "nested", "ignored.txt"), "");
    assert.deepEqual(javascriptFiles(directory).map(({ relativePath }) => relativePath), ["nested/child.js", "root.js"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("no source file interpolates raw hodlT() into a quoted attribute", () => {
  const directory = join(root, "src/js");
  const violations = [];
  for (const file of javascriptFiles(directory)) {
    for (const hit of attributeContextCalls(readFileSync(file.absolutePath, "utf8"))) {
      violations.push(`src/js/${file.relativePath}:${hit.line}:${hit.column} ${hit.snippet}`);
    }
  }
  assert.deepEqual(violations, [], "use hodlTAttr() for catalog text inside a quoted attribute");
});
