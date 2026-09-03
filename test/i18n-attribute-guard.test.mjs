// Catalog text interpolated into a quoted HTML-template attribute must use
// hodlTAttr(). Plain hodlT() is safe for DOM setAttribute(), but a quote in its
// result can end a quoted attribute assembled through innerHTML.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function expressionEnd(line, start) {
  let depth = 1;
  let quote = "";
  let escaped = false;
  for (let index = start + 2; index < line.length; index++) {
    const character = line[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "{") depth++;
    else if (character === "}" && --depth === 0) return index;
  }
  return line.length;
}

function insideQuotedAttribute(line, expressionStart) {
  const before = line.slice(0, expressionStart);
  return /[A-Za-z][\w:-]*\s*=\s*"[^"\n]*$/.test(before)
    || /[A-Za-z][\w:-]*\s*=\s*'[^'\n]*$/.test(before);
}

// Inspect every interpolation independently instead of skipping to the end of
// an outer expression. That is important for HTML templates nested inside
// expressions such as items.map(() => `<button aria-label="${...}">`).
export function attributeContextCalls(source) {
  const found = [];
  source.split("\n").forEach((line, lineIndex) => {
    let expressionStart = -1;
    while ((expressionStart = line.indexOf("${", expressionStart + 2)) >= 0) {
      if (!insideQuotedAttribute(line, expressionStart)) continue;
      const end = expressionEnd(line, expressionStart);
      const expression = line.slice(expressionStart + 2, end);
      for (const match of expression.matchAll(/\bhodlT\(/g)) {
        const column = expressionStart + 2 + match.index + 1;
        found.push({
          line: lineIndex + 1,
          column,
          snippet: line.slice(Math.max(0, column - 41), column + 29).trim(),
        });
      }
    }
  });
  return found;
}

test("the guard recognizes direct, conditional, prefixed, and nested attribute calls", () => {
  const count = (source) => attributeContextCalls(source).length;
  assert.equal(count('`<div aria-label="${hodlT("k")}">x</div>`'), 1);
  assert.equal(count('`<input placeholder="${hodlT("k", { n: 1 })}" title=\'${hodlT("j")}\'>`'), 2);
  assert.equal(count('`<div aria-label="${condition ? hodlT("a") : hodlT("b")}">`'), 2);
  assert.equal(count('`<div aria-label="Prefix ${hodlT("k")} suffix">`'), 1);
  assert.equal(count('`<div>${items.map(() => `<button aria-label="${hodlT("k")}">x</button>`)}</div>`'), 1);
});

test("the guard allows safe attribute helpers, element content, and DOM APIs", () => {
  const count = (source) => attributeContextCalls(source).length;
  assert.equal(count('`<div aria-label="${hodlTAttr("k")}">x</div>`'), 0);
  assert.equal(count('`<p class="x">${hodlT("k")}</p>`'), 0);
  assert.equal(count('`<div>${items.map(() => `<button aria-label="${hodlTAttr("k")}">x</button>`)}</div>`'), 0);
  assert.equal(count('element.setAttribute("aria-label", hodlT("k"));'), 0);
});

test("no source file interpolates raw hodlT() into a quoted attribute", () => {
  const directory = join(root, "src/js");
  const violations = [];
  for (const file of readdirSync(directory).filter((name) => name.endsWith(".js")).sort()) {
    for (const hit of attributeContextCalls(readFileSync(join(directory, file), "utf8"))) {
      violations.push(`src/js/${file}:${hit.line}:${hit.column} ${hit.snippet}`);
    }
  }
  assert.deepEqual(violations, [], "use hodlTAttr() for catalog text inside a quoted attribute");
});
