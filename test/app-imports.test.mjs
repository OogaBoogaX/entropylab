// app.js import guard: every helper app.js calls must actually be imported.
//
// The unit suites load slices of app.js with the names they need injected, so
// a call to a helper that was never imported passes every test and only throws
// ReferenceError in the real page. That is how the normalizeVinWitness send
// flow nearly shipped broken (#1028, caught in review before merge):
// bip352.js exported it, app.js called it, and every suite passed. This guard
// is the static analogue of ci-completeness.test.mjs: it diffs the bare calls
// app.js makes against the names it imports and declares, fails on any call
// to a name any local module exports but app.js never brought in, and fails
// on dead imports so the import block cannot rot.
//
// Limits (a text scan, not a JavaScript parser; the repo adds no parser
// dependency): declarations are not scoped, so a nested local, parameter or
// catch binding with the same name as an export hides a missing top-level
// import; only call forms are checked (name(, name?.(, name`), not bare
// references such as a function passed as a callback; and a call followed
// directly by a block can read as a method definition. Each gap lets a
// missing import through (a false negative); none reports a correct import.
// Run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");

// Imported local names app.js is allowed to never use (side-effect or
// deliberately unused imports). hodlFillLocaleSelect is imported with the
// other i18n helpers but is not referenced anywhere in app.js at rock.
// hodlPsbtSelfTests and validateVanityRange appear at rock only as a property
// name or object key, never as a binding, so the binding-use check below
// cannot see them; removing the imports is a source change, so they are
// allowlisted here until then.
const DEAD_IMPORT_ALLOWLIST = Object.freeze(["hodlFillLocaleSelect", "hodlPsbtSelfTests", "validateVanityRange"]);

// export * from "./x.js" chains are followed this many hops when collecting
// every module's exports, so a re-export cycle cannot loop the guard.
const STAR_EXPORT_DEPTH = 8;

const escapeRe = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isLocalJs = (specifier) => specifier.startsWith("./") && specifier.endsWith(".js");

// A regex literal may follow an operator, an opener or one of these keywords;
// anywhere else a "/" is division. Good enough to keep quoted regex bodies
// from being mistaken for string literals.
const REGEX_AFTER = new Set(["return", "typeof", "case", "delete", "void", "in", "of", "new", "instanceof", "yield", "await", "throw", "else", "do"]);

// Whether the ")" at `index` in the blanked output closes the header of an
// if, for, while or with: a statement starts after it, so a "/" there opens
// a regex, not a division (for (let n of e) /\s/.test(n) ...). Mirrors
// closesControlHeader in test/app-slice-harness.mjs.
function closesControlHeader(out, index) {
  let depth = 0, at = index;
  for (; at >= 0; at--) {
    if (out[at] === ")") depth += 1;
    else if (out[at] === "(" && --depth === 0) break;
  }
  let word = at - 1;
  while (word >= 0 && /\s/.test(out[word])) word -= 1;
  return /\b(?:if|for|while|with)$/.test(out.slice(Math.max(0, word - 5), word + 1).join(""));
}

// Blank comments and string/regex/template-literal text to spaces so call
// sites cannot hide inside prose, copy or patterns. Newlines survive so line
// numbers stay stable; template ${...} expressions stay because they are real
// code and hold most of the page's hodlT`...` calls. Length and offsets are
// preserved, so a position in the output indexes the same byte in the source.
function scan(src) {
  const out = src.split("");
  const blank = (i) => { if (out[i] !== "\n") out[i] = " "; };
  const stack = [{ mode: "code", braces: 0 }];
  // prevSig and prevPrevSig are the last two significant characters ("x"
  // stands for any value: a word, a string, a closed regex); prevSigAt is
  // prevSig's offset, so a "/" after ")" can ask closesControlHeader.
  let prevSig = "";
  let prevPrevSig = "";
  let prevSigAt = -1;
  let word = "";
  let lastWord = "";
  const markSig = (c, at) => { prevPrevSig = prevSig; prevSig = c; prevSigAt = at; };
  let i = 0;
  while (i < src.length) {
    const state = stack[stack.length - 1];
    const c = src[i];
    const d = src[i + 1];
    if (state.mode === "code") {
      if (c === "/" && d === "/") { blank(i); blank(i + 1); stack.push({ mode: "line" }); i += 2; continue; }
      if (c === "/" && d === "*") { blank(i); blank(i + 1); stack.push({ mode: "block" }); i += 2; continue; }
      if (/[\w$]/.test(c)) { word += c; i += 1; continue; }
      if (word) { lastWord = word; word = ""; markSig("x", i - 1); }
      if (c === "'" || c === '"') { blank(i); stack.push({ mode: "string", quote: c }); markSig("x", i); i += 1; continue; }
      if (c === "`") { blank(i); stack.push({ mode: "template" }); markSig("x", i); i += 1; continue; }
      if (c === "/") {
        // Division after a value, after "++"/"--" (i++ / 2) and after a ")"
        // that did not close an if/for/while/with header; a regex otherwise
        // (for (let n of e) /\s/.test(n) ...).
        const postfix = (prevSig === "+" && prevPrevSig === "+") || (prevSig === "-" && prevPrevSig === "-");
        if (!postfix && (prevSig === "" || "([{,;:=!&|?+-*%^~<>".includes(prevSig) || REGEX_AFTER.has(lastWord) || (prevSig === ")" && closesControlHeader(out, prevSigAt)))) {
          blank(i);
          stack.push({ mode: "regex", inClass: false });
        }
        markSig("/", i);
        i += 1;
        continue;
      }
      if (c === "{") state.braces += 1;
      else if (c === "}") {
        if (state.braces === 0 && stack.length > 1) { blank(i); stack.pop(); i += 1; continue; } // closes a template ${...}
        state.braces -= 1;
      }
      if (!/\s/.test(c)) markSig(c, i);
      i += 1;
      continue;
    }
    if (state.mode === "line") {
      if (c === "\n") { stack.pop(); i += 1; continue; }
      blank(i); i += 1; continue;
    }
    if (state.mode === "block") {
      if (c === "*" && d === "/") { blank(i); blank(i + 1); stack.pop(); i += 2; continue; }
      blank(i); i += 1; continue;
    }
    if (state.mode === "string") {
      if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
      blank(i);
      if (c === state.quote) { stack.pop(); markSig("x", i); }
      i += 1;
      continue;
    }
    if (state.mode === "regex") {
      if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
      if (c === "[") state.inClass = true;
      else if (c === "]") state.inClass = false;
      blank(i);
      if (c === "/" && !state.inClass) { stack.pop(); markSig("x", i); }
      i += 1;
      continue;
    }
    // template-literal text: blanked, but ${...} re-enters code mode
    if (c === "\\") { blank(i); blank(i + 1); i += 2; continue; }
    if (c === "`") { blank(i); stack.pop(); markSig("x", i); i += 1; continue; }
    if (c === "$" && d === "{") {
      blank(i); blank(i + 1);
      stack.push({ mode: "code", braces: 0 });
      // The interpolation is a fresh expression: the regex/division state of
      // the token before the template must not leak into it, or a leading
      // regex literal (${/"/.test(x) ...}) is misread as division.
      prevSig = "";
      prevPrevSig = "";
      lastWord = "";
      i += 2;
      continue;
    }
    blank(i); i += 1;
  }
  return out.join("");
}

// Static imports, parsed from the blanked source; the specifier string is
// blanked there, so its offsets (the /d match indices) are read back from the
// raw source. Records the LOCAL name of each binding (c for `b as c`).
function parseImports(code, raw) {
  const imports = [];
  for (const m of code.matchAll(/\bimport\s+([^;]*?)\s+from(\s+);/gd)) {
    const [start, end] = m.indices[2];
    const specifier = raw.slice(start, end).trim().replace(/^["']|["']$/g, "");
    for (const name of parseImportClause(m[1])) imports.push({ ...name, specifier });
  }
  return imports;
}

function parseImportClause(clause) {
  const names = [];
  const rest = clause.trim();
  const namespace = rest.match(/^\*\s+as\s+([A-Za-z_$][\w$]*)$/);
  if (namespace) return [{ local: namespace[1], imported: "*" }];
  const named = rest.match(/\{([\s\S]*)\}/);
  const defaultName = (named ? rest.slice(0, named.index) : rest).replace(/,\s*$/, "").trim();
  if (/^[A-Za-z_$][\w$]*$/.test(defaultName)) names.push({ local: defaultName, imported: "default" });
  if (!named) return names;
  for (const entry of named[1].split(",")) {
    const part = entry.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
    if (part) names.push({ local: part[2] ?? part[1], imported: part[1] });
  }
  return names;
}

// Index of the bracket closing the one at code[open] ("(", "[" or "{"), or
// -1. The code is blanked, so brackets inside strings and comments do not
// count.
function matchBracket(code, open) {
  const closer = { "(": ")", "[": "]", "{": "}" }[code[open]];
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === code[open]) depth += 1;
    else if (code[i] === closer) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Index just past the comment or string/regex/template literal starting at
// raw[index], or -1 when none starts there. declaratorNames skips these so a
// newline, comma or semicolon inside a literal cannot end or split a
// declaration. A "/" opens a regex only where a value cannot precede it —
// and never after "++"/"--": i++ / 2 is division.
function skipLiteral(raw, index) {
  const char = raw[index], next = raw[index + 1];
  if (char === "/" && next === "/") { const end = raw.indexOf("\n", index); return end < 0 ? raw.length : end; }
  if (char === "/" && next === "*") { const end = raw.indexOf("*/", index); return end < 0 ? raw.length : end + 2; }
  if (char === '"' || char === "'") {
    for (let i = index + 1; i < raw.length; i++) {
      if (raw[i] === "\\") i += 1;
      else if (raw[i] === char) return i + 1;
    }
    return raw.length;
  }
  if (char === "`") {
    for (let i = index + 1; i < raw.length; i++) {
      if (raw[i] === "\\") i += 1;
      else if (raw[i] === "`") return i + 1;
      else if (raw[i] === "$" && raw[i + 1] === "{") {
        let depth = 1;
        for (i += 2; depth && i < raw.length; i++) {
          const skipped = skipLiteral(raw, i);
          if (skipped > i) i = skipped - 1;
          else if (raw[i] === "{") depth += 1;
          else if (raw[i] === "}") depth -= 1;
        }
        i -= 1;
      }
    }
    return raw.length;
  }
  if (char === "/") {
    let before = index - 1;
    while (before >= 0 && /\s/.test(raw[before])) before -= 1;
    let regex = before < 0 || /[(,=:[!&|?{};+\-*%<>~^]/.test(raw[before]) || /\b(?:return|typeof|case|in|of|new|delete|void|instanceof|yield|await|throw|else|do)\s*$/.test(raw.slice(Math.max(0, before - 30), before + 1));
    if (regex && before >= 0 && (raw[before] === "+" || raw[before] === "-")) {
      let prev = before - 1;
      while (prev >= 0 && /\s/.test(raw[prev])) prev -= 1;
      if (raw[prev] === raw[before]) regex = false;
    }
    if (regex) {
      let inClass = false;
      for (let i = index + 1; i < raw.length; i++) {
        if (raw[i] === "\\") i += 1;
        else if (raw[i] === "[") inClass = true;
        else if (raw[i] === "]") inClass = false;
        else if (raw[i] === "/" && !inClass) {
          i += 1;
          while (i < raw.length && /[a-z]/i.test(raw[i])) i += 1;
          return i;
        }
      }
      return raw.length;
    }
  }
  return -1;
}

// Names bound by one const/let/var statement, read from blanked code starting
// just after the keyword. Every declarator counts: `const a = 1, b = 2`
// declares a and b. Destructuring patterns contribute their bound names.
function declaratorNames(code, raw, from) {
  const names = [];
  let depth = 0;
  let expectName = true;
  let last = ""; // last significant token character; "x" stands for any value
  for (let i = from; i < code.length; i++) {
    const skipped = skipLiteral(raw, i);
    if (skipped > i) {
      if (raw[i] !== "/" || (raw[i + 1] !== "/" && raw[i + 1] !== "*")) last = "x"; // a literal is a value; a comment is not
      i = skipped - 1;
      continue;
    }
    const c = code[i];
    if (expectName) {
      if (/\s/.test(c)) continue;
      if (c === "{" || c === "[") {
        const close = matchBracket(code, i);
        const pattern = code.slice(i + 1, close < 0 ? code.length : close);
        for (const inner of pattern.matchAll(/([A-Za-z_$][\w$]*)\s*(?![\w$:])/g)) names.push(inner[1]);
        if (close < 0) return names;
        i = close;
        expectName = false;
        last = "x";
        continue;
      }
      const m = code.slice(i).match(/^[A-Za-z_$][\w$]*/);
      if (!m) return names;
      names.push(m[0]);
      i += m[0].length - 1;
      expectName = false;
      last = "x";
      continue;
    }
    if ("([{".includes(c)) depth += 1;
    else if (")]}".includes(c)) {
      depth -= 1;
      if (depth < 0) return names; // the ")" of a for (const x of y) header
    } else if (depth <= 0 && c === ",") { expectName = true; last = ","; continue; }
    else if (depth <= 0 && c === ";") return names;
    else if (depth <= 0 && c === "\n" && !",=:?&|+-*%^~<>.!/".includes(last)) {
      // ASI: the statement ends at a newline it does not obviously continue
      // across — a trailing operator or comma (`const a = 1,\n  b = 2;`)
      // continues it, as does a next line that opens with one.
      const rest = code.slice(i + 1).match(/^\s*(\S)/);
      if (!rest || !".([:+-*/%&|?^<>,".includes(rest[1])) return names;
    }
    if (!/\s/.test(c)) last = c;
  }
  return names;
}

// Names a module exports, plus the local modules it re-exports everything
// from. Every declarator counts (`export const a = 1, b = 2` exports both);
// export default function/class name contributes its name; export { a, b as c
// } contributes the exported names (c for `b as c`); export * from "./x.js"
// is returned for the caller to resolve, depth-limited.
function parseExports(code, raw) {
  const names = new Set();
  const stars = [];
  for (const m of code.matchAll(/\bexport\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+default\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+(?:default\s+)?class\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bexport\s+(?:const|let|var)\s+/g)) {
    for (const name of declaratorNames(code, raw, m.index + m[0].length)) names.add(name);
  }
  for (const m of code.matchAll(/\bexport\s*\{([\s\S]*?)\}/g)) {
    for (const entry of m[1].split(",")) {
      const part = entry.trim().match(/^([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?$/);
      if (part) names.add(part[2] ?? part[1]);
    }
  }
  // The specifier string is blanked in `code`; its offsets (the /d match
  // indices of the whitespace run it was blanked into) are read back from
  // the raw source, exactly as parseImports does.
  for (const m of code.matchAll(/\bexport\s*\*\s*from(\s+);/gd)) {
    const [start, end] = m.indices[1];
    stars.push(raw.slice(start, end).trim().replace(/^["']|["']$/g, ""));
  }
  return { names, stars };
}

// All names a module exports, following export * from "./x.js" chains
// (depth-limited and cycle-safe) so re-exported helpers are guarded too.
function collectExports(specifier, load, depth = 0, seen = new Set()) {
  const names = new Set();
  if (depth > STAR_EXPORT_DEPTH || seen.has(specifier)) return names;
  seen.add(specifier);
  const src = load(specifier);
  if (src == null) return names;
  const { names: own, stars } = parseExports(scan(src), src);
  for (const name of own) names.add(name);
  for (const star of stars) {
    for (const name of collectExports(star, load, depth + 1, seen)) names.add(name);
  }
  return names;
}

// Names app.js declares anywhere, at any depth: function and class
// declarations, every declarator of every const/let/var statement, and the
// parameters of functions, methods, arrows and catch clauses. A bare call to
// any of these resolves locally, so it must not be reported.
function parseDeclared(code, raw) {
  const names = new Set();
  for (const m of code.matchAll(/\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\bclass\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/\b(?:const|let|var)\s+/g)) {
    for (const name of declaratorNames(code, raw, m.index + m[0].length)) names.add(name);
  }
  // Parameter lists: a "(" whose ")" is followed by "{" (a function, method
  // or catch body) or "=>" (an arrow). Control statements bind nothing.
  for (let open = 0; open < code.length; open += 1) {
    if (code[open] !== "(") continue;
    const close = matchBracket(code, open);
    if (close < 0) continue;
    const rest = code.slice(close + 1);
    if (!/^\s*\{/.test(rest) && !/^\s*=>/.test(rest)) continue;
    const before = code.slice(Math.max(0, open - 32), open).match(/([A-Za-z_$][\w$]*)\s*$/);
    if (before && /^(?:if|for|while|switch|with)$/.test(before[1])) continue;
    for (const name of paramNames(code, open, close)) names.add(name);
  }
  // Single-identifier arrow parameters: `x => ...`.
  for (const m of code.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>/g)) names.add(m[1]);
  return names;
}

// Names bound by the parameter list spanning code[open]..code[close]:
// identifiers, ...rest, and destructuring patterns ({ a, b: c } binds a and
// c). Defaults are skipped over by depth.
function paramNames(code, open, close) {
  const names = [];
  let depth = 0;
  let start = open + 1;
  const flush = (end) => {
    const text = code.slice(start, end).trim().replace(/^\.\.\./, "");
    if (text.startsWith("{") || text.startsWith("[")) {
      for (const inner of text.matchAll(/([A-Za-z_$][\w$]*)\s*(?![\w$:])/g)) names.push(inner[1]);
    } else {
      const m = text.match(/^[A-Za-z_$][\w$]*/);
      if (m) names.push(m[0]);
    }
  };
  for (let i = open; i < close; i++) {
    const c = code[i];
    if ("([{".includes(c)) depth += 1;
    else if (")]}".includes(c)) depth -= 1;
    else if (c === "," && depth === 1) { flush(i); start = i + 1; }
  }
  flush(close);
  return names;
}

// Bare uses of names a local module exports but app.js neither imports nor
// declares: calls `X(...)` and `X?.(...)`, and tagged templates X`...`.
// Method calls (x.X(...)), property accesses, function/accessor definitions
// and object-literal/class method definitions (X(...) { ... }) are not bare
// uses.
function findUnimportedCalls(code, raw, imported, declared, exportedBy) {
  const found = new Map();
  for (const name of exportedBy.keys()) {
    if (imported.has(name) || declared.has(name)) continue;
    const re = new RegExp(`(?<![\\w$.])${escapeRe(name)}(?![\\w$])`, "g");
    for (const m of code.matchAll(re)) {
      const after = code.slice(m.index + name.length);
      const call = /^\s*\(/.test(after) || /^\s*\?\.\s*\(/.test(after);
      // The backtick is blanked in `code`, so a tagged template is spotted
      // in the raw source at the same offset.
      const tagged = !call && /^\s*`/.test(raw.slice(m.index + name.length));
      if (!call && !tagged) continue;
      const before = code.slice(Math.max(0, m.index - 40), m.index);
      if (/(?:async\s+)?function\s*\*?\s*$/.test(before)) continue;
      if (/\b(?:get|set|static|async)\s*$/.test(before)) continue;
      if (call && isMethodDefinition(code, m.index, name.length)) continue;
      found.set(name, code.slice(0, m.index).split("\n").length);
      break;
    }
  }
  return [...found.entries()].map(([name, line]) => ({ name, line }));
}

// Whether the occurrence at `index` (a name directly followed by "(") is an
// object-literal or class method definition `name(...) { ... }` rather than
// a call: the parenthesised part is followed by a body and the name sits
// where a method name can — after "{", ",", ";", "}" or at a line start.
function isMethodDefinition(code, index, nameLength) {
  const open = index + nameLength + code.slice(index + nameLength).match(/^\s*/)[0].length;
  const close = matchBracket(code, open);
  if (close < 0 || !/^\s*\{/.test(code.slice(close + 1))) return false;
  const before = code.slice(0, index).match(/(\S)\s*$/);
  if (!before) return true;
  if ("{,;}".includes(before[1]) || before[1] === "}") return true;
  return /\n\s*$/.test(code.slice(0, index));
}

// Whether an imported binding is used as a binding somewhere in the body: a
// bare occurrence that is neither a property access (obj.name, obj?.name)
// nor an object-literal/destructuring key ({ name: ... }). A shorthand
// { name } or a value position ({ key: name }) IS a use.
function isUsed(body, local) {
  const re = new RegExp(`(?<![\\w$.])${escapeRe(local)}(?![\\w$])`, "g");
  for (const m of body.matchAll(re)) {
    const after = body.slice(m.index + m[0].length).match(/^\s*(\S)/);
    const before = body.slice(0, m.index).match(/(\S)\s*$/);
    if (after && before && after[1] === ":" && (before[1] === "{" || before[1] === ",")) continue;
    return true;
  }
  return false;
}

// Every way app.js's import block can rot, so the same check can be exercised
// against doctored sources below. A guard that cannot fail is not a guard.
// listModules must return every local module specifier ("./x.js"): the
// exports of modules app.js does not import from are guarded too, so the
// report can name the module that exports a missing name.
function importProblems(appSrc, loadModule, allowlist, listModules) {
  const code = scan(appSrc);
  const imports = parseImports(code, appSrc);
  const imported = new Set(imports.map((entry) => entry.local));
  const declared = parseDeclared(code, appSrc);
  const exportedBy = new Map();
  const problems = [];
  const importedSpecifiers = new Set(imports.map((entry) => entry.specifier).filter(isLocalJs));
  const allSpecifiers = [...new Set([...listModules(), ...importedSpecifiers])].sort();
  for (const specifier of allSpecifiers) {
    const src = loadModule(specifier);
    if (src == null) {
      if (importedSpecifiers.has(specifier)) problems.push(`imports from ${specifier}, which does not exist`);
      continue;
    }
    for (const name of collectExports(specifier, loadModule)) {
      if (!exportedBy.has(name)) exportedBy.set(name, new Set());
      exportedBy.get(name).add(specifier);
    }
  }
  for (const { name, line } of findUnimportedCalls(code, appSrc, imported, declared, exportedBy)) {
    problems.push(`calls ${name}() at line ${line} but neither imports nor declares it (exported by ${[...exportedBy.get(name)].join(", ")}); the page would throw ReferenceError`);
  }
  const body = code.replace(/\bimport\s+[^;]*;/g, (statement) => statement.replace(/[^\n]/g, " "));
  for (const { local, specifier } of imports) {
    if (allowlist.includes(local)) continue;
    if (!isUsed(body, local)) {
      problems.push(`imports ${local} from ${specifier} but never uses it; remove the import or add it to DEAD_IMPORT_ALLOWLIST`);
    }
  }
  return problems.sort();
}

const loadModule = (specifier) => {
  const path = join("src", "js", specifier);
  return existsSync(join(root, path)) ? read(path) : null;
};

// Every module in src/js, as "./name.js" specifiers: a call to a helper from
// a module app.js imports nothing from must still be caught.
const listModules = () => readdirSync(join(root, "src", "js"))
  .filter((file) => file.endsWith(".js"))
  .map((file) => `./${file}`);

test("app.js imports every exported helper it calls and uses every name it imports", () => {
  const appSrc = read("src/js/app.js");
  const imports = parseImports(scan(appSrc), appSrc);
  assert.ok(imports.length > 50, `fixture: expected app.js's import block, found ${imports.length} imported names`);
  const localModules = new Set(imports.map((entry) => entry.specifier).filter(isLocalJs));
  assert.ok(localModules.size > 20, `fixture: expected app.js to import from many local modules, found ${localModules.size}`);
  assert.ok(listModules().length >= localModules.size, "fixture: src/js must hold at least the modules app.js imports from");
  assert.deepEqual(importProblems(appSrc, loadModule, DEAD_IMPORT_ALLOWLIST, listModules), []);
});

test("the import guard detects its own failure modes", () => {
  const miniApp = [
    "import {",
    "  usedFn,",
    "  aliased as localFn,",
    "  tplFn,",
    '} from "./mod.js";',
    'import { deadFn } from "./mod.js";',
    "",
    "function declaredFn() {}",
    'const note = "missingFn() inside a string is not a call";',
    "// missingFn(); inside a comment is not a call",
    "usedFn();",
    "localFn();",
    "declaredFn();",
    "obj.missingFn();",
    "missingFn();",
    "const html = `label ${tplFn()} tail`;",
    "",
  ].join("\n");
  const miniMod = [
    "export function usedFn() {}",
    "export function aliased() {}",
    "export function tplFn() {}",
    "export function deadFn() {}",
    "export function missingFn() {}",
    "",
  ].join("\n");
  const load = (specifier) => (specifier === "./mod.js" ? miniMod : null);
  const problems = importProblems(miniApp, load, [], () => ["./mod.js"]);
  assert.ok(
    problems.some((problem) => problem.includes("missingFn") && problem.includes("line 15") && problem.includes("./mod.js")),
    `a bare call to an exported but un-imported name must be reported with its first line: ${problems}`,
  );
  assert.ok(
    problems.some((problem) => problem.includes("deadFn") && problem.includes("never uses")),
    "an import that is never used must be reported",
  );
  for (const safe of ["usedFn", "localFn", "aliased", "tplFn", "declaredFn"]) {
    assert.ok(!problems.some((problem) => problem.includes(safe)), `${safe} is imported, declared, aliased or method-called and must not be reported`);
  }
  const allowed = importProblems(miniApp, load, ["deadFn"], () => ["./mod.js"]);
  assert.ok(!allowed.some((problem) => problem.includes("deadFn")), "an allowlisted dead import must pass");
  assert.ok(allowed.some((problem) => problem.includes("missingFn")), "the allowlist must not hide missing imports");
});

test("the guard parses every export and declaration form and scans tricky code", () => {
  const app = [
    'import { first, cbish, deadish, keyish } from "./mod.js";',
    "",
    "first();",
    "const f = cbish;",
    "second();",
    "defaulted();",
    "starred();",
    "strayFn();",
    "optFn?.();",
    "tagFn`x`;",
    "trickyFn();",
    "",
    "const a = 1, plain = () => {};",
    "plain();",
    "function outer() {",
    "  function nestedish() { return 1; }",
    "  return nestedish();",
    "}",
    "function takesCb(paramish) {",
    "  paramish();",
    "}",
    "try {",
    "  first();",
    "} catch (catchish) {",
    "  catchish();",
    "}",
    "const handler = {",
    "  methodish(e) { return e; },",
    "};",
    "class Widget {",
    "  klassy() {}",
    "}",
    "const arrow = (arrowish) => arrowish();",
    "obj.propish();",
    "const opts = { keyish: 1 };",
    "obj.keyish;",
    'const s = `${/"/.test(first) ? "y" : "n"}`;',
    "if (first) /methodish()/.test(opts);",
    "let i = 0;",
    "i++ / 2;",
    "strayToo();",
    "",
  ].join("\n");
  const mod = [
    "export const first = () => {}, second = () => {};",
    "export default function defaulted() {}",
    "export function plain() {}",
    "export function nestedish() {}",
    "export function paramish() {}",
    "export function catchish() {}",
    "export function methodish() {}",
    "export function klassy() {}",
    "export function arrowish() {}",
    "export function propish() {}",
    "export function cbish() {}",
    "export function deadish() {}",
    "export function keyish() {}",
    'export * from "./inner.js";',
    "",
  ].join("\n");
  const inner = "export function starred() {}\n";
  const unused = [
    "export function strayFn() {}",
    "export function optFn() {}",
    "export function tagFn() {}",
    "export function trickyFn() {}",
    "export function strayToo() {}",
    "",
  ].join("\n");
  const sources = new Map([["./mod.js", mod], ["./inner.js", inner], ["./unused.js", unused]]);
  const load = (specifier) => sources.get(specifier) ?? null;
  const problems = importProblems(app, load, [], () => [...sources.keys()]);
  // Un-imported calls must be reported, however the name was exported
  // (second declarator, default function, star re-export) and whichever
  // call form app.js used — including exports of modules app.js does not
  // import from at all, and calls the tricky scanner lines must not hide.
  for (const missing of ["second", "defaulted", "starred", "strayFn", "optFn", "tagFn", "trickyFn", "strayToo"]) {
    assert.ok(
      problems.some((problem) => problem.includes(`calls ${missing}()`)),
      `${missing} is exported but neither imported nor declared and must be reported: ${problems}`,
    );
  }
  assert.ok(
    problems.some((problem) => problem.includes("strayFn") && problem.includes("./unused.js")),
    `the report names the module that exports the missing name: ${problems}`,
  );
  // A property access or an object key named like an import is not a use.
  for (const dead of ["deadish", "keyish"]) {
    assert.ok(
      problems.some((problem) => problem.includes(dead) && problem.includes("never uses")),
      `${dead} is never used as a binding and must be reported: ${problems}`,
    );
  }
  // Imported-and-used names (cbish is used as a value, not called), names
  // declared anywhere in app.js (a second declarator, a nested function,
  // parameters, a catch parameter), method definitions and property
  // accesses must not be reported.
  for (const safe of ["first", "cbish", "plain", "nestedish", "paramish", "catchish", "methodish", "klassy", "arrowish", "propish"]) {
    assert.ok(!problems.some((problem) => problem.includes(safe)), `${safe} must not be reported: ${problems}`);
  }
});
