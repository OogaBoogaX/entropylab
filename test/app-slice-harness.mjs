// Loads named top-level functions from src/js/app.js as a real ES module, for
// tests that must run the app's own code rather than a copy of it.
//
// app.js boots the whole page on import, so it cannot be imported directly.
// Instead this assembles a module from the requested functions plus every
// top-level hodl* function or declaration they reach, and app.js's own import
// statements for the names that closure uses, pointed at src/js/. Nothing is
// re-implemented: every line in the generated module is app.js source. A name
// passed in `stubs` is supplied by the test instead of taken from app.js.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const app = readFileSync(join(root, "src/js/app.js"), "utf8");


// Whether the ")" at `index` closes the header of an if, for, while or with:
// a statement starts after it, so a "/" there opens a regex, not a division
// (for (let n of e) /\s/.test(n) ...).
function closesControlHeader(index) {
  if (app[index] !== ")") return false;
  let depth = 0, at = index;
  for (; at >= 0; at--) {
    if (app[at] === ")") depth++;
    else if (app[at] === "(" && --depth === 0) break;
  }
  let word = at - 1;
  while (word >= 0 && /\s/.test(app[word])) word--;
  return /\b(?:if|for|while|with)$/.test(app.slice(Math.max(0, word - 5), word + 1));
}

// Index just past the literal or comment starting at `index`, or -1 when none
// starts there. Braces inside strings, templates, regexes and comments must
// not count toward a declaration's extent.
function skipLiteral(index) {
  const char = app[index], next = app[index + 1];
  if (char === "/" && next === "/") return app.indexOf("\n", index);
  if (char === "/" && next === "*") return app.indexOf("*/", index) + 2;
  if (char === '"' || char === "'") {
    for (let i = index + 1; i < app.length; i++) {
      if (app[i] === "\\") i++;
      else if (app[i] === char) return i + 1;
    }
  }
  if (char === "`") {
    for (let i = index + 1; i < app.length; i++) {
      if (app[i] === "\\") i++;
      else if (app[i] === "`") return i + 1;
      else if (app[i] === "$" && app[i + 1] === "{") {
        let depth = 1;
        for (i += 2; depth; i++) {
          const skipped = skipLiteral(i);
          if (skipped > i) i = skipped - 1;
          else if (app[i] === "{") depth++;
          else if (app[i] === "}") depth--;
        }
        i--;
      }
    }
  }
  if (char === "/") {
    // A regex literal follows an operator or an opening bracket, never a value.
    let before = index - 1;
    while (before >= 0 && /\s/.test(app[before])) before--;
    if (before < 0 || /[(,=:[!&|?{};+\-*%<>~^]/.test(app[before]) || /\b(?:return|typeof|case|in|of)$/.test(app.slice(Math.max(0, before - 6), before + 1)) || closesControlHeader(before)) {
      let inClass = false;
      for (let i = index + 1; i < app.length; i++) {
        if (app[i] === "\\") i++;
        else if (app[i] === "[") inClass = true;
        else if (app[i] === "]") inClass = false;
        else if (app[i] === "/" && !inClass) {
          i++;
          while (/[a-z]/i.test(app[i])) i++;
          return i;
        }
      }
    }
  }
  return -1;
}

// Index of a function body's opening brace. The parameter list ends at the
// first ")" at depth 0 (literals inside default parameters are skipped); the
// body opens after optional whitespace at "{" — written as ") {" in most of
// app.js but "){" in a few declarations.
function functionBodyOpen(start) {
  let depth = 0;
  for (let index = app.indexOf("(", start); index < app.length; index++) {
    const skipped = skipLiteral(index);
    if (skipped > index) {
      index = skipped - 1;
      continue;
    }
    const char = app[index];
    if (char === "(") depth++;
    else if (char === ")" && --depth === 0) {
      let brace = index + 1;
      while (/\s/.test(app[brace])) brace++;
      if (app[brace] !== "{") throw new Error(`function at ${start} has no braced body`);
      return brace;
    }
  }
  throw new Error(`unterminated parameter list at ${start}`);
}

// A declaration's full source: a function through its closing brace, a
// variable statement through its terminating semicolon or line.
function sourceAt(kind, start) {
  let depth = 0, opened = false;
  for (let index = kind === "function" ? functionBodyOpen(start) : start; index < app.length; index++) {
    const skipped = skipLiteral(index);
    if (skipped > index) {
      index = skipped - 1;
      opened = opened || kind === "variable";
      continue;
    }
    const char = app[index];
    if ("{[(".includes(char)) {
      depth++;
      opened = true;
    } else if ("}])".includes(char)) {
      depth--;
      if (kind === "function" && opened && depth === 0) return app.slice(start, index + 1);
    // A line ending in a comma continues the statement (var a = 1,\n  b = 2).
    } else if (kind === "variable" && depth === 0 && (char === ";" || (char === "\n" && opened && !/,\s*$/.test(app.slice(start, index))))) return app.slice(start, index + (char === ";" ? 1 : 0));
  }
  throw new Error(`unterminated declaration at ${start}`);
}

// Top-level declarations, by name. One variable statement may declare several
// names (var a = 1, b = 2); each name maps to that statement for the
// reference walk, but emission takes only the needed declarators (see
// statementDeclarators below): app.js packs data declarations and load-time
// DOM bindings into single var statements (var hodlTargetWordCount = 24, …,
// hodlOutEl = hodlElement("#out")), and executing the whole statement in a
// headless slice throws on the missing document.
const declarations = new Map();
// Statement start offset → its declarators in source order, so the emitted
// slice keeps exactly the declarators the closure reaches.
const statementDeclarators = new Map();
for (const match of app.matchAll(/^(?:async )?function (hodl\w+)\(/gm)) declarations.set(match[1], { kind: "function", start: match.index });
for (const match of app.matchAll(/^(?:const|let|var) (?=hodl)/gm)) {
  const keyword = match[0].trim();
  const statement = sourceAt("variable", match.index);
  // Declarator names sit at bracket depth 0, after the keyword or a comma.
  let depth = 0, expectName = true, declaratorStart = -1, declaratorName = null;
  const declarators = [];
  const closeDeclarator = (end) => {
    if (declaratorName === null) return;
    const text = statement.slice(declaratorStart, end).replace(/[\s;]+$/, "");
    if (!declarations.has(declaratorName)) declarations.set(declaratorName, { kind: "variable", start: match.index, declarator: text });
    declarators.push({ name: declaratorName, text });
    declaratorName = null;
  };
  for (let i = match[0].length; i <= statement.length; i++) {
    const skipped = i < statement.length ? skipLiteral(match.index + i) : -1;
    if (skipped > match.index + i) {
      i = skipped - match.index - 1;
      continue;
    }
    const char = statement[i]; // undefined at the end closes the last declarator
    if (char === undefined || (depth === 0 && char === ",")) {
      closeDeclarator(i);
      expectName = true;
      continue;
    }
    if ("{[(".includes(char)) depth++;
    else if ("}])".includes(char)) depth--;
    else if (depth === 0 && expectName && /[A-Za-z_$]/.test(char)) {
      declaratorName = statement.slice(i).match(/^[\w$]+/)[0];
      declaratorStart = i;
      expectName = false;
      i += declaratorName.length - 1;
    }
  }
  statementDeclarators.set(match.index, { keyword, declarators });
}
// The reference walk sees a declaration's own extent only: a whole function,
// but for a variable just its declarator — sibling declarators in a shared
// var statement are not references (var a = 1, b = 2 does not make a need b).
const declarationSource = (name) => {
  const declaration = declarations.get(name);
  return declaration.kind === "function" ? sourceAt("function", declaration.start) : declaration.declarator;
};

// Top-level statements that fill a declared variable at load, such as a loop
// pushing rows into a lookup table. One travels with any variable it names.
function statementAt(start) {
  let depth = 0;
  for (let index = start; index < app.length; index++) {
    const skipped = skipLiteral(index);
    if (skipped > index) {
      index = skipped - 1;
      continue;
    }
    const char = app[index];
    if ("{[(".includes(char)) depth++;
    else if ("}])".includes(char)) depth--;
    else if (depth === 0 && char === ";") return app.slice(start, index + 1);
    else if (depth === 0 && char === "\n" && /[})]\s*$/.test(app.slice(start, index)) && /^\S/.test(app.slice(index + 1))) return app.slice(start, index);
  }
  throw new Error(`unterminated statement at ${start}`);
}
const loadStatements = [...app.matchAll(/^(?:for|if|while) \(|^hodl\w+(?:\.\w+\(|\[| = )/gm)].map((match) => {
  const source = statementAt(match.index);
  return { start: match.index, source, names: new Set(source.match(/\bhodl\w+/g)) };
});

// app.js's import statements, keyed by each local name they bind.
const imports = new Map();
for (const match of app.matchAll(/^import \{([^}]*)\} from "\.\/([\w.-]+)";$/gm)) {
  const statement = match[0].replace(`"./${match[2]}"`, JSON.stringify(pathToFileURL(join(root, "src/js", match[2])).href));
  for (const binding of match[1].split(",").map((part) => part.trim()).filter(Boolean)) imports.set(binding.split(/\s+as\s+/).pop(), statement);
}

let loads = 0;
export async function loadAppFunctions(names, { stubs = {}, settable = [] } = {}) {
  const included = new Set(), queue = [...names];
  while (queue.length) {
    const name = queue.pop();
    if (included.has(name) || name in stubs || !declarations.has(name)) continue;
    included.add(name);
    for (const reference of declarationSource(name).matchAll(/\bhodl\w+/g)) queue.push(reference[0]);
  }
  // Pull in the load-time statements that fill an included variable, and
  // whatever they reference in turn, until nothing new is reached.
  const statements = new Set();
  for (let grew = true; grew; ) {
    grew = false;
    for (const statement of loadStatements) {
      if (statements.has(statement) || ![...statement.names].some((name) => included.has(name) && declarations.get(name).kind === "variable")) continue;
      statements.add(statement);
      grew = true;
      queue.push(...statement.names);
      while (queue.length) {
        const name = queue.pop();
        if (included.has(name) || name in stubs || !declarations.has(name)) continue;
        included.add(name);
        for (const reference of declarationSource(name).matchAll(/\bhodl\w+/g)) queue.push(reference[0]);
      }
    }
  }
  for (const name of names) if (!included.has(name)) throw new Error(`app.js has no top-level ${name}`);
  // Declarations in source order, so top-level constants are initialized
  // before anything that reads them at load. A variable statement emits only
  // the declarators the closure reached, never its untouched siblings.
  const starts = [...new Set([...included].map((name) => declarations.get(name).start))].sort((a, b) => a - b);
  const bodies = [
    ...starts.map((start) => {
      if (app.startsWith("function", start) || app.startsWith("async function", start)) return { start, source: sourceAt("function", start) };
      const { keyword, declarators } = statementDeclarators.get(start);
      const needed = declarators.filter((declarator) => included.has(declarator.name));
      return { start, source: `${keyword} ${needed.map((declarator) => declarator.text).join(", ")};` };
    }),
    ...statements,
  ].sort((a, b) => a.start - b.start).map((entry) => entry.source);
  const words = new Set(bodies.join("\n").match(/\b[A-Za-z_$][\w$]*\b/g));
  const importStatements = new Set([...imports].filter(([local]) => words.has(local) && !(local in stubs)).map(([, statement]) => statement));
  const source = [
    ...importStatements,
    // app.js reads this esbuild define at module scope (scripts/build.mjs
    // substitutes it; production gets false). A slice that reaches one of
    // the guarded statements through its closure must see the same value,
    // not a ReferenceError.
    "const __ENTROPYLAB_TEST_HOOKS__ = false;",
    ...Object.keys(stubs).map((name) => `const ${name} = globalThis.__appSliceStubs[${JSON.stringify(name)}];`),
    ...bodies,
    `export { ${names.join(", ")} };`,
    // A test can set a top-level variable the loaded functions read (the
    // reveal toggle, say) through __set.name(value), without stubbing it out.
    `export const __set = { ${settable.map((name) => `${name}: (value) => { ${name} = value; }`).join(", ")} };`,
  ].join("\n");
  globalThis.__appSliceStubs = stubs;
  // Outside test/, so suites that list that directory never see it.
  const directory = mkdtempSync(join(tmpdir(), "entropylab-app-slice-")), modulePath = join(directory, `slice-${loads++}.mjs`);
  writeFileSync(modulePath, source);
  try {
    return await import(pathToFileURL(modulePath).href);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
