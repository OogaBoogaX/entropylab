import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { i18nMarkupTokens, repositoryUiSourceFiles } from "./i18n-sync.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const i18nRuntimeAttribute = "data-runtime-owned";

function spaces(value) {
  return value.replace(/[^\r\n]/g, " ");
}

function maskNonMarkup(source) {
  return source
    .replace(/<!--[\s\S]*?-->/g, spaces)
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, spaces)
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, spaces);
}

function decodeText(value) {
  return value.replace(/&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));/gi, (entity, decimal, hex, named) => {
    if (decimal) return String.fromCodePoint(Number(decimal));
    if (hex) return String.fromCodePoint(Number.parseInt(hex, 16));
    return ({ amp: "&", quot: '"', apos: "'", lt: "<", gt: ">", nbsp: " " })[named.toLowerCase()] ?? entity;
  });
}

function normalized(value) {
  return decodeText(value).replace(/\s+/g, " ").trim();
}

function identity(token) {
  const id = token.attributes.get("id")?.value;
  if (id) return `${token.name}#${id}`;
  const value = token.attributes.get("value")?.value;
  if (value) return `${token.name}[value=${value}]`;
  const classes = token.attributes.get("class")?.value?.trim().split(/\s+/).filter(Boolean);
  return `${token.name}${classes?.length ? `.${classes[0]}` : ""}`;
}

function pathOf(stack, token) {
  return [...stack.slice(-2).map((frame) => frame.identity), identity(token)].join("/");
}

export function collectUnwiredMarkup(fragment, label = "markup", { ignoredIds = [] } = {}) {
  const source = maskNonMarkup(fragment);
  const tokens = i18nMarkupTokens(source);
  const ignoredIdSet = new Set(ignoredIds);
  const stack = [];
  const entries = [];
  let cursor = 0;

  function recordText(value) {
    if (!stack.length) return;
    const text = normalized(value);
    if (!text) return;
    const runtimeOwner = stack.findLast((frame) => frame.runtime);
    if (runtimeOwner) {
      entries.push(`${label}:${stack.map((frame) => frame.identity).slice(-3).join("/")}: ${i18nRuntimeAttribute} boundary ${runtimeOwner.identity} contains source text`);
      return;
    }
    if (stack.some((frame) => frame.covered || frame.ignored)) return;
    entries.push(`${label}:${stack.map((frame) => frame.identity).slice(-3).join("/")}:text:${text}`);
  }

  for (const token of tokens) {
    recordText(source.slice(cursor, token.start));
    cursor = token.end;
    if (token.closing) {
      for (let index = stack.length - 1; index >= 0; index -= 1) {
        const frame = stack.pop();
        if (frame.name === token.name) break;
      }
      continue;
    }

    const runtimeOwner = stack.findLast((frame) => frame.runtime);
    const ancestorReplaced = stack.some((frame) => frame.rich || frame.ignored || frame.runtime);
    const tokenPath = pathOf(stack, token);
    if (runtimeOwner) entries.push(`${label}:${tokenPath}: ${i18nRuntimeAttribute} boundary ${runtimeOwner.identity} contains static markup`);
    if (!ancestorReplaced) {
      for (const [attribute, marker] of [["aria-label", "data-i18n-aria"], ["aria-placeholder", "data-i18n-aria-placeholder"], ["placeholder", "data-i18n-placeholder"], ["title", "data-i18n-title"], ["alt", "data-i18n-alt"], ["data-copy-label", "data-i18n-copy-label"], ["data-copied-label", "data-i18n-copied-label"]]) {
        const value = normalized(token.attributes.get(attribute)?.value ?? "");
        if (value && !token.attributes.has(marker)) entries.push(`${label}:${tokenPath}:@${attribute}:${value}`);
      }
    }

    const runtime = token.attributes.has(i18nRuntimeAttribute);
    if (runtime && !token.attributes.get("id")?.value) entries.push(`${label}:${tokenPath}: ${i18nRuntimeAttribute} boundary needs an id`);
    if (runtime && [...token.attributes.keys()].some((name) => name === "data-i18n" || name.startsWith("data-i18n-"))) {
      entries.push(`${label}:${tokenPath}: ${i18nRuntimeAttribute} boundary cannot also carry a translation marker`);
    }
    if (runtime && token.selfClosing) entries.push(`${label}:${tokenPath}: ${i18nRuntimeAttribute} boundary cannot be self-closing`);

    if (!token.selfClosing) {
      const rich = token.attributes.has("data-i18n-html");
      stack.push({
        name: token.name,
        identity: identity(token),
        rich,
        covered: rich || token.attributes.has("data-i18n"),
        runtime,
        ignored: ignoredIdSet.has(token.attributes.get("id")?.value) || token.name === "svg" || token.name === "script" || token.name === "style",
      });
    }
  }
  recordText(source.slice(cursor));
  return entries.sort();
}

function templateEnd(source, start) {
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "$" && source[index + 1] === "{") {
      let slashes = 0;
      for (let before = index - 1; before >= start && source[before] === "\\"; before -= 1) slashes += 1;
      if (slashes % 2 === 0) return { interpolation: index };
    }
    if (source[index] !== "`") continue;
    let slashes = 0;
    for (let before = index - 1; before >= start && source[before] === "\\"; before -= 1) slashes += 1;
    if (slashes % 2 === 0) return { end: index };
  }
  return {};
}

export function collectAnnotatedShellFragments(source, label) {
  const marker = "/* i18n-static-shell */";
  const fragments = [];
  let cursor = 0;
  while ((cursor = source.indexOf(marker, cursor)) !== -1) {
    const assignmentStart = cursor + marker.length;
    const templateStart = source.indexOf("`", assignmentStart);
    if (templateStart === -1 || !/^\s*[A-Za-z_$][\w$]*\.(?:innerHTML|outerHTML)\s*=\s*$/.test(source.slice(assignmentStart, templateStart))) {
      throw new Error(`${label}: ${marker} must immediately annotate an element HTML template assignment.`);
    }
    const boundary = templateEnd(source, templateStart + 1);
    if (boundary.interpolation !== undefined) throw new Error(`${label}: annotated static-shell template cannot contain interpolation.`);
    const end = boundary.end;
    if (end === undefined) throw new Error(`${label}: annotated static-shell template is unterminated.`);
    fragments.push({ label: `${label}#static-shell-${fragments.length + 1}`, markup: source.slice(templateStart + 1, end) });
    cursor = end + 1;
  }
  return fragments;
}

// A static HTML literal is a shell whether or not its author remembered
// the annotation. Require the source-local marker so a new panel cannot bypass
// the structural wiring gate merely by living in a new file. Interpolated
// renderers remain runtime output and are covered by their behavioral tests.
export function collectUnannotatedStaticShells(source, label) {
  const entries = [];
  const assignment = /\.(innerHTML|outerHTML)\s*=\s*\(*\s*([`"'])/g;
  for (const match of source.matchAll(assignment)) {
    const location = `${label}:${source.slice(0, match.index).split(/\r?\n/).length}`;
    const sink = match[1];
    const quote = match[2];
    const start = match.index + match[0].length;
    let end;
    if (quote === "`") {
      const boundary = templateEnd(source, start);
      if (boundary.interpolation !== undefined) continue;
      end = boundary.end;
    } else {
      for (let index = start; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === quote) {
          end = index;
          break;
        }
      }
    }
    if (end === undefined) {
      entries.push(`${location}: unterminated static ${sink} literal`);
      continue;
    }
    if (!normalized(source.slice(start, end))) continue;
    const before = source.slice(0, match.index);
    if (!/\/\* i18n-static-shell \*\/\s*[A-Za-z_$][\w$]*$/.test(before)) {
      entries.push(`${location}: static ${sink} literal needs an immediate /* i18n-static-shell */ annotation`);
    }
  }
  const trailingLiteral = /\.(innerHTML|outerHTML)\s*=\s*(?!\(*\s*[`"'])[^;\r\n]+?\+\s*\(*\s*([`"'])/g;
  for (const match of source.matchAll(trailingLiteral)) {
    const location = `${label}:${source.slice(0, match.index).split(/\r?\n/).length}`;
    const quote = match[2];
    const start = match.index + match[0].length;
    let end;
    if (quote === "`") {
      const boundary = templateEnd(source, start);
      if (boundary.interpolation !== undefined) continue;
      end = boundary.end;
    } else {
      for (let index = start; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === quote) {
          end = index;
          break;
        }
      }
    }
    if (end === undefined) entries.push(`${location}: unterminated static ${match[1]} concatenation literal`);
    else if (normalized(source.slice(start, end))) entries.push(`${location}: static ${match[1]} text after a dynamic concatenation requires behavioral translation coverage`);
  }
  const adjacent = /\.insertAdjacentHTML\s*\(\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*,\s*\(*\s*([`"'])/g;
  for (const match of source.matchAll(adjacent)) {
    const location = `${label}:${source.slice(0, match.index).split(/\r?\n/).length}`;
    const quote = match[1];
    const start = match.index + match[0].length;
    let end;
    if (quote === "`") {
      const boundary = templateEnd(source, start);
      if (boundary.interpolation !== undefined) continue;
      end = boundary.end;
    } else {
      for (let index = start; index < source.length; index += 1) {
        if (source[index] === "\\") index += 1;
        else if (source[index] === quote) {
          end = index;
          break;
        }
      }
    }
    if (end === undefined) {
      entries.push(`${location}: unterminated static insertAdjacentHTML literal`);
    } else if (normalized(source.slice(start, end))) {
      entries.push(`${location}: static insertAdjacentHTML literals are forbidden; use translated DOM text or an annotated HTML assignment`);
    }
  }
  return entries;
}

export function collectRepositoryUnwired() {
  const entries = [];
  let annotatedShells = 0;
  for (const file of repositoryUiSourceFiles()) {
    const source = readFileSync(join(root, file), "utf8");
    if (extname(file) === ".js") entries.push(...collectUnannotatedStaticShells(source, file));
    for (const fragment of collectAnnotatedShellFragments(source, file)) {
      annotatedShells += 1;
      entries.push(...collectUnwiredMarkup(fragment.markup, fragment.label));
    }
    if (extname(file) === ".html") {
      const bodyOpen = /<body\b[^>]*>/i.exec(source);
      const bodyClose = source.toLowerCase().lastIndexOf("</body>");
      if (!bodyOpen || bodyClose === -1) throw new Error(`${file} has no complete body element.`);
      // #btc-calc is the no-flash source copy replaced by the annotated
      // application shell. Scanning both would report every element twice.
      entries.push(...collectUnwiredMarkup(source.slice(bodyOpen.index + bodyOpen[0].length, bodyClose), file, { ignoredIds: ["btc-calc"] }));
      continue;
    }
  }
  if (!annotatedShells) throw new Error("No /* i18n-static-shell */ source region was found.");
  return entries.sort();
}

export function runI18nWiring() {
  const current = collectRepositoryUnwired();
  if (!current.length) {
    console.log("All static-shell UI text is wired.");
    return;
  }
  for (const entry of current) console.error(`Unwired text: ${entry}`);
  console.error("Wire every current English string through en.json; no hardcoded static-shell text is allowed.");
  process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) runI18nWiring();
