import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { i18nMarkupTokens } from "./i18n-sync.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const baselinePath = join(root, "scripts/i18n-unwired.json");

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
    if (!stack.length || stack.some((frame) => frame.covered || frame.ignored)) return;
    const text = normalized(value);
    if (!text) return;
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

    const ancestorReplaced = stack.some((frame) => frame.rich || frame.ignored);
    const tokenPath = pathOf(stack, token);
    if (!ancestorReplaced) {
      for (const [attribute, marker] of [["aria-label", "data-i18n-aria"], ["placeholder", "data-i18n-placeholder"], ["title", "data-i18n-title"], ["alt", "data-i18n-alt"]]) {
        const value = normalized(token.attributes.get(attribute)?.value ?? "");
        if (value && !token.attributes.has(marker)) entries.push(`${label}:${tokenPath}:@${attribute}:${value}`);
      }
    }

    if (!token.selfClosing) {
      const rich = token.attributes.has("data-i18n-html");
      stack.push({
        name: token.name,
        identity: identity(token),
        rich,
        covered: rich || token.attributes.has("data-i18n"),
        ignored: ignoredIdSet.has(token.attributes.get("id")?.value) || token.name === "svg" || token.name === "script" || token.name === "style",
      });
    }
  }
  recordText(source.slice(cursor));
  return entries.sort();
}

function templateEnd(source, start) {
  for (let index = start; index < source.length; index += 1) {
    if (source[index] !== "`") continue;
    let slashes = 0;
    for (let before = index - 1; before >= start && source[before] === "\\"; before -= 1) slashes += 1;
    if (slashes % 2 === 0) return index;
  }
  return -1;
}

export function collectRepositoryUnwired() {
  const indexSource = readFileSync(join(root, "src/index.html"), "utf8");
  const bodyOpen = /<body\b[^>]*>/i.exec(indexSource);
  const bodyClose = indexSource.toLowerCase().lastIndexOf("</body>");
  if (!bodyOpen || bodyClose === -1) throw new Error("src/index.html has no complete body element.");
  const bodyStart = bodyOpen.index + bodyOpen[0].length;

  const appSource = readFileSync(join(root, "src/js/app.js"), "utf8");
  const marker = "hodlRootEl.innerHTML = `";
  const appStart = appSource.indexOf(marker);
  if (appStart === -1) throw new Error("src/js/app.js has no root HTML template.");
  const templateStart = appStart + marker.length;
  const appEnd = templateEnd(appSource, templateStart);
  if (appEnd === -1) throw new Error("src/js/app.js has an unterminated root HTML template.");

  return [
    // The source template's #btc-calc is a no-flash placeholder replaced by
    // app.js. The runtime root template below is the copy that must be wired.
    ...collectUnwiredMarkup(indexSource.slice(bodyStart, bodyClose), "src/index.html", { ignoredIds: ["btc-calc"] }),
    ...collectUnwiredMarkup(appSource.slice(templateStart, appEnd), "src/js/app.js#root-template"),
  ].sort();
}

export function runI18nWiring(argv = process.argv.slice(2)) {
  const current = collectRepositoryUnwired();
  if (argv.includes("--write-baseline")) {
    writeFileSync(baselinePath, `${JSON.stringify(current, null, 2)}\n`);
    console.log(`Recorded ${current.length} legacy unwired strings.`);
    return;
  }
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
  if (JSON.stringify(current) === JSON.stringify(baseline)) {
    console.log(`No new hardcoded UI text (${current.length} legacy entries remain for Step 3).`);
    return;
  }
  const expected = new Set(baseline);
  const actual = new Set(current);
  for (const entry of current) if (!expected.has(entry)) console.error(`New unwired text: ${entry}`);
  for (const entry of baseline) if (!actual.has(entry)) console.error(`Baseline entry changed or was wired: ${entry}`);
  console.error("Wire new English through en.json, or regenerate the baseline only when intentionally shrinking the Step 3 inventory.");
  process.exitCode = 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) runI18nWiring();
