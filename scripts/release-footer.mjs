#!/usr/bin/env node
// The build footer of a built entropylab.html, as the release checks read it
// (#1406): src/shell.html renders it as
//   <span class="page-footer-build">v{{VERSION}} · commit <code>{{COMMIT_SHORT}}</code> …
// pages-release.yml and release-assets.yml compare the version with the
// release tag and the commit with the tag's history. One parser for both, so
// the two checks cannot drift apart, and a test pins it to the real markup.
// The built page carries the footer more than once (the build copies the
// shell); every copy must name the same version and commit.
//
//   node scripts/release-footer.mjs <entropylab.html>
// prints "<version> <short-commit>" and exits 0, or names the problem on
// stderr and exits 1. No dependencies; reads only the given file.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const FOOTER = /<span class="page-footer-build">v([0-9A-Za-z.+-]+) · commit <code>([0-9a-f]{7,40})<\/code>/g;
// Every use of the footer class that is not a CSS or JS selector (".page-
// footer-build"): each must be a copy FOOTER reads. One with another
// attribute or an uppercase commit was skipped, not checked (red-team sweep
// 0eed735, release-footer #1). The class is counted as a token rather than
// inside a parsed tag, so no element name or quoted ">" hides one (#1477
// gate: Kimi, DeepSeek).
const FOOTER_CLASS = /(?<![\w.-])page-footer-build(?![\w-])/g;
// Numeric character references are decoded before the count, as the browser
// decodes them: a class spelled page-footer-buil&#100; is a footer copy too
// (#1477 r2 gate, Kimi).
const decodeCharRefs = (text) => text.replace(/&#(?:x([0-9a-f]+)|(\d+));?/gi, (whole, hex, dec) => {
  const code = hex ? Number.parseInt(hex, 16) : Number(dec);
  return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
});

export function releaseFooter(html) {
  const found = [...String(html).matchAll(FOOTER)].map(([, version, commit]) => ({ version, commit }));
  if (!found.length) return { error: "the page carries no build footer" };
  if ((decodeCharRefs(String(html)).match(FOOTER_CLASS) || []).length !== found.length) return { error: "the page carries a build footer this parser cannot read" };
  const distinct = new Set(found.map(({ version, commit }) => `${version} ${commit}`));
  if (distinct.size !== 1) return { error: "the page's build footers disagree" };
  return found[0];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const file = process.argv[2];
  if (!file) {
    console.error("usage: node scripts/release-footer.mjs <entropylab.html>");
    process.exit(1);
  }
  const result = releaseFooter(readFileSync(file, "utf8"));
  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }
  console.log(`${result.version} ${result.commit}`);
}
