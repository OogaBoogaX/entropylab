// Preview blocks hide unreleased markup from the release artifact: the release
// build strips everything between `<!-- preview -->` and `<!-- /preview -->`,
// a preview build keeps the contents and drops only the markers. The markers
// must be balanced and never nested, so a stray or unclosed marker fails the
// build instead of leaking half a feature into the release artifact.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPreviewBlocks } from "../scripts/preview-blocks.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

test("a preview block is removed from a release build and kept in a preview build", () => {
  const html = "before\n<!-- preview -->\nfeature\n<!-- /preview -->\nafter";
  assert.equal(applyPreviewBlocks(html, false), "before\nafter");
  assert.equal(applyPreviewBlocks(html, true), "before\nfeature\nafter");
});

test("multiple blocks work and text outside them is untouched", () => {
  const html = "a\n<!-- preview -->\nb\n<!-- /preview -->\nc\n<!-- preview -->\nd\n<!-- /preview -->\ne";
  assert.equal(applyPreviewBlocks(html, false), "a\nc\ne");
  assert.equal(applyPreviewBlocks(html, true), "a\nb\nc\nd\ne");
});

test("an unclosed marker throws", () => {
  assert.throws(() => applyPreviewBlocks("a\n<!-- preview -->\nb", false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks("a\n<!-- preview -->\nb", true), /preview blocks are unbalanced/);
});

test("a nested marker throws", () => {
  const html = "<!-- preview -->\na\n<!-- preview -->\nb\n<!-- /preview -->\nc\n<!-- /preview -->";
  assert.throws(() => applyPreviewBlocks(html, false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks(html, true), /preview blocks are unbalanced/);
});

test("a stray closing marker throws", () => {
  assert.throws(() => applyPreviewBlocks("a\n<!-- /preview -->\nb", false), /preview blocks are unbalanced/);
  assert.throws(() => applyPreviewBlocks("a\n<!-- /preview -->\nb", true), /preview blocks are unbalanced/);
});

test("an input with no markers is returned unchanged", () => {
  const html = "<div>no markers here</div>\n<p>still here</p>\n";
  assert.equal(applyPreviewBlocks(html, false), html);
  assert.equal(applyPreviewBlocks(html, true), html);
});

test("build.mjs defines __ENTROPYLAB_PREVIEW__, strips both shell copies and refuses --preview without an outside --out", () => {
  const build = readFileSync(join(root, "scripts", "build.mjs"), "utf8");
  assert.match(build, /__ENTROPYLAB_PREVIEW__:\s*preview\s*\?\s*"true"\s*:\s*"false"/);
  assert.match(build, /--preview requires --out outside the repository root/);
  assert.match(build, /applyPreviewBlocks\(read\("shell\.html"\), preview\)/);
  assert.match(build, /plugins:\s*\[previewHtml\]/);
});

// Red-team on a15448d (P1): an inline marker would pass through as text and
// leak its block into a release build, so it must fail the build.
test("a marker that shares its line with markup throws", () => {
  for (const html of [
    "<div><!-- preview --><button>x</button><!-- /preview --></div>",
    "<!-- preview --><button>x</button>\n<!-- /preview -->",
    "<!-- preview -->\n<button>x</button><!-- /preview -->",
  ]) {
    assert.throws(() => applyPreviewBlocks(html, false), /own line/);
    assert.throws(() => applyPreviewBlocks(html, true), /own line/);
  }
});

// Red-team on a15448d (P2): prove the esbuild plugin itself transforms an
// HTML module bundled through the text loader, not just that build.mjs
// mentions it.
test("the esbuild plugin strips preview blocks from a bundled .html module", async () => {
  const { build } = await import("esbuild");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { previewHtmlPlugin } = await import("../scripts/preview-blocks.mjs");
  const dir = mkdtempSync(join(tmpdir(), "preview-plugin-"));
  try {
    writeFileSync(join(dir, "page.html"), "<p>shipped</p>\n<!-- preview -->\n<p>unreleased</p>\n<!-- /preview -->\n");
    writeFileSync(join(dir, "entry.js"), 'import page from "./page.html";\nexport default page;\n');
    const bundle = async (preview) => (await build({ entryPoints: [join(dir, "entry.js")], bundle: true, write: false, format: "esm", loader: { ".html": "text" }, plugins: [previewHtmlPlugin(preview)] })).outputFiles[0].text;
    const release = await bundle(false);
    const previewBuild = await bundle(true);
    assert.ok(release.includes("shipped") && !release.includes("unreleased") && !release.includes("<!-- preview -->"), "release bundle drops the block");
    assert.ok(previewBuild.includes("shipped") && previewBuild.includes("unreleased") && !previewBuild.includes("<!-- preview -->"), "preview bundle keeps the contents, not the markers");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Red-team on a1788dc (P1/P2): a near-miss spelling must fail the build, not
// pass through as content and ship the block.
test("near-miss marker spellings throw", () => {
  for (const marker of ["<!--preview-->", "<!-- Preview -->", "<!-- PREVIEW -->", "<!-- preview: lightning -->", "<!--/preview-->", "<!-- / preview -->", "<!-- preview -->x"]) {
    assert.throws(() => applyPreviewBlocks(`<p>a</p>\n${marker}\n<p>b</p>\n`, false), /preview marker/, marker);
  }
  // Ordinary comments and the word "preview" in text are untouched.
  assert.equal(applyPreviewBlocks("<!-- a note -->\n<p>preview of a PSBT</p>\n", false), "<!-- a note -->\n<p>preview of a PSBT</p>\n");
});

// Reviews of 82d50c0 (GLM, MiniMax).
test("any comment mentioning preview must be an exact marker (extra dash, plural)", () => {
  for (const marker of ["<!--- preview -->", "<!--- /preview --->", "<!-- previews -->", "<!-- show the preview -->"]) {
    assert.throws(() => applyPreviewBlocks(`<p>a</p>\n${marker}\n`, false), /preview marker/, marker);
  }
});

test("build.mjs strips preview blocks from both templates and refuses the constant in classic scripts", () => {
  const build = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../scripts/build.mjs"), "utf8");
  assert.match(build, /const template = applyPreviewBlocks\(read\("index\.html"\), preview\)/);
  assert.match(build, /classic scripts cannot use __ENTROPYLAB_PREVIEW__/);
});

test("the committed release artifact carries no preview residue", () => {
  // The artifact CI commits after each merge: no preview marker and no
  // unreplaced preview constant may reach it (the test-hooks flag has the
  // same artifact-level pin in validate.test.mjs).
  const artifact = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../entropylab.html"), "utf8");
  assert.doesNotMatch(artifact, /<!-- \/?preview -->|__ENTROPYLAB_PREVIEW__/);
});
