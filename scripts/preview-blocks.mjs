// Preview blocks let unreleased markup merge into rock hidden: the release
// build strips everything between `<!-- preview -->` and `<!-- /preview -->`,
// a preview build keeps the contents and drops only the markers. The markers
// must be balanced and never nested, so a stray or unclosed marker fails the
// build instead of leaking half a feature into the release artifact.
import { readFileSync } from "node:fs";

const OPEN = "<!-- preview -->";
const CLOSE = "<!-- /preview -->";

export function applyPreviewBlocks(html, preview) {
  const out = [];
  let inside = false;
  for (const line of html.split("\n")) {
    const marker = line.trim();
    // A marker sharing its line with markup, or any near-miss spelling
    // (<!--preview-->, <!-- Preview -->, <!-- preview: name -->), would pass
    // through as text and leak the block into a release build: anything that
    // looks like a preview marker must be exactly one, alone on its line.
    if ((line.includes(OPEN) && marker !== OPEN) || (line.includes(CLOSE) && marker !== CLOSE)) {
      throw new Error("preview markers must each stand alone on their own line");
    }
    // Any comment on the line that mentions "preview" counts: an extra dash
    // (<!--- preview -->), a plural or a suffix must not slip past as text.
    if (/<!--[^\n]*?preview/i.test(line) && marker !== OPEN && marker !== CLOSE) {
      throw new Error(`unrecognized preview marker: write exactly "${OPEN}" or "${CLOSE}" on its own line`);
    }
    if (marker === OPEN) {
      if (inside) throw new Error("preview blocks are unbalanced");
      inside = true;
      continue;
    }
    if (marker === CLOSE) {
      if (!inside) throw new Error("preview blocks are unbalanced");
      inside = false;
      continue;
    }
    if (inside && !preview) continue;
    out.push(line);
  }
  if (inside) throw new Error("preview blocks are unbalanced");
  return out.join("\n");
}

// The esbuild plugin that applies the same transform to every .html module
// the bundle loads (app.js imports shell.html through the text loader), so a
// release build hides preview markup in the bundled copy as well as in the
// injected one. It reads the file as esbuild would, with a UTF-8 BOM
// stripped, so a shell with no preview blocks bundles byte-for-byte as before.
export function previewHtmlPlugin(preview) {
  return {
    name: "preview-blocks",
    setup(build) {
      build.onLoad({ filter: /\.html$/ }, (args) => ({
        contents: applyPreviewBlocks(readFileSync(args.path, "utf8").replace(/^﻿/, ""), preview),
        loader: "text",
      }));
    },
  };
}
