// The preview build's warning must reach the artifact, and the release build
// must carry none of it. Checked on the final HTML, after every transform.
//
// The station line is counted inside each station, not across the whole page:
// a page-wide total let one station carry two lines while another carried
// none and still passed (CodeRabbit on 3f1736a3).
export const PREVIEW_STRINGS = [
  "This is a preview build",
  "This build is still being tested and is not approved for real use. Use test seeds only: never enter a real seed or key, and never send funds to anything made here.",
  "I understand: test seeds only",
  "Preview build: test seeds only. Never enter a real seed or key, or fund anything made here.",
  "Preview only: not approved for real use. Use a test seed, and do not fund anything made here.",
];
export const PREVIEW_MARKER_IDS = ['id="preview-notice"', 'id="preview-banner"'];
export const PREVIEW_STATION_IDS = ['id="slip39-check"', 'id="seedqr-check"', 'id="seedxor-card"'];
const STATION_LINE = PREVIEW_STRINGS[4];

export const checkPreviewWarning = (html, preview) => {
  if (preview) {
    for (const id of PREVIEW_MARKER_IDS) {
      if (!html.includes(id)) throw new Error(`Preview build is missing ${id}`);
    }
    for (const text of PREVIEW_STRINGS) {
      if (!html.includes(text)) throw new Error(`Preview build is missing the text: ${text}`);
    }
    const wrong = [];
    for (const id of PREVIEW_STATION_IDS) {
      const at = html.indexOf(id);
      if (at === -1) continue;
      const end = html.indexOf("</section>", at);
      if (end === -1) throw new Error(`Preview build station ${id} has no closing </section>`);
      const lines = html.slice(at, end).split(STATION_LINE).length - 1;
      if (lines !== 1) wrong.push(`${id} has ${lines}`);
    }
    if (wrong.length) throw new Error(`Preview build station line count wrong: ${wrong.join(", ")}; each station needs one`);
  } else {
    for (const text of PREVIEW_STRINGS) {
      if (html.includes(text)) throw new Error(`Release build leaked preview text: ${text}`);
    }
    for (const id of [...PREVIEW_MARKER_IDS, ...PREVIEW_STATION_IDS]) {
      if (html.includes(id)) throw new Error(`Release build leaked preview markup: ${id}`);
    }
  }
};
