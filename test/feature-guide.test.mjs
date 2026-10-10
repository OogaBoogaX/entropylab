// Contract: lessons accept known IDs and render bundled text, without reading
// secrets, storing data, doing I/O, or navigating except on an explicit tool action.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { MiniDocument } from "./mini-dom.mjs";
import { createFeatureGuideSession, initFeatureGuide } from "../src/js/feature-guide.js";
import { featureGuideLessons, featureGuideEntries } from "../src/js/feature-guide-content.js";
import { collectSources } from "../scripts/i18n-sources.mjs";

test("guide catalog omits held-back workspace lessons", () => {
  const lessons = featureGuideLessons();
  assert.ok(lessons.length > 0);
  for (const id of ["lightning", "journal"]) {
    assert.equal(lessons.some(lesson => lesson.id === id || lesson.tool === id), false);
    const session = createFeatureGuideSession(lessons, featureGuideEntries.map(entry => entry.tool));
    session.choose(id);
    assert.equal(session.view().lessonId, null);
  }
});

const fixtures = [
  { id: "basics", steps: [{ id: "one" }, { id: "two" }] },
  { id: "keys", tool: "calc", steps: [{ id: "keys-one" }] },
  { id: "hidden", tool: "journal", steps: [{ id: "hidden-one" }] },
];
test("bounds, contents/resume, completion and restart preserve only learning state", () => {
  const session = createFeatureGuideSession(fixtures, ["calc"]);
  assert.equal(session.view().mode, "contents");
  session.choose("basics");
  session.back();
  assert.equal(session.view().index, 0);
  session.next();
  session.contents();
  assert.equal(session.view().mode, "contents");
  session.resume();
  assert.equal(session.view().index, 1);
  session.next();
  assert.equal(session.view().mode, "complete");
  assert.deepEqual(session.view().completed, ["basics"]);
  session.next();
  assert.equal(session.view().index, 2);
  session.back();
  assert.equal(session.view().index, 1);
  session.choose("basics");
  assert.equal(session.view().index, 0);
  assert.deepEqual(session.view().completed, ["basics"]);
  session.clear();
  assert.equal(session.view().lessonId, null);
  assert.deepEqual(session.view().completed, []);
});
test("unknown lesson IDs return to contents and hidden tools have no navigation target", () => {
  const session = createFeatureGuideSession(fixtures, ["calc"]);
  session.choose("keys");
  assert.equal(session.view().tool, "calc");
  for (const id of ["hidden", "__proto__", "<img src=x>", "", null]) {
    session.choose(id);
    assert.equal(session.view().tool, null);
    if (id !== "hidden") assert.equal(session.view().mode, "contents");
  }
});

function withPage(run, translate = (text) => text) {
  const saved = Object.getOwnPropertyDescriptors(globalThis);
  const random = Math.random;
  const doc = new MiniDocument(), handlers = {}, events = {}, opened = [];
  doc.body.innerHTML = '<button id="guide-open" data-guide-open=""></button><div id="calc-tool-intro"></div><textarea id="seed"></textarea>';
  Object.defineProperty(doc.getElementById("seed"), "value", { get() { throw new Error("guide read a secret"); }, set() { throw new Error("guide wrote a secret"); } });
  const create = doc.createElement.bind(doc);
  doc.createElement = (tag) => { const node = create(tag); node.focus = () => { doc.activeElement = node; }; return node; };
  const opener = doc.getElementById("guide-open");
  opener.focus = () => { doc.activeElement = opener; };
  doc.addEventListener = (name, fn) => { handlers[name] = fn; };
  const win = { addEventListener(name, fn) { events[name] = fn; } };
  Object.defineProperty(globalThis, "document", { configurable: true, writable: true, value: doc });
  for (const name of ["fetch", "WebSocket", "XMLHttpRequest"]) Object.defineProperty(globalThis, name, { configurable: true, value: () => { throw new Error("guide attempted I/O"); } });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { throw new Error("guide accessed storage"); } });
  Math.random = () => { throw new Error("guide manufactured randomness"); };
  Object.defineProperty(globalThis, "crypto", { configurable: true, get() { throw new Error("guide accessed cryptography"); } });
  try {
    const guide = initFeatureGuide({ win, t: translate, availableTools: ["calc", "msig", "psbt", "bip85", "sp", "vanity"], onOpenTool: (id) => opened.push(id) });
    const click = (selector) => {
      const target = doc.querySelector(selector);
      assert.ok(target, `missing control ${selector}`);
      handlers.click({ target });
    };
    run({ guide, doc, events, opened, click, opener });
  } finally {
    Math.random = random;
    for (const name of ["document", "fetch", "WebSocket", "XMLHttpRequest", "localStorage", "crypto"]) {
      if (saved[name]) Object.defineProperty(globalThis, name, saved[name]);
      else delete globalThis[name];
    }
  }
}
test("lazy dialog, deep links, close/resume, repeated completion and explicit navigation", () => withPage(({ doc, guide, click, opened, opener }) => {
  assert.equal(doc.getElementById("feature-guide-overlay"), null);
  click("#guide-open");
  assert.ok(doc.getElementById("feature-guide-dialog"));
  click('[data-guide-lesson="basics"]');
  assert.equal(doc.getElementById("guide-back").disabled, true);
  click("#guide-next");
  const step = doc.getElementById("guide-step").dataset.guideStep;
  click("#guide-close");
  assert.equal(guide.isOpen(), false);
  assert.equal(doc.activeElement, opener);
  click("#guide-open");
  click('[data-guide-action="resume"]');
  assert.equal(doc.getElementById("guide-step").dataset.guideStep, step);
  click("#guide-contents");
  click('[data-guide-lesson="keys"]');
  while (doc.getElementById("guide-next")) click("#guide-next");
  assert.ok(doc.querySelector('[data-guide-complete="keys"]'));
  click('[data-guide-action="restart"]');
  assert.equal(doc.getElementById("guide-step").dataset.guideStep, featureGuideLessons().find((item) => item.id === "keys").steps[0].id);
  assert.deepEqual(opened, []);
  click('[data-guide-action="open-tool"]');
  assert.deepEqual(opened, ["calc"]);
  assert.equal(guide.isOpen(), false);
  guide.open("journal", opener);
  assert.equal(doc.querySelector('[data-guide-action="open-tool"]'), null);
  guide.open("missing", opener);
  assert.ok(doc.querySelector('[data-guide-lesson="basics"]'));
}));
test("translated or hostile lesson content stays text; refresh preserves step; teardown refuses reopen", () => withPage(({ doc, guide, events, opener }) => {
  guide.open("basics", opener);
  const id = doc.getElementById("guide-step").dataset.guideStep;
  assert.equal(doc.querySelector("img"), null);
  assert.equal(doc.querySelector("script"), null);
  assert.ok(doc.getElementById("guide-step").textContent.includes("<img"));
  guide.refresh();
  assert.equal(doc.getElementById("guide-step").dataset.guideStep, id);
  events.pagehide();
  assert.equal(guide.isOpen(), false);
  guide.open("basics", opener);
  assert.equal(guide.isOpen(), false);
  events.pageshow({ persisted: true });
  guide.open(null, opener);
  assert.equal(doc.querySelector('[data-guide-action="resume"]'), null);
}, (text) => `<img src=x onerror=alert(1)>${text}`));
test("catalog covers released workspaces with complete steps, unique IDs, and extracted translations", async () => {
  const lessons = featureGuideLessons();
  assert.equal(lessons.find((item) => item.id === "basics").steps.length, 8);
  assert.deepEqual([...new Set(lessons.map((item) => item.tool).filter(Boolean))].sort(), ["bip85", "calc", "msig", "psbt", "sp", "vanity"]);
  const sources = await collectSources(fileURLToPath(new URL("..", import.meta.url)));
  const strings = [];
  const stepIds = [];
  for (const lesson of lessons) {
    strings.push(lesson.title, lesson.summary);
    assert.ok(lesson.steps.length >= 2);
    for (const step of lesson.steps) {
      stepIds.push(step.id);
      for (const field of ["title", "body", "check", "limit"]) {
        assert.ok(typeof step[field] === "string" && step[field].length);
        strings.push(step[field]);
      }
      if (step.example) strings.push(step.example);
      if (step.term) strings.push(...step.term);
    }
  }
  assert.equal(new Set(stepIds).size, stepIds.length);
  assert.equal(new Set(lessons.map((item) => item.id)).size, lessons.length);
  assert.ok(strings.every((text) => sources.has(text)), "guide content must be available to translation automation");
  assert.ok(featureGuideEntries.every(([, lesson]) => lessons.some((item) => item.id === lesson)));
});
test("guide entry and app lifecycle wiring belong to the source shell and boot", () => {
  const root = new URL("..", import.meta.url);
  const doc = new MiniDocument();
  doc.body.innerHTML = readFileSync(new URL("src/shell.html", root), "utf8");
  assert.ok(doc.getElementById("guide-open")?.hasAttribute("data-guide-open"));
  for (const [id] of featureGuideEntries) assert.ok(doc.getElementById(id), `missing context target ${id}`);
  const app = readFileSync(new URL("src/js/app.js", root), "utf8");
  assert.match(app, /hodlFeatureGuide\s*=\s*initFeatureGuide\(/);
  assert.match(app, /hodlFeatureGuide\?\.refresh\(\)/);
});
test("optional routes advance only explicitly and reject unknown routes", () => withPage(({ guide, click, doc, opened, opener }) => {
  guide.open(null, opener);
  click('#guide-route-recovery');
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, 'exports-public');
  while (doc.getElementById('guide-next')) click('#guide-next');
  click('#guide-route-next');
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, 'multisig-quorum');
  assert.deepEqual(opened, []);
  click('#guide-contents');
  click('#guide-lesson-basics');
  assert.equal(doc.getElementById('guide-route-next'), null);
}));
test("optional checks give feedback without advancing or touching wallet data", () => withPage(({ guide, click, doc, opener }) => {
  guide.open('basics', opener);
  for (let i = 1; i < featureGuideLessons().find(item => item.id === 'basics').steps.length; i++) click('#guide-next');
  const before = doc.getElementById('guide-step').dataset.guideStep;
  click('#guide-answer-0');
  assert.equal(doc.getElementById('guide-feedback').dataset.guideCorrect, 'false');
  click('#guide-answer-1');
  assert.equal(doc.getElementById('guide-feedback').dataset.guideCorrect, 'true');
  assert.equal(doc.activeElement, doc.getElementById('guide-feedback'));
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, before);
}));

test("checks appear once after lesson concepts, never on earlier steps", () => withPage(({ guide, click, doc, opener }) => {
  for (const id of ['basics', 'exports', 'inspect', 'bip85']) {
    guide.open(id, opener);
    const lesson = featureGuideLessons().find(item => item.id === id);
    for (let i = 0; i < lesson.steps.length; i++) {
      assert.equal(!!doc.getElementById('guide-check'), i === lesson.steps.length - 1, `${id} step ${i}`);
      click('#guide-next');
    }
    assert.equal(doc.getElementById('guide-check'), null);
  }
}));
test("completed route reopening offers the next lesson, while interruptions resume the same step", () => withPage(({ guide, click, doc, opened, opener }) => {
  guide.open(null, opener); click('#guide-route-wallet');
  while (doc.getElementById('guide-next')) click('#guide-next');
  click('#guide-close'); guide.open(null, opener);
  assert.equal(doc.getElementById('guide-resume'), null);
  click('#guide-continue-route');
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, 'keys-methods');
  click('#guide-next'); click('#guide-close'); guide.open(null, opener); click('#guide-resume');
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, 'keys-labs');
  while (doc.getElementById('guide-next')) click('#guide-next');
  assert.ok(doc.getElementById('guide-finish-lessons'));
  click('#guide-finish-bip85');
  assert.equal(doc.getElementById('guide-step').dataset.guideStep, 'bip85-recipe');
  assert.deepEqual(opened, []);
}));

test("diagram highlights are bound to concept IDs and first-use basics terms are explained", () => withPage(({ guide, click, doc, opener }) => {
  guide.open('basics', opener);
  assert.equal(doc.getElementById('guide-story'), null);
  click('#guide-next');
  assert.equal(doc.querySelector('[aria-current="step"]').dataset.guideStage, 'keys');
  click('#guide-next');
  assert.equal(doc.querySelector('[aria-current="step"]').dataset.guideStage, 'input');
  assert.ok(featureGuideLessons().find(item => item.id === 'basics').steps.every(item => item.term?.length === 2));
}));
