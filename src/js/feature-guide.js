import { createModal } from "./modal.js";
import { featureGuideLessons, featureGuideEntries, featureGuideRoutes, featureGuideCheck } from "./feature-guide-content.js";

// This state contains only public lesson IDs and progress, never wallet data.
export function createFeatureGuideSession(lessons, availableTools) {
  const catalog = new Map(lessons.map((lesson) => [lesson.id, lesson]));
  const tools = new Set(availableTools);
  const completed = new Set();
  let lessonId = null, index = 0, mode = "contents";
  const view = () => ({ mode, lessonId, index, completed: [...completed], tool: mode !== "contents" && tools.has(catalog.get(lessonId)?.tool) ? catalog.get(lessonId).tool : null });
  return {
    view,
    choose(id) {
      if (!catalog.has(id)) { mode = "contents"; return; }
      lessonId = id; index = 0; mode = "lesson";
    },
    contents() { mode = "contents"; },
    resume() { if (lessonId) mode = index === catalog.get(lessonId).steps.length ? "complete" : "lesson"; },
    next() {
      if (mode !== "lesson") return;
      if (++index === catalog.get(lessonId).steps.length) { mode = "complete"; completed.add(lessonId); }
    },
    back() { if (mode !== "contents" && index > 0) { index--; mode = "lesson"; } },
    clear() { lessonId = null; index = 0; mode = "contents"; completed.clear(); },
  };
}

export function initFeatureGuide({ t: hodlTText, availableTools, onOpenTool, win = window }) {
  const session = createFeatureGuideSession(featureGuideLessons(), availableTools);
  let modal = null, active = true, route = null;
  const element = (tag, text = "", className = "", id = "") => {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    if (id) node.id = id;
    return node;
  };
  const button = (text, action, id = "", lesson = "") => {
    const node = element("button", text, "btn secondary", id);
    node.type = "button";
    node.dataset.guideAction = action;
    if (lesson) node.dataset.guideLesson = lesson;
    return node;
  };
  const close = () => modal?.hide();
  const nextRouteLesson = (view) => route?.lessons[route.lessons.indexOf(view.lessonId) + 1];
  const ensureModal = () => {
    if (modal) return;
    modal = createModal({
      id: "feature-guide-overlay", className: "feature-guide-overlay", card: "",
      focusables: () => [...modal.overlay.querySelectorAll("button, summary")].filter((node) => !node.disabled && !node.closest("[hidden]") && (node.tagName === "SUMMARY" || !node.closest("details") || node.closest("details").open)),
      onDismiss: close,
    });
    // Every word is rendered through a text sink, including catalog values.
    modal.overlay.setAttribute("data-i18n-skip", "");
    const card = element("section", "", "modal-card feature-guide-card", "feature-guide-dialog");
    card.setAttribute("role", "dialog");
    card.setAttribute("aria-modal", "true");
    card.setAttribute("aria-labelledby", "guide-title");
    modal.overlay.append(card);
  };
  const render = () => {
    const card = document.getElementById("feature-guide-dialog");
    const view = session.view();
    const lessons = featureGuideLessons(hodlTText);
    const lesson = lessons.find((item) => item.id === view.lessonId);
    const header = element("div", "", "row");
    const title = element("h2", hodlTText("EntropyLab guide"), "modal-title", "guide-title");
    header.append(title, button(hodlTText("Close"), "close", "guide-close"));
    const content = element("div", "", "guide-content", "guide-content");
    const footer = element("div", "", "row modal-actions");
    let focus;
    if (view.mode === "contents") {
      const intro = element("p", hodlTText("Small lessons, at your pace. Start with the basics or pick a feature. No wallet secrets are needed. Your place is kept only until this page is reloaded or left."));
      content.append(intro);
      if (lesson && view.index < lesson.steps.length) content.append(button(hodlTText("Continue learning: {lesson}", { lesson: lesson.title }), "resume", "guide-resume"));
      else if (lesson && nextRouteLesson(view)) {
        const next = lessons.find(item => item.id === nextRouteLesson(view));
        content.append(button(hodlTText("Continue route: {lesson}", { lesson: next.title }), "continue-route", "guide-continue-route"));
      }
      content.append(button(hodlTText("New here? Start with the basics"), "route", "guide-start-basics", "wallet"));
      content.append(element("p", hodlTText("Read {count} of {total} lessons this session", { count: view.completed.length, total: lessons.length }), "field-note", "guide-session-progress"));
      const choices = (items, action, prefix) => {
        const list = element("div", "", "guide-lessons");
        for (const item of items) {
          const choice = button("", action, `${prefix}${item.id}`, item.id);
          choice.append(element("strong", item.title));
          if (item.summary) choice.append(element("span", item.summary, "muted"));
          if (view.completed.includes(item.id)) choice.append(element("span", hodlTText("Read this session"), "field-note"));
          list.append(choice);
        }
        return list;
      };
      focus = element("h3", hodlTText("What would you like to understand?"));
      content.append(focus, choices(featureGuideRoutes(hodlTText), "route", "guide-route-"));
      const browse = element("details", "", "", "guide-browse");
      browse.append(element("summary", hodlTText("Browse all lessons")), choices(lessons, "choose", "guide-lesson-"));
      content.append(browse);
    } else {
      footer.append(button(hodlTText("Contents"), "contents", "guide-contents"));
      const status = element("p", view.mode === "complete" ? hodlTText("Lesson finished · {lesson}", { lesson: lesson.title }) : hodlTText("Step {step} of {total} · {lesson}", { step: view.index + 1, total: lesson.steps.length, lesson: lesson.title }), "field-note", "guide-progress");
      status.setAttribute("role", "status");
      status.setAttribute("aria-live", "polite");
      content.append(status);
      if (route) status.textContent = hodlTText("{route} · Lesson {lessonNumber} of {lessonTotal} · {progress}", { route: route.title, lessonNumber: route.lessons.indexOf(view.lessonId) + 1, lessonTotal: route.lessons.length, progress: status.textContent });
      const currentStep = lesson.steps[view.index];
      if (currentStep?.diagramStage) {
        const story = element("details", "", "", "guide-story");
        story.append(element("summary", hodlTText("See how the pieces fit")));
        const chain = element("ol", "", "guide-chain");
        const labels = [hodlTText("Your input"), hodlTText("Recovery material"), hodlTText("Keys"), hodlTText("Addresses")];
        const stages = ["input", "recovery", "keys", "addresses"];
        labels.forEach((label, index) => { const node = element("li", label); node.dataset.guideStage = stages[index]; if (stages[index] === currentStep.diagramStage) node.setAttribute("aria-current", "step"); chain.append(node); });
        story.append(chain, element("p", hodlTText("Your input follows a deterministic recipe into recovery material, keys, and addresses. Settings affect the recipe. This diagram calculates nothing."), "field-note"));
        content.append(story);
      }
      if (view.mode === "complete") {
        content.dataset.guideComplete = lesson.id;
        focus = element("h3", hodlTText("A little clearer, one lesson at a time"));
        content.append(focus, element("p", hodlTText("You can revisit this lesson whenever you like. Reading a lesson does not certify a wallet, device, or transaction safe.")));
        const finishActions = element("div", "", "row", "guide-finish-actions");
        finishActions.append(button(hodlTText("Read this lesson again"), "restart", "guide-restart"));
        const nextId = route?.lessons[route.lessons.indexOf(view.lessonId) + 1];
        if (nextId) finishActions.append(button(hodlTText("Continue route: {lesson}", { lesson: lessons.find(item => item.id === nextId).title }), "route-next", "guide-route-next", nextId));
        content.append(finishActions);
        content.append(element("h4", hodlTText("Choose another lesson"), "label"));
        const links = element("div", "", "guide-lessons", "guide-finish-lessons");
        for (const id of ["keys", "multisig", "inspect", "bip85", "silent", "vanity"]) {
          const item = lessons.find(item => item.id === id);
          links.append(button(item.title, "choose", `guide-finish-${id}`, id));
        }
        content.append(links);
      } else {
        const step = lesson.steps[view.index];
        const body = element("section", "", "guide-step", "guide-step");
        body.dataset.guideStep = step.id;
        focus = element("h3", step.title);
        body.append(focus, element("p", step.body));
        if (step.example) body.append(element("p", step.example, "edge-note is-info"));
        const check = element("div", "", "guide-note");
        check.append(element("h4", hodlTText("What to check"), "label"), element("p", step.check));
        const limit = element("div", "", "guide-note");
        limit.append(element("h4", hodlTText("Limits"), "label"), element("p", step.limit, "edge-note is-muted"));
        body.append(check, limit);
        if (step.term) {
          const details = element("details");
          details.append(element("summary", hodlTText("Explain this word: {word}", { word: step.term[0] })), element("p", step.term[1]));
          body.append(details);
        }
        content.append(body);
      }
      const quiz = featureGuideCheck(currentStep?.id, hodlTText);
      if (quiz && view.mode === "lesson") {
        const details = element("details", "", "", "guide-check");
        details.append(element("summary", hodlTText("Try a quick check (optional)")), element("p", quiz[0]));
        const answers = element("div", "", "row");
        quiz[1].forEach((answer, index) => answers.append(button(answer, "answer", `guide-answer-${index}`, String(index))));
        const feedback = element("p", "", "field-note", "guide-feedback");
        feedback.setAttribute("role", "status");
        feedback.setAttribute("aria-live", "polite");
        feedback.tabIndex = -1;
        details.append(answers, feedback);
        content.append(details);
      }
      const actions = element("div", "", "modal-actions-end");
      const back = button(hodlTText("Back"), "back", "guide-back");
      back.disabled = view.index === 0;
      actions.append(back);
      if (view.mode === "lesson") actions.append(button(hodlTText(view.index + 1 === lesson.steps.length ? "Finish lesson" : "Next"), "next", "guide-next"));
      const next = actions.querySelector("#guide-next");
      if (next) next.className = "btn primary";
      footer.append(actions);
      if (view.tool) {
        const open = button(hodlTText("Open this tool"), "open-tool", "guide-open-tool");
        content.append(open, element("p", hodlTText("Uses normal tool navigation and changes displayed results. Vanity runs its usual timing sample. No search or derivation starts."), "field-note"));
      }
    }
    focus.id = "guide-focus";
    focus.tabIndex = -1;
    card.replaceChildren(header, content, footer);
    return focus;
  };
  const open = (id, opener) => {
    if (!active) return;
    ensureModal();
    if (id) { route = null; session.choose(id); } else session.contents();
    modal.show(render(), opener);
  };
  const click = (event) => {
    if (!active) return;
    const entry = event.target.closest?.("[data-guide-open]");
    if (entry) { open(entry.dataset.guideOpen, entry); return; }
    const control = event.target.closest?.("[data-guide-action]");
    if (!control || control.disabled || !modal?.isOpen() || !control.closest("#feature-guide-dialog")) return;
    const action = control.dataset.guideAction;
    if (action === "close") { close(); return; }
    if (action === "open-tool") {
      const view = session.view();
      if (view.tool) { modal.hide({ restoreFocus: false }); onOpenTool(view.tool, view.lessonId); }
      return;
    }
    if (action === "answer") {
      const quiz = featureGuideCheck(featureGuideLessons().find(item => item.id === session.view().lessonId)?.steps[session.view().index]?.id, hodlTText);
      if (!quiz) return;
      const feedback = document.getElementById("guide-feedback");
      const correct = Number(control.dataset.guideLesson) === quiz[2];
      feedback.dataset.guideCorrect = String(correct);
      feedback.textContent = (correct ? hodlTText("That's right. ") : hodlTText("Take another look. ")) + quiz[3];
      feedback.focus();
      feedback.scrollIntoView?.({ block: "nearest" });
      return;
    }
    if (action === "route") {
      route = featureGuideRoutes(hodlTText).find(item => item.id === control.dataset.guideLesson) ?? null;
      if (!route) return;
      session.choose(route.lessons[0]);
    }
    else if (["route-next", "continue-route"].includes(action)) {
      const view = session.view();
      const id = nextRouteLesson(view);
      const lesson = featureGuideLessons().find(item => item.id === view.lessonId);
      if (!id || view.index !== lesson?.steps.length) return;
      session.choose(id);
    }
    else if (action === "choose") { route = null; session.choose(control.dataset.guideLesson); }
    else if (action === "restart") session.choose(session.view().lessonId);
    else if (action === "contents") session.contents();
    else if (["back", "next", "resume"].includes(action)) session[action]();
    else return;
    render().focus();
  };
  document.addEventListener("click", click);
  for (const [id, lesson] of featureGuideEntries) {
    const intro = document.getElementById(id);
    if (!intro) continue;
    const entry = element("button", hodlTText("Explain this tool"), "btn secondary guide-explain");
    entry.type = "button";
    entry.dataset.guideOpen = lesson;
    intro.append(entry);
  }
  win.addEventListener("pagehide", () => {
    active = false;
    session.clear();
    route = null;
    modal?.hide({ restoreFocus: false });
    document.getElementById("feature-guide-dialog")?.replaceChildren();
  });
  win.addEventListener("pageshow", (event) => { if (event.persisted) active = true; });
  return {
    open, isOpen: () => modal?.isOpen() ?? false,
    refresh() {
      for (const entry of document.querySelectorAll("[data-guide-open]")) {
        if (entry.dataset.guideOpen) entry.textContent = hodlTText("Explain this tool");
      }
      if (route) route = featureGuideRoutes(hodlTText).find(item => item.id === route.id);
      if (active && modal?.isOpen()) {
        const id = document.activeElement?.id;
        render();
        document.getElementById(id)?.focus();
      }
    },
  };
}
