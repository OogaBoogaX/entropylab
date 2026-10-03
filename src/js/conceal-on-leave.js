// Revealed private values go back behind their masks when the user leaves
// the page. A secret left on screen is what Windows Recall snapshots, what a
// screen share broadcasts, and what iOS saves to disk as the app-switcher
// picture. Leaving is any of: the window loses focus, the page is hidden, or
// nobody has pressed a key, clicked, touched or scrolled for `idleMs`.
// `conceal` does the hiding; it must be safe to call when nothing is shown.
const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"];

export function initConcealOnLeave({ conceal, idleMs, win = window, doc = document }) {
  let timer = 0;
  const arm = () => {
    win.clearTimeout(timer);
    timer = win.setTimeout(conceal, idleMs);
  };
  win.addEventListener("blur", conceal);
  doc.addEventListener("visibilitychange", () => {
    if (doc.visibilityState === "hidden") conceal();
  });
  for (const type of ACTIVITY) doc.addEventListener(type, arm, { capture: true, passive: true });
  arm();
}
