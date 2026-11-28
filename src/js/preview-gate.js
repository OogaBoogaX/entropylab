export const PREVIEW_ACK_KEY = "entropylab-preview-ack";

// Default removal watcher: calls back once, when the node has left the
// document. With no MutationObserver or no parent to watch it does nothing,
// so the page behind the node stays inert (fail closed).
const watchForRemoval = (node, callback) => {
  const parent = node.parentNode;
  if (typeof MutationObserver !== "function" || !parent) return;
  const observer = new MutationObserver(() => {
    if (node.isConnected) return;
    observer.disconnect();
    callback();
  });
  observer.observe(parent, { childList: true });
};

const isHidden = (element) => element?.hidden === true || element?.hasAttribute?.("hidden") === true;

export function initPreviewGate({ doc, storage, whenRemoved = watchForRemoval }) {
  const notice = doc.getElementById("preview-notice");
  if (!notice) return;
  const btcCalc = doc.getElementById("btc-calc");
  const button = doc.getElementById("preview-notice-accept");
  const setInert = () => btcCalc?.setAttribute("inert", "");
  const clearInert = () => btcCalc?.removeAttribute("inert");
  // The beta disclaimer's Tab trap is a keydown listener on its overlay, so it
  // only runs while focus is inside. The notice kept the overlay
  // visibility:hidden (so its accept.focus() did nothing) and removing the
  // notice drops focus to the document, where one Tab walks into the app:
  // hand focus to the disclaimer and keep the page inert until it leaves.
  const handOff = () => {
    const disclaimer = doc.getElementById("beta-disclaimer");
    if (!disclaimer || isHidden(disclaimer)) {
      clearInert();
      return;
    }
    setInert();
    const stepOne = doc.getElementById("beta-disclaimer-step-1");
    const target = isHidden(stepOne)
      ? doc.getElementById("beta-disclaimer-proof")
      : doc.getElementById("beta-disclaimer-accept");
    target?.focus();
    whenRemoved(disclaimer, clearInert);
  };
  let acknowledged = false;
  try {
    acknowledged = storage()?.getItem(PREVIEW_ACK_KEY) === "1";
  } catch {
    acknowledged = false;
  }
  if (acknowledged) {
    // Set it before the hand-off decides: the notice can go while a
    // disclaimer waits.
    notice.remove();
    setInert();
    handOff();
    return;
  }
  setInert();
  button?.focus();
  notice.addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    event.preventDefault();
    button?.focus();
  });
  button?.addEventListener("click", () => {
    try {
      storage()?.setItem(PREVIEW_ACK_KEY, "1");
    } catch {
      // The notice simply shows again on the next load.
    }
    // Remove the notice first: its `:has()` rule keeps the disclaimer
    // visibility:hidden, and a hidden element cannot take focus.
    notice.remove();
    handOff();
  });
}
