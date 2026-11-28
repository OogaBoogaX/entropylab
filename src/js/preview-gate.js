export const PREVIEW_ACK_KEY = "entropylab-preview-ack";

export function initPreviewGate({ doc, storage }) {
  const notice = doc.getElementById("preview-notice");
  if (!notice) return;
  const btcCalc = doc.getElementById("btc-calc");
  const button = doc.getElementById("preview-notice-accept");
  const setInert = () => btcCalc?.setAttribute("inert", "");
  const clearInert = () => btcCalc?.removeAttribute("inert");
  let acknowledged = false;
  try {
    acknowledged = storage()?.getItem(PREVIEW_ACK_KEY) === "1";
  } catch {
    acknowledged = false;
  }
  if (acknowledged) {
    notice.remove();
    clearInert();
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
    clearInert();
    notice.remove();
  });
}
