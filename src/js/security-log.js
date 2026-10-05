// Public security signals only. The API accepts a fixed event code, never
// caller-provided text, errors, fields or wallet data. History stays in this
// page, is bounded, and is discarded at the same pagehide boundary as keys.
import { t } from "./i18n.js";

export const SECURITY_LOG_LIMIT = 100;

const eventSpec = (code) => {
  switch (code) {
    case "session-started": return { level: "info", label: t("INFO"), message: t("Security log started. Events stay in this page for this session.") };
    case "network-online": return { level: "warning", label: t("WARN"), message: t("ONLINE: your browser reports a network connection. Do not enter wallet secrets on a connected device.") };
    case "network-offline": return { level: "info", label: t("INFO"), message: t("OFFLINE: your browser reports no network connection. This does not prove an air gap.") };
    case "network-unknown": return { level: "warning", label: t("WARN"), message: t("Connection status is unavailable. Treat this device as connected.") };
    case "page-translated": return { level: "warning", label: t("WARN"), message: t("Browser page translation detected. An online translator may receive page text. Turn it off and use EntropyLab's language menu.") };
    default: return null;
  }
};

export function initSecurityLog({ doc = document, win = window, nav = navigator, now = () => new Date() } = {}) {
  const output = doc.getElementById("security-log-output");
  if (!output) return null;
  const entries = [];
  let active = false;
  let networkState;

  const rowFor = ({ code, at }) => {
    const spec = eventSpec(code);
    const row = doc.createElement("li");
    row.dataset.event = code;
    row.dataset.level = spec.level;
    const time = doc.createElement("time");
    time.setAttribute("datetime", at.toISOString());
    time.textContent = at.toLocaleTimeString([], { hour12: false });
    const level = doc.createElement("span");
    level.dataset.securityLevel = "";
    level.textContent = `[${spec.label}]`;
    const message = doc.createElement("span");
    message.dataset.securityMessage = "";
    message.textContent = spec.message;
    row.append(time, level, message);
    return row;
  };
  const record = (code) => {
    if (!active || !eventSpec(code)) return false;
    // Follow new output only when the reader was already at the bottom.
    const follow = output.scrollHeight - output.scrollTop - output.clientHeight <= 24;
    const entry = { code, at: now() };
    entries.push(entry);
    output.append(rowFor(entry));
    if (entries.length > SECURITY_LOG_LIMIT) {
      entries.shift();
      output.firstChild.remove();
    }
    if (follow) output.scrollTop = output.scrollHeight;
    return true;
  };
  const refresh = () => {
    output.replaceChildren(...entries.map(rowFor));
  };
  const checkNetwork = () => {
    if (!active) return;
    const state = nav.onLine === true ? "network-online" : nav.onLine === false ? "network-offline" : "network-unknown";
    if (state === networkState) return;
    networkState = state;
    record(state);
  };
  const start = () => {
    active = true;
    networkState = undefined;
    record("session-started");
    checkNetwork();
    // The translation warning is latched: a restored page must still warn
    // even if the detector already disconnected before pagehide.
    if (doc.getElementById("translated-warning")?.hidden === false) record("page-translated");
  };
  win.addEventListener("online", checkNetwork);
  win.addEventListener("offline", checkNetwork);
  nav.connection?.addEventListener?.("change", checkNetwork);
  win.addEventListener("pagehide", () => {
    active = false;
    entries.length = 0;
    output.replaceChildren();
  });
  win.addEventListener("pageshow", (event) => {
    if (event.persisted) start();
  });
  start();
  return Object.freeze({ record, refresh });
}
