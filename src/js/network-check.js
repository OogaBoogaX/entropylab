
// Network check: drives the header status tag, which reads ONLINE in red when
// this computer has a network adapter available and OFFLINE in green when it
// does not. Detection relies on navigator.onLine plus the online/offline
// events only — no network traffic of any kind is ever generated. When onLine
// is false the OS reports no usable network adapter, so the machine is
// offline. When true, an adapter is available with a link; that includes
// a LAN without internet access, which still matters for an air-gap
// warning. Browsers intentionally offer no finer-grained adapter
// introspection, so an OFFLINE tag is not proof of an air gap.
(() => {
  const TAG_ID = "network-status";

  // The markup ships in the online state, so every path here either confirms
  // it or downgrades it; the tag can never be left claiming an unverified gap.
  const setStatus = (online) => {
    const tag = document.getElementById(TAG_ID);
    if (!tag) return;
    const t = globalThis.hodlTText;
    tag.dataset.state = online ? "online" : "offline";
    tag.textContent = t ? t(online ? "Online" : "Offline") : (online ? "Online" : "Offline");
    tag.setAttribute("aria-label", t ? t(online ? "Network status: online" : "Network status: offline") : (online ? "Network status: online" : "Network status: offline"));
  };

  const checkNetwork = () => {
    setStatus(navigator.onLine === true);
  };

  checkNetwork();
  window.addEventListener("online", checkNetwork);
  window.addEventListener("offline", checkNetwork);
  // Chromium-only Network Information API: re-check on connection changes.
  navigator.connection?.addEventListener?.("change", checkNetwork);
})();
