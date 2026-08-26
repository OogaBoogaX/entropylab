
// Network check: shows the green network warning when this computer has a
// network adapter available, and hides the warning when it does not.
// Detection relies on navigator.onLine plus the online/offline events
// only — no network traffic of any kind is ever generated. When onLine is
// false the OS reports no usable network adapter, so the machine is
// offline. When true, an adapter is available with a link; that includes
// a LAN without internet access, which still matters for an air-gap
// warning. Browsers intentionally offer no finer-grained adapter
// introspection, so a missing warning is not proof of an air gap.
(() => {
  const WARNING_ID = "network-warning";

  const showWarning = () => {
    document.getElementById(WARNING_ID)?.removeAttribute("hidden");
  };

  const hideWarning = () => {
    document.getElementById(WARNING_ID)?.setAttribute("hidden", "");
  };

  const checkNetwork = () => {
    if (navigator.onLine === true) showWarning();
    else hideWarning();
  };

  checkNetwork();
  window.addEventListener("online", checkNetwork);
  window.addEventListener("offline", checkNetwork);
  // Chromium-only Network Information API: re-check on connection changes.
  navigator.connection?.addEventListener?.("change", checkNetwork);
})();
