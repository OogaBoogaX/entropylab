
(() => {
  const host = location.hostname;
  const isLoopback = /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(host);
  // Any page served over the network is the cautious case, not only the
  // canonical domain: a self-hosted mirror or a LAN copy over http(s) is just
  // as online, so the warning keys on the transport, never on one hostname.
  const isNetworkServed =
    (location.protocol === "http:" || location.protocol === "https:") && !isLoopback;
  // file:// and loopback are local; the banner can still be forced there for
  // screenshots or QA with ?online-preview=1.
  const isLocalPreview =
    (location.protocol === "file:" || isLoopback) &&
    new URLSearchParams(location.search).get("online-preview") === "1";
  if (!isNetworkServed && !isLocalPreview) return;

  // A network-served copy always warns: the banner cannot be dismissed.
  document.getElementById("online-warning")?.removeAttribute("hidden");
})();
