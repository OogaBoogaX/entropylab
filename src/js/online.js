
(() => {
  const isHostedOnline = /^(www\.)?entropylab\.online$/i.test(location.hostname);
  const isLocalPreview = (
    location.protocol === "file:" || /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)
  ) && new URLSearchParams(location.search).get("online-preview") === "1";
  if (!isHostedOnline && !isLocalPreview) return;

  // The hosted site always warns: the banner cannot be dismissed.
  document.getElementById("online-warning")?.removeAttribute("hidden");
})();
