
(() => {
  const isHostedOnline = /^(www\.)?entropylab\.online$/i.test(location.hostname);
  const isLocalPreview = (
    location.protocol === "file:" || /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)
  ) && new URLSearchParams(location.search).get("online-preview") === "1";
  if (!isHostedOnline && !isLocalPreview) return;

  // The hosted site always warns: a Geist project banner is not dismissible,
  // and the only thing that clears this one is running the file off the network.
  document.getElementById("online-warning")?.removeAttribute("hidden");
})();

function hodlFormatRecoverySheet(text) {
  const lines = text.split("\n");
  if (lines[1] !== "ENTROPYLAB V{{VERSION}}") lines.splice(1, 0, "ENTROPYLAB V{{VERSION}}");
  return lines.join("\n");
}
