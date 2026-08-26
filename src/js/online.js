
(() => {
  const isHostedOnline = /^(www\.)?entropylab\.online$/i.test(location.hostname);
  const isLocalPreview = (
    location.protocol === "file:" || /^(localhost|127\.0\.0\.1|\[::1\])$/i.test(location.hostname)
  ) && new URLSearchParams(location.search).get("online-preview") === "1";
  const onlineWarning = document.getElementById("online-warning");

  const hideOnlineWarning = () => {
    if (onlineWarning) onlineWarning.hidden = true;
  };
  const checkInternetConnection = async () => {
    if (!navigator.onLine) {
      hideOnlineWarning();
      return;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      await fetch("https://www.google.com/generate_204", {
        mode: "no-cors",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: controller.signal
      });
      if (onlineWarning) onlineWarning.hidden = false;
    } catch {
      hideOnlineWarning();
    } finally {
      clearTimeout(timeout);
    }
  };

  checkInternetConnection();

  if (!isHostedOnline && !isLocalPreview) return;

  const brandMark = document.getElementById("online-brand-mark");
  if (brandMark) {
    brandMark.src = brandMark.dataset.onlineSrc;
    brandMark.hidden = false;
  }

  const favicon = document.createElement("link");
  favicon.id = "online-favicon";
  favicon.rel = "icon";
  favicon.type = "image/png";
  favicon.sizes = "64x64";
  favicon.href = "assets/favicon.png";
  document.head.appendChild(favicon);
})();

function hodlFormatRecoverySheet(text) {
  const lines = text.split("\n");
  if (lines[1] !== "ENTROPYLAB V{{VERSION}}") lines.splice(1, 0, "ENTROPYLAB V{{VERSION}}");
  return lines.join("\n");
}

(() => {
  const current = document.querySelector('meta[name="application-version"]')?.content || "v{{VERSION}}";
  const currentFile = "entropylab-" + current.replace(/^v/, "") + ".html";
  const selects = [...document.querySelectorAll(".version-select")];
  const downloads = [...document.querySelectorAll('[download^="entropylab-"]')];
  let availableVersions = [{ version: current, file: currentFile }];

  downloads.forEach((link) => {
    link.href = currentFile;
    link.download = currentFile;
  });

  const render = (versions) => {
    const safe = versions.filter((item) =>
      /^v\d+(?:\.\d+)*$/.test(item.version) &&
      /^entropylab-\d+(?:\.\d+)*\.html$/.test(item.file)
    );

    if (!safe.some((item) => item.version === current)) {
      safe.unshift({ version: current, file: currentFile });
    }
    const latest = safe.reduce((best, item) => {
      const parts = item.version.slice(1).split(".").map(Number);
      const bestParts = best.version.slice(1).split(".").map(Number);
      const length = Math.max(parts.length, bestParts.length);
      for (let index = 0; index < length; index++) {
        const difference = (parts[index] || 0) - (bestParts[index] || 0);
        if (difference > 0) return item;
        if (difference < 0) return best;
      }
      return best;
    }, safe[0]);
    availableVersions = safe.map((item) => ({ ...item }));

    selects.forEach((select) => {
      select.replaceChildren(...safe.map((item) => {
        const option = document.createElement("option");
        option.value = item.file;
        option.textContent = item.version + (item.version === latest.version ? " (Latest)" : "");
        option.selected = item.version === current;
        return option;
      }));
      select.onchange = () => location.assign(select.value);
    });
  };

  render(availableVersions);
  window.addEventListener("pageshow", () => render(availableVersions));
  if (/^https?:$/.test(location.protocol)) {
    fetch("versions.json", { cache: "no-store" })
      .then((response) => {
        if (!response.ok) throw new Error("Version list unavailable");
        return response.json();
      })
      .then((data) => render(Array.isArray(data.versions) ? data.versions : []))
      .catch(() => {});
  }
})();
