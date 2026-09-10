// Opens EntropyLab in a full tab when the toolbar icon is clicked.
// A popup would be capped at 800x600, which is far too small for the tool.
const APP_PAGE = "entropylab.html";

chrome.action.onClicked.addListener(() => {
  chrome.tabs.create({ url: chrome.runtime.getURL(APP_PAGE) });
});

// First install: open it once so the tool is there straight away.
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL(APP_PAGE) });
  }
});
