// Runs on every page at document_start
// Sends current URL to background for scanning

(function() {
  // skip chrome:// and extension pages
  const url = window.location.href;
  if (url.startsWith("chrome") || url.startsWith("extension")) return;
  if (url === "about:blank") return;

  // send URL to background service worker
  chrome.runtime.sendMessage({
    type: "SCAN_URL",
    url: url,
  });
})();