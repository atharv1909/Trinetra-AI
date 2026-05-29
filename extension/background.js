const API_BASE = "http://localhost:8000";

// cache scanned URLs to avoid repeat calls
const scanCache = {};
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function scanUrl(url) {
  // check cache
  const cached = scanCache[url];
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.result;
  }

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        target_org: null  // auto-detect
      }),
    });

    if (!response.ok) return null;
    const result = await response.json();

    // cache result
    scanCache[url] = { result, timestamp: Date.now() };
    return result;

  } catch (error) {
    // backend not running — fail silently
    console.log("[Trinetra] Backend not reachable:", error.message);
    return null;
  }
}

function getBadge(riskLevel, score) {
  if (riskLevel === "HIGH")   return { text: "!", color: "#DC2626" };
  if (riskLevel === "MEDIUM") return { text: "?", color: "#D97706" };
  if (riskLevel === "LOW")    return { text: "~", color: "#2563EB" };
  return { text: "", color: "#16A34A" };
}

// listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== "SCAN_URL") return;

  const url    = message.url;
  const tabId  = sender.tab?.id;
  if (!tabId) return;

  // scan asynchronously
  scanUrl(url).then((result) => {
    if (!result) return;

    const { text, color } = getBadge(result.risk_level, result.final_score);

    // update badge
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });

    // store result for popup
    chrome.storage.local.set({
      [`scan_${tabId}`]: {
        result,
        url,
        timestamp: Date.now()
      }
    });

    // show notification for HIGH risk
    if (result.risk_level === "HIGH") {
      chrome.notifications.create({
        type:    "basic",
        iconUrl: "icons/icon48.png",
        title:   "⚠ Trinetra AI — Phishing Detected",
        message: `This page may be impersonating a trusted organization.\nRisk Score: ${Math.round(result.final_score * 100)}%`,
        priority: 2
      });
    }
  });
});

// clear badge when tab navigates
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    chrome.action.setBadgeText({ text: "...", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#6B7280", tabId });
  }
});