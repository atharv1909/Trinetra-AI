function getScoreColor(riskLevel) {
  const colors = {
    HIGH:   "#DC2626",
    MEDIUM: "#D97706",
    LOW:    "#2563EB",
    SAFE:   "#16A34A",
  };
  return colors[riskLevel] || "#6B7280";
}

function getFlagClass(flag) {
  const danger = [
    "FORM_POSTS_EXTERNALLY", "CREDENTIAL_HARVESTING_PATTERN",
    "VISUAL_CLONE_DETECTED", "HOMOGLYPH_ATTACK", "TYPOSQUAT_DETECTED"
  ];
  const warn = [
    "HIGH_VISUAL_SIMILARITY", "BRAND_KEYWORD_IN_DOMAIN",
    "BRAND_IN_SUBDOMAIN", "SSL_INVALID", "IP_ADDRESS_IN_URL"
  ];
  if (danger.includes(flag)) return "danger";
  if (warn.includes(flag))   return "warn";
  return "";
}

function renderResult(data) {
  const { result, url } = data;
  const score    = Math.round(result.final_score * 100);
  const risk     = result.risk_level;
  const flags    = result.flags || [];
  const urlScore = Math.round((result.url_score || 0) * 100);
  const behScore = Math.round((result.behavior_score || 0) * 100);
  const visScore = Math.round((result.visual_score || 0) * 100);

  const flagsHtml = flags.length > 0
    ? flags.map(f =>
        `<div class="flag ${getFlagClass(f)}">${f.replace(/_/g, ' ')}</div>`
      ).join("")
    : `<div class="flag">No suspicious signals detected</div>`;

  document.getElementById("content").innerHTML = `
    <div class="score-section">
      <div class="score-circle ${risk}">
        <span class="score-num">${score}</span>
        <span class="score-pct">/ 100</span>
      </div>
      <div class="risk-label ${risk}">${risk} RISK</div>
    </div>

    <div class="url-box">${url.length > 60 ? url.slice(0,60)+"..." : url}</div>

    <div class="eyes">
      <div class="eye-card">
        <div class="eye-name">URL</div>
        <div class="eye-score" style="color:${getScoreColor(risk)}">${urlScore}</div>
      </div>
      <div class="eye-card">
        <div class="eye-name">VISUAL</div>
        <div class="eye-score" style="color:${getScoreColor(risk)}">${visScore}</div>
      </div>
      <div class="eye-card">
        <div class="eye-name">BEHAVIOR</div>
        <div class="eye-score" style="color:${getScoreColor(risk)}">${behScore}</div>
      </div>
    </div>

    <div class="flags">
      <div class="flags-title">Detection signals</div>
      ${flagsHtml}
    </div>

    <a class="open-btn" href="http://localhost:8000/docs" target="_blank">
      Open Full Dashboard →
    </a>
  `;
}

// get current tab and load its scan result
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tabId = tabs[0]?.id;
  if (!tabId) return;

  chrome.storage.local.get(`scan_${tabId}`, (data) => {
    const scanData = data[`scan_${tabId}`];

    if (!scanData) {
      document.getElementById("content").innerHTML = `
        <div class="no-backend">
          <p>Start the Trinetra backend to enable real-time scanning.</p>
          <br>
          <code style="font-size:10px;color:#555">uvicorn main:app --port 8000</code>
        </div>
      `;
      return;
    }

    renderResult(scanData);
  });
});