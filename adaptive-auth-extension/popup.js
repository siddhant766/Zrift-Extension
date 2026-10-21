// ==============================================================================
// Concept-Drift Adaptive Access Control: Extension Popup HUD
// ==============================================================================

function renderDashboard() {
  chrome.storage.local.get(
    ["trustScore", "status", "lastSample", "backendConnected"],
    (data) => {
      const scoreEl = document.getElementById("trustScore");
      const progressEl = document.getElementById("trustProgress");
      const statusEl = document.getElementById("statusText");
      const badgeEl = document.getElementById("backendBadge");

      const score = data.trustScore !== undefined ? data.trustScore : 96;
      scoreEl.textContent = `${score}%`;
      progressEl.style.width = `${Math.min(100, Math.max(0, score))}%`;

      // Visual color logic
      if (score >= 75) {
        scoreEl.style.color = "#22c55e";
        progressEl.style.backgroundColor = "#22c55e";
      } else if (score >= 65) {
        scoreEl.style.color = "#eab308";
        progressEl.style.backgroundColor = "#eab308";
      } else {
        scoreEl.style.color = "#ef4444";
        progressEl.style.backgroundColor = "#ef4444";
      }

      statusEl.textContent = data.status || "Calibrated";

      // Backend status badge
      if (data.backendConnected) {
        badgeEl.textContent = "API Connected";
        badgeEl.className = "badge online";
      } else {
        badgeEl.textContent = "Local Fallback";
        badgeEl.className = "badge offline";
      }

      // Populate biometric metrics
      if (data.lastSample) {
        const s = data.lastSample;
        document.getElementById("dwell").textContent = `${s.meanDwellMs ?? "--"} ms`;
        document.getElementById("flight").textContent = `${s.meanFlightMs ?? "--"} ms`;
        document.getElementById("velocity").textContent = `${s.meanMouseVelocity ?? "--"} px/s`;
        document.getElementById("jerk").textContent = `${s.meanMouseJerk ?? "--"}`;
      }
    }
  );
}

// Simulate adversarial drift button
document.getElementById("simulateDriftBtn").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.runtime.sendMessage(
    { type: "SIMULATE_DRIFT", tabId: tab ? tab.id : null },
    () => {
      renderDashboard();
      setTimeout(() => window.close(), 250);
    }
  );
});

// Reset baseline button
document.getElementById("resetBaselineBtn").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.runtime.sendMessage(
    { type: "RESET_BASELINE", tabId: tab ? tab.id : null },
    () => {
      renderDashboard();
    }
  );
});

// Initial render & interval update
renderDashboard();
setInterval(renderDashboard, 1500);
