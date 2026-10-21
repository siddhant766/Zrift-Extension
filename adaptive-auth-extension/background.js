// ==============================================================================
// Concept-Drift Adaptive Access Control: Background Service Worker
// ==============================================================================

const BACKEND_URL = "http://127.0.0.1:8000";
const CLIENT_SECRET = "enterprise-client-secret-key";
const CLIENT_ID = "ext-node-01";
const TRUST_THRESHOLD = 65;

let telemetryBuffer = [];
let tabSwitchCount = 0;
let currentTrustScore = 96;
let isLocked = false;
let backendAvailable = false;

// Track tab context & focus shifts
chrome.tabs.onActivated.addListener(() => {
  tabSwitchCount++;
});

// Initialize local storage state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    trustScore: currentTrustScore,
    status: "Calibrated",
    backendConnected: false,
    lastSample: null
  });
});

// Cryptographically sign payload using Web Crypto API (HMAC-SHA256)
async function signPayload(jsonString) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(CLIENT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, enc.encode(jsonString));
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Flush buffered telemetry to FastAPI ML backend or local fallback
async function flushTelemetryBatch(activeTabId) {
  if (telemetryBuffer.length === 0) return;

  const batch = [...telemetryBuffer];
  telemetryBuffer = [];

  const bodyData = {
    clientId: CLIENT_ID,
    timestamp: Date.now(),
    tabSwitches: tabSwitchCount,
    samples: batch
  };
  tabSwitchCount = 0;

  const bodyString = JSON.stringify(bodyData);
  let signature = "";
  try {
    signature = await signPayload(bodyString);
  } catch (err) {
    console.error("[Crypto Error]", err);
  }

  let serverResponse = null;

  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/telemetry`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Signature": signature
      },
      body: bodyString
    });

    if (res.ok) {
      serverResponse = await res.json();
      backendAvailable = true;
      currentTrustScore = serverResponse.trustScore;
    } else {
      backendAvailable = false;
    }
  } catch (err) {
    backendAvailable = false;
  }

  // Fallback heuristic scoring if backend is offline
  if (!serverResponse) {
    // Check latest sample for radical deviations
    const last = batch[batch.length - 1];
    if (last && (last.meanDwellMs > 450 || last.meanMouseVelocity > 1800 || last.meanMouseJerk > 120000)) {
      currentTrustScore = Math.max(30, currentTrustScore - 15);
    } else {
      // Natural gradual recovery towards normal
      currentTrustScore = Math.min(96, currentTrustScore + 1);
    }
  }

  const statusText =
    currentTrustScore < TRUST_THRESHOLD
      ? "Anomaly Flagged - Step-Up Required"
      : serverResponse?.isDriftAdaptive
      ? "Calibrated (Drift Adapted)"
      : "Calibrated";

  await chrome.storage.local.set({
    trustScore: currentTrustScore,
    status: statusText,
    backendConnected: backendAvailable,
    lastBatchTime: new Date().toLocaleTimeString(),
    lastSample: batch[batch.length - 1],
    modelMetrics: serverResponse?.metrics || null
  });

  // Enforce zero-trust lock if trust score dropped below threshold
  if (currentTrustScore < TRUST_THRESHOLD) {
    isLocked = true;
    const reason = serverResponse?.reason || "Behavioral anomaly deviation exceeded threshold";
    triggerLockOverlay(activeTabId, currentTrustScore, reason);
  }
}

// Trigger lock on active tab
async function triggerLockOverlay(tabId, score, reason) {
  let targetTabId = tabId;
  if (!targetTabId) {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    targetTabId = activeTab?.id;
  }
  if (targetTabId) {
    try {
      chrome.tabs.sendMessage(targetTabId, {
        type: "TRIGGER_LOCK",
        trustScore: score,
        reason: reason
      });
    } catch (e) {
      console.warn("Could not inject lock into tab:", e);
    }
  }
}

// Central Message Dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // 1. Process Biometric Telemetry Sample from content.js
  if (message.type === "BIOMETRIC_SAMPLE") {
    telemetryBuffer.push({
      ...message.data,
      tabSwitchCount
    });

    // Flush batch when buffer reaches 2 samples (~10 seconds)
    if (telemetryBuffer.length >= 2) {
      flushTelemetryBatch(sender.tab?.id);
    }
    sendResponse({ received: true });
    return true;
  }

  // 2. Step-Up MFA Verification Handler
  if (message.type === "VERIFY_STEP_UP") {
    (async () => {
      let verified = false;

      // Check with backend if available
      try {
        const res = await fetch(`${BACKEND_URL}/api/v1/verify-step-up`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            clientId: CLIENT_ID,
            totpCode: message.code
          })
        });
        if (res.ok) {
          const data = await res.json();
          verified = data.verified;
        }
      } catch (e) {
        // Fallback for offline demo: verify demo TOTP code
        verified = message.code === "123456";
      }

      if (verified) {
        isLocked = false;
        currentTrustScore = 96;
        await chrome.storage.local.set({
          trustScore: currentTrustScore,
          status: "Calibrated (MFA Verified - Drift Baseline Updated)"
        });
        sendResponse({ verified: true });
      } else {
        sendResponse({ verified: false });
      }
    })();
    return true; // Keep channel open for async response
  }

  // 3. Simulate Adversarial Drift (Demo / Presentation Trigger)
  if (message.type === "SIMULATE_DRIFT") {
    currentTrustScore = 42;
    isLocked = true;
    chrome.storage.local.set({
      trustScore: currentTrustScore,
      status: "Adversarial Drift Simulated (Threat Detected)"
    });

    triggerLockOverlay(
      message.tabId,
      currentTrustScore,
      "Simulated Adversarial Drift: High-entropy mouse path & key dwell shift"
    );
    sendResponse({ ok: true });
    return true;
  }

  // 4. Reset Baseline
  if (message.type === "RESET_BASELINE") {
    currentTrustScore = 96;
    isLocked = false;
    chrome.storage.local.set({
      trustScore: currentTrustScore,
      status: "Calibrated (Baseline Reset)"
    });
    if (message.tabId) {
      chrome.tabs.sendMessage(message.tabId, { type: "RELEASE_LOCK" });
    }
    sendResponse({ ok: true });
    return true;
  }
});
