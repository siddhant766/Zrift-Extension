// ==============================================================================
// Concept-Drift Adaptive Access Control: Client-Side Biometric Sensor
// ==============================================================================

// --- 1. PRIVACY-PRESERVING KEYSTROKE TIMING DYNAMICS ---
// Note: We DO NOT capture e.key, e.code, or text values to ensure zero keystroke logging.
let lastKeyUpTime = null;
const keyPressTimestamps = new Map();
let dwellTimes = [];
let flightTimes = [];

window.addEventListener(
  "keydown",
  (e) => {
    if (e.repeat) return;
    const now = performance.now();
    // Use an anonymous slot key to track dwell duration
    keyPressTimestamps.set("slot_" + (e.which || "active"), now);

    if (lastKeyUpTime !== null) {
      const flight = now - lastKeyUpTime;
      // Filter out long pauses (e.g. > 2.5s) to avoid skewing continuous typing flight time
      if (flight > 5 && flight < 2500) {
        flightTimes.push(flight);
      }
    }
  },
  true
);

window.addEventListener(
  "keyup",
  (e) => {
    const now = performance.now();
    const keySlot = "slot_" + (e.which || "active");
    if (keyPressTimestamps.has(keySlot)) {
      const dwell = now - keyPressTimestamps.get(keySlot);
      if (dwell > 5 && dwell < 2000) {
        dwellTimes.push(dwell);
      }
      keyPressTimestamps.delete(keySlot);
    }
    lastKeyUpTime = now;
  },
  true
);

// --- 2. MOUSE KINEMATICS (Velocity, Acceleration, and Jerk) ---
let prevMouse = null;
let velocities = [];
let accelerations = [];
let jerks = [];

window.addEventListener(
  "mousemove",
  (e) => {
    const now = performance.now();
    if (prevMouse) {
      const dt = (now - prevMouse.t) / 1000; // convert to seconds
      if (dt >= 0.016) {
        // Sample at ~60 Hz to minimize CPU overhead
        const dx = e.clientX - prevMouse.x;
        const dy = e.clientY - prevMouse.y;
        const dist = Math.hypot(dx, dy);
        const velocity = dist / dt; // px/s
        const accel = prevMouse.v !== undefined ? (velocity - prevMouse.v) / dt : 0; // px/s²
        const jerk = prevMouse.a !== undefined ? Math.abs(accel - prevMouse.a) / dt : 0; // px/s³

        velocities.push(velocity);
        accelerations.push(accel);
        if (jerk > 0) {
          jerks.push(jerk);
        }

        prevMouse = { x: e.clientX, y: e.clientY, t: now, v: velocity, a: accel };
      }
    } else {
      prevMouse = { x: e.clientX, y: e.clientY, t: now };
    }
  },
  { passive: true }
);

// Statistical helpers
const mean = (arr) => (arr.length ? +(arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2) : 0);
const stdDev = (arr) => {
  if (arr.length < 2) return 0;
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  const variance = arr.reduce((sum, val) => sum + Math.pow(val - m, 2), 0) / arr.length;
  return +Math.sqrt(variance).toFixed(2);
};

// --- 3. FLUSH BIOMETRIC SUMMARY VECTORS EVERY 5 SECONDS ---
setInterval(() => {
  if (dwellTimes.length === 0 && velocities.length === 0) return;

  const payload = {
    type: "BIOMETRIC_SAMPLE",
    data: {
      timestamp: Date.now(),
      urlHost: window.location.hostname || "local",
      meanDwellMs: mean(dwellTimes),
      stdDwellMs: stdDev(dwellTimes),
      meanFlightMs: mean(flightTimes),
      stdFlightMs: stdDev(flightTimes),
      keystrokeCount: dwellTimes.length,
      meanMouseVelocity: mean(velocities),
      maxMouseVelocity: velocities.length ? +Math.max(...velocities).toFixed(2) : 0,
      meanMouseJerk: mean(jerks),
      mouseSampleCount: velocities.length
    }
  };

  chrome.runtime.sendMessage(payload);

  // Clear rolling sampling windows
  dwellTimes = [];
  flightTimes = [];
  velocities = [];
  accelerations = [];
  jerks = [];
}, 5000);

// --- 4. INLINE STEP-UP MFA OVERLAY ENFORCER (SHADOW DOM ISOLATED) ---
let overlayHost = null;

function showStepUpOverlay(trustScore, reason) {
  if (overlayHost) return; // Prevent duplicate lock injection

  overlayHost = document.createElement("div");
  overlayHost.id = "zt-adaptive-lock-host";
  const shadow = overlayHost.attachShadow({ mode: "open" });

  shadow.innerHTML = `
    <style>
      :host {
        all: initial;
      }
      .backdrop {
        position: fixed;
        inset: 0;
        z-index: 2147483647;
        background: rgba(10, 15, 30, 0.94);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        color: #f8fafc;
      }
      .card {
        background: #0f172a;
        border: 1px solid #dc2626;
        border-radius: 16px;
        padding: 32px 28px;
        width: 380px;
        max-width: 90vw;
        text-align: center;
        box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 30px rgba(220, 38, 38, 0.25);
        animation: fadeIn 0.2s ease-out;
      }
      @keyframes fadeIn {
        from { opacity: 0; transform: scale(0.96); }
        to { opacity: 1; transform: scale(1); }
      }
      .shield-icon {
        width: 52px;
        height: 52px;
        margin: 0 auto 16px;
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
      }
      h2 {
        margin: 0 0 8px;
        color: #f87171;
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      p {
        font-size: 13.5px;
        color: #94a3b8;
        line-height: 1.5;
        margin: 0 0 20px;
      }
      .score-badge {
        display: inline-block;
        background: #450a0a;
        color: #fca5a5;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 6px;
        border: 1px solid #7f1d1d;
        margin-bottom: 16px;
        font-size: 13px;
      }
      input {
        width: 85%;
        padding: 12px;
        border-radius: 8px;
        border: 1px solid #334155;
        background: #1e293b;
        color: #f8fafc;
        margin-bottom: 14px;
        text-align: center;
        font-size: 18px;
        font-family: monospace;
        letter-spacing: 4px;
        outline: none;
        transition: border-color 0.2s;
      }
      input:focus {
        border-color: #38bdf8;
        box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
      }
      .btn {
        width: 92%;
        padding: 12px;
        background: #2563eb;
        color: #ffffff;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: background-color 0.2s, transform 0.1s;
      }
      .btn:hover {
        background: #1d4ed8;
      }
      .btn:active {
        transform: scale(0.98);
      }
      .hint {
        margin-top: 14px;
        font-size: 11px;
        color: #64748b;
      }
      .error-msg {
        color: #f87171;
        font-size: 12px;
        margin-top: 10px;
        display: none;
      }
    </style>
    <div class="backdrop">
      <div class="card">
        <div class="shield-icon">🛡️</div>
        <h2>Step-Up MFA Required</h2>
        <div class="score-badge">Trust Score: ${trustScore}% (Threshold: 65%)</div>
        <p>Continuous biometrics detected behavioral anomaly or concept drift: <i>${reason || "High deviation from baseline typing & mouse profile"}</i>. Application state is securely frozen.</p>
        <input type="text" id="mfaCode" maxlength="6" placeholder="------" autofocus />
        <button id="verifyBtn" class="btn">Verify & Resume Session</button>
        <div id="errMsg" class="error-msg">Invalid TOTP code. Try demo code: 123456</div>
        <div class="hint">Demo Master MFA Code: <b>123456</b></div>
      </div>
    </div>
  `;

  document.documentElement.appendChild(overlayHost);

  const verifyBtn = shadow.getElementById("verifyBtn");
  const mfaInput = shadow.getElementById("mfaCode");
  const errMsg = shadow.getElementById("errMsg");

  const submitMFA = () => {
    const code = mfaInput.value.trim();
    if (!code) return;

    verifyBtn.textContent = "Verifying...";
    chrome.runtime.sendMessage({ type: "VERIFY_STEP_UP", code }, (res) => {
      verifyBtn.textContent = "Verify & Resume Session";
      if (res && res.verified) {
        if (overlayHost) {
          overlayHost.remove();
          overlayHost = null;
        }
      } else {
        errMsg.style.display = "block";
        mfaInput.value = "";
        mfaInput.focus();
      }
    });
  };

  verifyBtn.addEventListener("click", submitMFA);
  mfaInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitMFA();
  });
}

// Listen for background lock and unlock triggers
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "TRIGGER_LOCK") {
    showStepUpOverlay(msg.trustScore, msg.reason);
    sendResponse({ status: "locked" });
  } else if (msg.type === "RELEASE_LOCK") {
    if (overlayHost) {
      overlayHost.remove();
      overlayHost = null;
    }
    sendResponse({ status: "unlocked" });
  }
});
