# Concept-Drift-Aware Adaptive Access Control (Continuous Zero Trust)

A full-stack, continuous behavioral authentication system powered by a **Manifest V3 Browser Extension sensor**, **Transit-Layer HMAC Cryptography**, **Concept-Drift ML Engine**, and a **Real-Time Enterprise Admin HUD**.

---

## Architecture Overview

```
┌────────────────────────────────┐
│   Active Webpage (DOM)         │
│   Keystroke & Mouse Physics    │
│   (content.js)                 │
└──────────────┬─────────────────┘
               │ Local 5-sec Buffer
               ▼
┌────────────────────────────────┐
│   MV3 Service Worker           │
│   HMAC-SHA256 Signing          │
│   (background.js)              │
└──────────────┬─────────────────┘
               │ Signed Payload (mTLS / HMAC)
               ▼
┌─────────────────────────────────────────────────────────────┐
│   FastAPI & Concept-Drift Core (Backend)                    │
│   - Cryptographic Signature Verification                    │
│   - Anomaly Detector & Wasserstein/Z-Score Drift Tracker    │
│   - Uncertainty-Gated Step-Up MFA Oracle                    │
└──────────────┬──────────────────────────────────────────────┘
               │ Trust Score < 65% ?
               ▼
┌────────────────────────────────┐
│   DOM Lock Screen Enforcer     │
│   (Isolated Shadow DOM Modal)  │
│   Freezes session until TOTP   │
└────────────────────────────────┘
```

---

## Directory Structure

```
.
├── adaptive-auth-extension/       # Manifest V3 Enterprise Sensor
│   ├── manifest.json             # Extension configuration & permissions
│   ├── content.js                # Keystroke dwell/flight & mouse jerk capture + Lock screen
│   ├── background.js             # Telemetry buffering, Web Crypto HMAC signing, policy check
│   ├── popup.html                # Live Biometric HUD & Drift Simulator
│   ├── popup.js                  # Popup UI state & triggers
│   └── icons/                    # Extension icons (16, 48, 128px)
│
└── backend/                      # Continuous Authentication & ML Core
    ├── main.py                   # FastAPI application + Embedded Real-Time HUD
    ├── ml_engine.py              # Anomaly detection & Uncertainty-gated baseline retraining
    ├── test_client.py            # Automated simulation & attack injection script
    └── requirements.txt          # Dependencies (FastAPI, Uvicorn, etc.)
```

---

## Quickstart Guide

### 1. Launch the Backend Server
From the project root:
```bash
cd backend
python -m uvicorn main:app --reload --port 8000
```
- Open **http://127.0.0.1:8000** in your browser to view the **Enterprise Admin Dashboard**.

### 2. Load the Extension in Your Browser
1. Open Chrome, Brave, or Edge and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON (top-right corner).
3. Click **Load unpacked** (top-left) and select the `adaptive-auth-extension` folder.
4. Pin the extension to your toolbar.

### 3. Test & Demonstrate
- **Live Biometrics**: Open any website (e.g. Wikipedia or GitHub) and type or move your mouse. Open the extension popup to see live mean dwell time, flight time, mouse velocity, and mouse jerk.
- **Simulate Adversarial Drift**: Click **"Simulate Adversarial Drift"** in the extension popup (or on the Admin HUD). The browser page will freeze with a glassmorphic **Step-Up MFA** lock screen.
- **Unlock Session**: Enter the demo TOTP code `123456` and click **"Verify & Resume Session"**. The lock disappears and the baseline adaptively retrains.
- **Automated CLI Simulation**: Run `python backend/test_client.py` to see the entire cryptographic verification, attack detection, and baseline adaptation loop in the terminal.
