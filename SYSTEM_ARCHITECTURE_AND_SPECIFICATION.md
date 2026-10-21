# System Architecture & Technical Specification: Concept-Drift-Aware Adaptive Access Control

**System Title:** Concept-Drift-Aware Adaptive Access Control for Continuous Zero-Trust Authentication  
**Specification Version:** 1.0.0  
**Target Environment:** Manifest V3 Browser Extension (Client), FastAPI / Python 3.14 (ML Core), Zero-Trust Admin HUD  
**Domain:** Continuous Behavioral Biometrics, Zero-Trust Architecture (ZTA), Concept-Drift Adaptation, Adversarial Defense  

---

## 1. Executive Summary & Problem Formulation

### 1.1 The Vulnerability of Point-in-Time Authentication
Contemporary authentication architectures (passwords, multi-factor authentication, TOTP, WebAuthn/FIDO2) operate on a **point-in-time** verification model. Once the user satisfies authentication at step zero ($t = 0$), the security perimeter assumes the session remains trusted indefinitely until cookie expiration or manual logout ($t = T_{\text{expiry}}$).

This paradigm introduces severe attack surfaces:
1. **Session Hijacking / Post-Auth Physical Takeover:** An authorized employee steps away from their workstation; an insider or unauthorized party assumes control of the active session.
2. **Reverse Proxy Session Theft:** Attackers steal session cookies through AitM (Adversary-in-the-Middle) phishing, bypassing MFA entirely.
3. **Application State Destruction:** Traditional Zero Trust Network Access (ZTNA) solutions terminate the underlying TCP/TLS proxy connection when anomalies occur, causing permanent data loss on unsaved forms, active IDE sessions, or enterprise SaaS inputs.

### 1.2 Proposed Continuous Solution
This system implements **Passive Continuous Behavioral Authentication** using a privacy-preserving Manifest V3 browser extension sensor coupled with a real-time Machine Learning and Concept-Drift Engine. Identity is treated as a continuous stochastic variable modeled through neuromuscular timing intervals and mouse kinematics.

Crucially, it introduces an **Uncertainty-Gated Step-Up MFA Oracle** to solve the fundamental academic challenge in behavioral biometrics: distinguishing between **benign human behavioral drift** (fatigue, ergonomic change, hardware swap) and **adversarial takeover / model poisoning**.

---

## 2. High-Level System Architecture

```mermaid
flowchart TD
    subgraph ClientTier ["Client-Side Sensor Tier (Manifest V3)"]
        DOM["Active Web Page DOM\n(Any Web Application)"]
        CS["content.js\nPrivacy-Preserving Telemetry Sensor\n• Dwell / Flight Timers\n• Mouse Kinematics (~60Hz)"]
        Shadow["Isolated Shadow DOM Host\n• Glassmorphic Lock Screen\n• z-index: 2147483647\n• In-place State Preservation"]
        SW["background.js\nEvent-Driven Service Worker\n• In-Memory Buffer\n• Web Crypto HMAC-SHA256\n• Tab Context Tracker"]
        Popup["popup.html / popup.js\nLive HUD & Drift Simulator"]

        DOM -->|Passive Raw Events| CS
        CS -->|Biometric Summary Vectors (5s)| SW
        SW -->|TRIGGER_LOCK / RELEASE_LOCK| CS
        CS -->|Inject / Remove| Shadow
        SW <-->|Query / Simulate| Popup
    end

    subgraph TransitTier ["Secure Transit Layer"]
        HMAC["Cryptographic Envelope\n• Header: X-Client-Signature (HMAC-SHA256)\n• Body: ClientId + Timestamp + Batch"]
    end

    subgraph ServerTier ["Backend & ML Engine Tier (FastAPI Core)"]
        API["FastAPI Ingestion Endpoint\n/api/v1/telemetry"]
        CryptoVerif["HMAC-SHA256 Verification\nConstant-Time Digest Comparison"]
        MLEngine["ConceptDriftBiometricEngine\nml_engine.py"]
        ZScore["Feature Extraction &\nStandardized Z-Score Engine"]
        Quarantine["Quarantine Buffer\nCandidate Drift Samples"]
        Baseline["Calibrated User Baseline\n(Means & Standard Deviations)"]
        MFAOracle["Step-Up MFA Oracle\n/api/v1/verify-step-up\nHuman-in-the-Loop Verifier"]

        API --> CryptoVerif
        CryptoVerif -->|Valid Signature| MLEngine
        MLEngine --> ZScore
        ZScore --> Baseline
        MLEngine -->|Benign Drift Candidate| Quarantine
        MFAOracle -->|Verified: EMA Retraining| Baseline
        MFAOracle -->|Failed: Purge Poison| Quarantine
    end

    subgraph AdminTier ["Enterprise Governance Tier"]
        Dashboard["Enterprise Admin Monitor\n• Real-Time Chart.js Stream\n• Live Baseline Table\n• Audit Event Feed\n• Attack Simulator"]
    end

    SW -->|POST /api/v1/telemetry| HMAC
    HMAC --> API
    API -->|Trust Score + Action| SW
    MLEngine -->|Streaming Metrics & Audit Logs| Dashboard
```

---

## 3. Mathematical Formulations & Physics Modeling

The sensor captures behavioral telemetry across two independent biomechanical channels without logging sensitive inputs.

```
+----------------------------------------------------------------------------+
|                  PRIVACY INVARIANT (ZERO KEYLOGGING)                       |
|   Neither e.key, e.code, nor input string values are EVER captured.        |
|   Only monotonic clock deltas (performance.now()) are recorded.           |
+----------------------------------------------------------------------------+
```

### 3.1 Keystroke Dynamics

```
Key Down Event (i-1)      Key Up Event (i-1)       Key Down Event (i)       Key Up Event (i)
      |                         |                        |                        |
      +--- Dwell Time (i-1) ----+                        +--- Dwell Time (i) ----+
      |                         |                        |                        |
      |                         +--- Flight Time (i) ----+                        |
```

1. **Keystroke Dwell Time ($T_{\text{dwell}}$):** The duration a physical key remains depressed.
   $$T_{\text{dwell}, k} = t_{\text{keyup}, k} - t_{\text{keydown}, k}$$
   Filtered bounds: $5\text{ ms} \le T_{\text{dwell}, k} \le 2000\text{ ms}$.

2. **Keystroke Flight Time ($T_{\text{flight}}$):** The transition latency between releasing one key and pressing the subsequent key.
   $$T_{\text{flight}, k} = t_{\text{keydown}, k} - t_{\text{keyup}, k-1}$$
   Filtered bounds: $5\text{ ms} \le T_{\text{flight}, k} \le 2500\text{ ms}$ (pauses $> 2.5\text{s}$ are treated as idle cognitive pauses and pruned).

3. **Windowed Keystroke Statistical Summary:**
   $$\mu_{\text{dwell}} = \frac{1}{N_k} \sum_{i=1}^{N_k} T_{\text{dwell}, i}, \quad \sigma_{\text{dwell}} = \sqrt{\frac{1}{N_k} \sum_{i=1}^{N_k} (T_{\text{dwell}, i} - \mu_{\text{dwell}})^2}$$
   $$\mu_{\text{flight}} = \frac{1}{M_k} \sum_{i=1}^{M_k} T_{\text{flight}, i}, \quad \sigma_{\text{flight}} = \sqrt{\frac{1}{M_k} \sum_{i=1}^{M_k} (T_{\text{flight}, i} - \mu_{\text{flight}})^2}$$

---

### 3.2 Mouse Kinematics (Velocity, Acceleration, Jerk)

Mouse movement vectors are sampled at $\sim 60\text{ Hz}$ ($\Delta t \ge 0.016\text{ s}$) to prevent browser execution thread saturation:

1. **Euclidean Displacement ($\Delta d$):**
   $$\Delta d = \sqrt{(x_t - x_{t-1})^2 + (y_t - y_{t-1})^2}$$

2. **Instantaneous Velocity ($v$):**
   $$v(t) = \frac{\Delta d}{\Delta t} \quad [\text{pixels/second}]$$

3. **Instantaneous Acceleration ($a$):**
   $$a(t) = \frac{v(t) - v(t-1)}{\Delta t} \quad [\text{pixels/second}^2]$$

4. **Instantaneous Jerk ($j$):** The first derivative of acceleration with respect to time (the rate of change of acceleration), which reflects unconscious neuromuscular motor control:
   $$j(t) = \frac{|a(t) - a(t-1)|}{\Delta t} \quad [\text{pixels/second}^3]$$

5. **Windowed Mouse Statistical Summary:**
   $$\mu_{\text{vel}} = \frac{1}{N_m} \sum_{i=1}^{N_m} v_i, \quad \mu_{\text{jerk}} = \frac{1}{N_j} \sum_{i=1}^{N_j} j_i$$

---

### 3.3 Anomaly Scoring & Standardization

For each incoming batch of biometric vectors, features are standardized against the active user baseline profile $\mathcal{B}$:

$$\mathcal{B} = \left\{ \mu_{f}, \sigma_{f} \mid f \in \{\text{dwell}, \text{flight}, \text{velocity}, \text{jerk}\} \right\}$$

1. **Standardized Feature Deviation ($Z$-score):**
   $$Z_f = \frac{|\bar{x}_f - \mu_f|}{\max(\sigma_f, \epsilon)}$$
   where $\epsilon = 10^{-4}$ prevents division-by-zero instability.

2. **Composite Anomaly Metric ($A$):**
   $$A = w_1 Z_{\text{dwell}} + w_2 Z_{\text{flight}} + w_3 Z_{\text{vel}} + w_4 Z_{\text{jerk}}$$
   *Feature Weight Distribution:*
   - $w_1 = 0.35$ (Dwell time: highest individual specificity)
   - $w_2 = 0.25$ (Flight time: cadence pattern)
   - $w_3 = 0.20$ (Mouse velocity: motor speed)
   - $w_4 = 0.20$ (Mouse jerk: tremor and trajectory curvature)
   $$\sum_{i=1}^4 w_i = 1.0$$

---

### 3.4 Dynamic Trust Score Calibration

The continuous Trust Score $S_t \in [0, 100]$ evolves dynamically based on the composite anomaly metric $A$:

$$S_t = \begin{cases}
  \min\left(98.0, \, S_{t-1} + \min(2.0, (1.8 - A) \cdot 2.0)\right) & \text{if } A < 1.8 \quad \text{[Legitimate Baseline]} \\
  \max\left(55.0, \, S_{t-1} - 8.5 \cdot A\right) & \text{if } 1.8 \le A < 3.2 \quad \text{[Benign Drift Candidate]} \\
  \max\left(20.0, \, S_{t-1} - 14.0 \cdot A\right) & \text{if } A \ge 3.2 \quad \text{[Adversarial Hijack]}
\end{cases}$$

```
Trust Score Scale:
100% ────────────────────────── [Calibrated / Verified User]
 85% ────────────────────────── [Normal Behavioral Variance]
 65% ─── TRUST THRESHOLD ────── [ZERO-TRUST ENFORCEMENT BOUNDARY]
 45% ────────────────────────── [Uncertainty Quarantine / Drift Flagged]
 20% ────────────────────────── [Adversarial Lockout Enforced]
```

### 3.5 Policy Decision Function
$$\text{PolicyAction}(S_t) = \begin{cases}
  \text{ALLOW} & \text{if } S_t \ge 65.0 \\
  \text{TRIGGER\_LOCK} & \text{if } S_t < 65.0
\end{cases}$$

---

## 4. Uncertainty & Concept-Drift Engine (The Retraining Oracle)

### 4.1 The Fundamental Dilemma: FRR vs. Model Poisoning
- **Traditional Static Baseline:** Causes high False Reject Rates (FRR) over time as legitimate users experience benign drift (e.g., typing one-handed, mechanical keyboard change, fatigue, injury).
- **Naive Continuous Retraining:** Vulnerable to **Adversarial Creep (Model Poisoning)**, where an attacker slowly mimics the user or gradually introduces altered behaviors until the model accepts the attacker as baseline.

### 4.2 Uncertainty-Gated Human-in-the-Loop Oracle
The engine resolves this dilemma by decoupling anomaly detection from model retraining through a **Quarantine Buffer ($\mathcal{Q}$)** and a **Step-Up MFA Oracle**:

```
[Incoming High-Anomaly Batch]
               │
               ▼
   Placed in Quarantine Buffer (Q)
   Trust Score Drops < 65%
   Shadow DOM Screen Locks
               │
               ▼
      [Step-Up MFA Prompt]
               │
        ┌──────┴──────┐
        ▼             ▼
  [MFA SUCCESS]  [MFA FAILED / TIMEOUT]
        │             │
        │             ▼
        │        Purge Q immediately
        │        (Poisoning Neutralized)
        ▼
  Exponential Moving Average (EMA)
  Adaptive Baseline Update:
  μ_new = (1 - α) * μ_old + α * μ_Q
```

### 4.3 Retraining Equations (EMA Adaptation)
When Step-Up MFA verification succeeds ($V_{\text{MFA}} = \text{True}$), the quarantined samples are authenticated as benign human drift. Baseline parameters adapt via Exponential Moving Average with learning rate $\alpha = 0.25$:

$$\mu_{f}^{(k+1)} = (1 - \alpha) \mu_{f}^{(k)} + \alpha \left(\frac{1}{|\mathcal{Q}|} \sum_{s \in \mathcal{Q}} x_{f, s}\right)$$

If MFA fails ($V_{\text{MFA}} = \text{False}$):
$$\mathcal{Q} \leftarrow \emptyset$$
The candidate samples are discarded; baseline parameters remain pristine.

---

## 5. Component Specifications & Protocols

### 5.1 Client-Side Sensor (`content.js`)
- **Execution Context:** Isolated world in target web page DOM (`run_at: "document_idle"`).
- **Event Listeners:** Capture-phase window listeners (`keydown`, `keyup`, `mousemove`).
- **Buffer Flush Cycle:** Every 5,000 ms via `setInterval`.
- **Enforcement Host:** Attached to `document.documentElement` inside an isolated Shadow DOM (`mode: "open"`).
- **CSS Isolation:** Prevents parent web application CSS rules (Tailwind, Bootstrap, resets) from distorting or concealing the lock screen.

### 5.2 Service Worker (`background.js`)
- **Execution Context:** Manifest V3 Event-driven service worker.
- **Navigation Context:** Tracks `chrome.tabs.onActivated` to monitor tab switching frequency.
- **Web Crypto Signing:** Signs payload using HMAC-SHA256 (`crypto.subtle.importKey`, `crypto.subtle.sign`).
- **State Storage:** Persists live trust score, status badge, and latest biometric vector in `chrome.storage.local`.

### 5.3 Secure Transit Layer (`backend/main.py`)
- **Header:** `X-Client-Signature: <64-character hex HMAC-SHA256>`
- **Payload Schema:**
  ```json
  {
    "clientId": "ext-node-01",
    "timestamp": 1729497000000,
    "tabSwitches": 2,
    "samples": [
      {
        "timestamp": 1729496995000,
        "urlHost": "workspace.internal",
        "meanDwellMs": 118.5,
        "stdDwellMs": 18.2,
        "meanFlightMs": 162.1,
        "stdFlightMs": 31.0,
        "keystrokeCount": 32,
        "meanMouseVelocity": 435.0,
        "maxMouseVelocity": 1120.0,
        "meanMouseJerk": 19200.0,
        "mouseSampleCount": 85
      }
    ]
  }
  ```
- **Cryptographic Verification:**
  $$\text{Valid} \iff \text{HMAC-SHA256}(K, \text{RawBody}) = \text{X-Client-Signature}$$
  Computed using constant-time string comparison (`hmac.compare_digest`) to prevent timing attacks.

---

## 6. Novelty Matrix: Competitive & Academic Positioning

| Dimension | Conventional Industry SDKs (BioCatch, TypingDNA) | Standard Academic Research Papers | **This Architecture** |
| :--- | :--- | :--- | :--- |
| **Deployment Model** | 1st-party Website JS SDK (Single domain only) | Static offline CSV dataset evaluations | **Manifest V3 Enterprise Extension** (Cross-SaaS across GitHub, AWS, Salesforce) |
| **Model Retraining** | Black-box cloud heuristics; rarely retrains dynamically | Static train/test split; zero drift accommodation | **Uncertainty-Gated Drift Engine** with EMA adaptation |
| **Poisoning Defense** | Vulnerable to gradual adversarial mimicry | Not addressed in most benchmarks | **Step-Up MFA Oracle** gates all baseline updates |
| **Enforcement Mechanism** | Redirects to login page or terminates TCP session | Simulation metric only (EER / FAR / FRR) | **Shadow DOM In-DOM Freeze** preserving application state |
| **Data Privacy** | Raw key character sequences often hashed | Raw character logs | **Strict Privacy Invariant:** Zero key characters logged |

---

## 7. API Reference

| Endpoint | Method | Security | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/telemetry` | `POST` | HMAC-SHA256 Header | Ingests signed biometric batches, evaluates anomaly score, returns trust score & policy action. |
| `/api/v1/verify-step-up` | `POST` | JSON Body | Validates TOTP code (`123456`), unlocks session, and executes adaptive baseline retraining. |
| `/api/v1/simulate-attack` | `POST` | None (Demo) | Injects high-variance synthetic vectors to demonstrate instant lockout. |
| `/api/v1/dashboard/metrics` | `GET` | CORS Open | Feeds real-time trust score timeline, baseline stats, and audit log to the Admin HUD. |
| `/` | `GET` | None | Serves the Enterprise Admin Dashboard HUD. |
| `/demo` | `GET` | None | Serves the Interactive Employee Portal testing pad. |

---

## 8. Summary Audit Log Event Types

```
[BASELINE_RETRAINED] -> Step-Up MFA passed; baseline adapted to benign drift.
[ADVERSARIAL_DRIFT]   -> Composite anomaly exceeded threshold; DOM lock triggered.
[DRIFT_WARNING]       -> Moderate behavioral variation placed in quarantine.
[MFA_FAILED]          -> Invalid TOTP entered; quarantine buffer purged to prevent poisoning.
[INTEGRITY_FAIL]      -> Invalid HMAC-SHA256 signature; HTTP 401 rejected.
```
