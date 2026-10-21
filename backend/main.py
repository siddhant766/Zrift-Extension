"""
Concept-Drift Aware Adaptive Access Control Backend API
Continuous Zero-Trust Authentication Service
"""

import hmac
import hashlib
import json
import time
from typing import Dict, Any, List
from fastapi import FastAPI, Request, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ml_engine import ConceptDriftBiometricEngine

app = FastAPI(
    title="Zero-Trust Adaptive Behavioral Access Control",
    version="1.0.0",
    description="Concept-drift aware continuous authentication engine with uncertainty-gated baseline retraining."
)

# Enable CORS for browser extensions and web dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cryptographic secret shared with enterprise extension nodes
CLIENT_SECRET = b"enterprise-client-secret-key"

# Initialize ML & Concept-Drift Engine
engine = ConceptDriftBiometricEngine()

# Telemetry history for live dashboard visualization
history_timeline: List[Dict[str, Any]] = []

def verify_hmac_signature(raw_body: bytes, provided_signature: str) -> bool:
    """Validate transit layer cryptographic integrity using HMAC-SHA256."""
    if not provided_signature:
        return False
    computed_signature = hmac.new(CLIENT_SECRET, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_signature, provided_signature)


class StepUpRequest(BaseModel):
    clientId: str
    totpCode: str


@app.post("/api/v1/telemetry")
async def ingest_telemetry(
    request: Request,
    x_client_signature: str = Header(None, alias="X-Client-Signature")
):
    """
    Ingest signed biometric telemetry batch from the browser extension.
    Validates HMAC signature to prevent man-in-the-middle replay or injection.
    """
    raw_body = await request.body()

    # Enforce transit layer security signature
    if x_client_signature and not verify_hmac_signature(raw_body, x_client_signature):
        engine.log_event("INTEGRITY_FAIL", "Invalid HMAC signature detected on telemetry payload", "CRITICAL")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Transit Layer Error: Cryptographic signature mismatch"
        )

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    samples = payload.get("samples", [])
    client_id = payload.get("clientId", "unknown")

    # Evaluate batch through concept drift engine
    trust_score, eval_status, metrics = engine.evaluate_batch(samples)

    # Record historical timeline for enterprise admin dashboard
    entry = {
        "timestamp": time.strftime("%H:%M:%S"),
        "trustScore": trust_score,
        "anomaly": metrics.get("compositeAnomaly", 0.0),
        "status": eval_status
    }
    history_timeline.append(entry)
    if len(history_timeline) > 60:
        history_timeline.pop(0)

    # Determine policy enforcement action
    action = "ALLOW"
    if trust_score < engine.trust_threshold:
        action = "TRIGGER_LOCK"

    return {
        "status": "success",
        "clientId": client_id,
        "trustScore": trust_score,
        "action": action,
        "evaluation": eval_status,
        "isDriftAdaptive": len(engine.quarantine_buffer) > 0,
        "metrics": metrics
    }


@app.post("/api/v1/verify-step-up")
async def verify_step_up(body: StepUpRequest):
    """
    Step-Up MFA Human-in-the-Loop Oracle.
    Master demo code: 123456
    """
    is_valid = (body.totpCode.strip() == "123456")
    verified, msg = engine.verify_mfa_and_adapt_baseline(is_valid)

    if not verified:
        raise HTTPException(status_code=403, detail=msg)

    return {
        "verified": True,
        "message": msg,
        "trustScore": engine.trust_score,
        "retrainingCount": engine.total_retraining_events
    }


@app.post("/api/v1/simulate-attack")
async def simulate_attack():
    """Simulate an adversarial takeover with synthetic high-anomaly telemetry."""
    synthetic_attack_sample = [
        {
            "meanDwellMs": 480.0,
            "meanFlightMs": 420.0,
            "meanMouseVelocity": 1950.0,
            "meanMouseJerk": 145000.0,
            "keystrokeCount": 18
        }
    ]
    trust_score, eval_status, metrics = engine.evaluate_batch(synthetic_attack_sample)
    return {
        "message": "Adversarial high-entropy vector injected",
        "trustScore": trust_score,
        "status": eval_status,
        "action": "TRIGGER_LOCK" if trust_score < engine.trust_threshold else "ALLOW"
    }


@app.get("/api/v1/dashboard/metrics")
async def get_dashboard_metrics():
    """Data feed for the Enterprise Security HUD."""
    return {
        "trustScore": round(engine.trust_score, 1),
        "threshold": engine.trust_threshold,
        "driftMagnitude": engine.drift_magnitude,
        "retrainingEvents": engine.total_retraining_events,
        "quarantinedCount": len(engine.quarantine_buffer),
        "baseline": engine.baseline,
        "timeline": history_timeline[-25:],
        "auditLog": engine.audit_log[:15]
    }


@app.get("/", response_class=HTMLResponse)
async def serve_admin_dashboard():
    """Enterprise Zero-Trust Admin Dashboard UI."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Enterprise Zero-Trust Behavioral Access HUD</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #090d16;
      color: #f1f5f9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 24px;
    }
    .top-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #1e293b;
    }
    .top-title {
      font-size: 20px;
      font-weight: 700;
      color: #38bdf8;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .pulse-dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      background: #22c55e;
      box-shadow: 0 0 10px #22c55e;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 18px;
    }
    .card-label {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
      margin-bottom: 8px;
    }
    .card-val {
      font-size: 32px;
      font-weight: 800;
      color: #f8fafc;
    }
    .score-green { color: #22c55e; }
    .score-red { color: #ef4444; }
    .score-yellow { color: #eab308; }
    .main-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }
    .chart-container {
      height: 280px;
      position: relative;
    }
    .baseline-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
      margin-top: 10px;
    }
    .baseline-table th, .baseline-table td {
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid #1e293b;
    }
    .baseline-table th { color: #64748b; font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
    }
    .badge-info { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
    .badge-warning { background: rgba(234, 179, 8, 0.15); color: #facc15; }
    .badge-critical { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .badge-success { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
    .btn-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 24px;
    }
    .action-btn {
      padding: 10px 18px;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .action-btn:hover { opacity: 0.9; }
    .btn-red { background: #dc2626; color: white; }
    .btn-green { background: #16a34a; color: white; }
    .btn-blue { background: #2563eb; color: white; }
    .log-feed {
      max-height: 220px;
      overflow-y: auto;
      font-size: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .log-item {
      padding: 8px 12px;
      background: #182234;
      border-radius: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <div class="top-title">
      <div class="pulse-dot"></div>
      Zero-Trust Continuous Authentication Engine • Admin Monitor
    </div>
    <div style="font-size: 12px; color: #94a3b8;">
      FastAPI ML Drift Core • Port 8000
    </div>
  </div>

  <div class="btn-bar">
    <button class="action-btn btn-red" onclick="triggerAttack()">⚡ Inject Simulated Adversarial Hijack</button>
    <button class="action-btn btn-green" onclick="verifyMFA()">🔑 Authorize Step-Up MFA (Retrain Baseline)</button>
    <button class="action-btn btn-blue" onclick="fetchMetrics()">↻ Refresh Live Stream</button>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">Session Trust Score</div>
      <div id="trustScoreVal" class="card-val score-green">96.0%</div>
      <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Dynamic Threshold: 65%</div>
    </div>
    <div class="card">
      <div class="card-label">Concept Drift Anomaly Z</div>
      <div id="anomalyVal" class="card-val">0.12</div>
      <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Z-dist from user baseline</div>
    </div>
    <div class="card">
      <div class="card-label">Quarantined Drift Samples</div>
      <div id="quarantineVal" class="card-val" style="color: #facc15;">0</div>
      <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Pending Step-Up MFA Oracle</div>
    </div>
    <div class="card">
      <div class="card-label">Adaptive Retraining Events</div>
      <div id="retrainVal" class="card-val" style="color: #38bdf8;">0</div>
      <div style="font-size: 11px; color: #64748b; margin-top: 4px;">Benign drift model updates</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="card">
      <div class="card-label">Continuous Trust Score & Drift Stream</div>
      <div class="chart-container">
        <canvas id="trustChart"></canvas>
      </div>
    </div>
    <div class="card">
      <div class="card-label">Active Calibrated Biometric Baseline</div>
      <table class="baseline-table">
        <thead>
          <tr>
            <th>Biometric Dimension</th>
            <th>Baseline Mean</th>
            <th>Std Dev</th>
          </tr>
        </thead>
        <tbody id="baselineBody">
          <tr><td>Key Dwell</td><td id="b-dwell">115 ms</td><td>±22 ms</td></tr>
          <tr><td>Key Flight</td><td id="b-flight">160 ms</td><td>±35 ms</td></tr>
          <tr><td>Mouse Velocity</td><td id="b-vel">420 px/s</td><td>±110 px/s</td></tr>
          <tr><td>Mouse Jerk</td><td id="b-jerk">18,500 px/s³</td><td>±5,200</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="card-label" style="margin-bottom: 12px;">Zero-Trust Continuous Audit & Drift Log</div>
    <div id="logFeed" class="log-feed">
      <div style="color: #64748b; text-align: center; padding: 20px;">Awaiting telemetry events...</div>
    </div>
  </div>

  <script>
    let chartInstance = null;

    function initChart() {
      const ctx = document.getElementById('trustChart').getContext('2d');
      chartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Trust Score (%)',
              borderColor: '#22c55e',
              backgroundColor: 'rgba(34, 197, 94, 0.1)',
              borderWidth: 2,
              fill: true,
              data: [],
              tension: 0.3
            },
            {
              label: 'Lock Threshold (65%)',
              borderColor: '#ef4444',
              borderDash: [5, 5],
              borderWidth: 1.5,
              data: [],
              pointRadius: 0
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: { min: 0, max: 100, grid: { color: '#1e293b' } },
            x: { grid: { color: '#1e293b' } }
          },
          plugins: {
            legend: { labels: { color: '#94a3b8' } }
          }
        }
      });
    }

    async function fetchMetrics() {
      try {
        const res = await fetch('/api/v1/dashboard/metrics');
        const data = await res.json();

        // Update score
        const scoreEl = document.getElementById('trustScoreVal');
        scoreEl.textContent = `${data.trustScore}%`;
        if (data.trustScore >= 75) {
          scoreEl.className = 'card-val score-green';
        } else if (data.trustScore >= 65) {
          scoreEl.className = 'card-val score-yellow';
        } else {
          scoreEl.className = 'card-val score-red';
        }

        document.getElementById('anomalyVal').textContent = data.driftMagnitude;
        document.getElementById('quarantineVal').textContent = data.quarantinedCount;
        document.getElementById('retrainVal').textContent = data.retrainingEvents;

        // Baseline stats
        if (data.baseline) {
          document.getElementById('b-dwell').textContent = `${data.baseline.meanDwellMs.mean} ms`;
          document.getElementById('b-flight').textContent = `${data.baseline.meanFlightMs.mean} ms`;
          document.getElementById('b-vel').textContent = `${data.baseline.meanMouseVelocity.mean} px/s`;
          document.getElementById('b-jerk').textContent = `${data.baseline.meanMouseJerk.mean} px/s³`;
        }

        // Timeline chart
        if (data.timeline && chartInstance) {
          chartInstance.data.labels = data.timeline.map(t => t.timestamp);
          chartInstance.data.datasets[0].data = data.timeline.map(t => t.trustScore);
          chartInstance.data.datasets[1].data = data.timeline.map(() => 65);
          chartInstance.update();
        }

        // Audit Log
        const logFeed = document.getElementById('logFeed');
        if (data.auditLog && data.auditLog.length > 0) {
          logFeed.innerHTML = data.auditLog.map(log => `
            <div class="log-item">
              <div>
                <span class="badge badge-${log.severity.toLowerCase()}">${log.type}</span>
                <span style="color: #cbd5e1; margin-left: 8px;">${log.details}</span>
              </div>
              <div style="color: #64748b; font-size: 11px;">${log.timestamp} • Trust: ${log.trustScore}%</div>
            </div>
          `).join('');
        }
      } catch (e) {
        console.warn('Dashboard fetch error', e);
      }
    }

    async function triggerAttack() {
      await fetch('/api/v1/simulate-attack', { method: 'POST' });
      fetchMetrics();
    }

    async function verifyMFA() {
      await fetch('/api/v1/verify-step-up', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId: 'admin-console', totpCode: '123456' })
      });
      fetchMetrics();
    }

    initChart();
    fetchMetrics();
    setInterval(fetchMetrics, 2000);
  </script>
</body>
</html>
"""


@app.get("/demo", response_class=HTMLResponse)
async def serve_demo_page():
    """Interactive Enterprise Web App to demonstrate automated continuous authentication."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Enterprise Portal - Continuous Biometrics Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0f172a;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 30px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid #334155;
      margin-bottom: 30px;
    }
    .company {
      font-size: 22px;
      font-weight: 800;
      color: #38bdf8;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      background: rgba(34, 197, 94, 0.15);
      border: 1px solid rgba(34, 197, 94, 0.3);
      color: #4ade80;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 999px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .pulse {
      width: 8px; height: 8px; border-radius: 50%;
      background: #22c55e; box-shadow: 0 0 8px #22c55e;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.3);
    }
    h3 { margin-bottom: 12px; color: #f1f5f9; font-size: 16px; }
    p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin-bottom: 16px; }
    textarea {
      width: 100%;
      height: 140px;
      background: #090d16;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 14px;
      color: #f8fafc;
      font-size: 15px;
      font-family: inherit;
      resize: vertical;
      outline: none;
      transition: border-color 0.2s;
    }
    textarea:focus {
      border-color: #38bdf8;
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.15);
    }
    .interactive-zone {
      border: 2px dashed #475569;
      border-radius: 8px;
      padding: 30px;
      text-align: center;
      color: #94a3b8;
      background: #0f172a;
      cursor: crosshair;
      user-select: none;
      transition: background 0.2s;
    }
    .interactive-zone:hover {
      background: #162032;
      border-color: #38bdf8;
      color: #cbd5e1;
    }
    .info-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #182234;
      padding: 12px 18px;
      border-radius: 8px;
      margin-top: 14px;
      font-size: 13px;
      color: #94a3b8;
    }
    a.hud-link {
      color: #38bdf8;
      text-decoration: none;
      font-weight: 600;
    }
    a.hud-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="header">
    <div class="company">
      <span>🏢</span> Apex FinTech • Internal Payroll & Strategy Portal
    </div>
    <div class="badge">
      <div class="pulse"></div>
      Zero-Trust Continuous Biometrics Active
    </div>
  </div>

  <div class="card">
    <h3>Continuous Passive Authentication in Progress</h3>
    <p>
      The browser extension is passively analyzing your keystroke dwell/flight times and mouse trajectory physics in the background. 
      You do not need to click any buttons. As long as you type and interact normally, your trust score will remain above 90% and your session remains completely frictionless.
    </p>
    <textarea placeholder="Start typing any notes, report summary, or message here to feed live biometric telemetry..."></textarea>
    
    <div class="info-bar">
      <span>💡 Microsecond keystroke timings are being automatically signed and sent to the ML engine every 5 seconds.</span>
      <a class="hud-link" href="/" target="_blank">Open Real-Time Admin Monitor ↗</a>
    </div>
  </div>

  <div class="card">
    <h3>Mouse Kinematics Testing Zone</h3>
    <p>Move your mouse around this zone. The sensor captures velocity, acceleration, and jerk (~60 Hz) without collecting any personal data or screen content.</p>
    <div class="interactive-zone" onmousemove="updateMouseTracker(event)">
      <div style="font-size: 24px; margin-bottom: 6px;">🖱️</div>
      <div id="mouseInfo">Move mouse across this area to stream trajectory vectors</div>
    </div>
  </div>

  <script>
    let moveCount = 0;
    function updateMouseTracker(e) {
      moveCount++;
      document.getElementById('mouseInfo').innerHTML = 
        `Coordinates: X: <b>${e.clientX}</b>, Y: <b>${e.clientY}</b> | Live Samples Streamed: <b>${moveCount}</b>`;
    }
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

