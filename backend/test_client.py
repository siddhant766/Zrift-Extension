"""
End-to-End Test and Simulation Client for Concept-Drift Adaptive Zero-Trust Access Control
Demonstrates:
  1. Cryptographic HMAC-SHA256 Payload Signing (Transit Layer)
  2. Baseline Telemetry Verification (High Trust)
  3. Adversarial Session Hijack (Plunging Trust & Lockout)
  4. Benign Drift Adaptation via Step-Up MFA Oracle
"""

import hmac
import hashlib
import json
import time
import urllib.request
import urllib.error

API_URL = "http://127.0.0.1:8000"
CLIENT_SECRET = b"enterprise-client-secret-key"
CLIENT_ID = "ext-node-01"

def sign_payload(payload_bytes: bytes) -> str:
    """Generate HMAC-SHA256 signature for transit integrity."""
    return hmac.new(CLIENT_SECRET, payload_bytes, hashlib.sha256).hexdigest()

def send_telemetry(samples, desc=""):
    print(f"\n--- [Telemetry Batch: {desc}] ---")
    data = {
        "clientId": CLIENT_ID,
        "timestamp": int(time.time() * 1000),
        "tabSwitches": 1,
        "samples": samples
    }
    raw_json = json.dumps(data).encode("utf-8")
    sig = sign_payload(raw_json)

    req = urllib.request.Request(
        f"{API_URL}/api/v1/telemetry",
        data=raw_json,
        headers={
            "Content-Type": "application/json",
            "X-Client-Signature": sig
        }
    )

    try:
        with urllib.request.urlopen(req) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            print(f"  • Trust Score: {res_data['trustScore']}%")
            print(f"  • Policy Action: {res_data['action']}")
            print(f"  • Anomaly Metric (Z): {res_data['metrics'].get('compositeAnomaly')}")
            print(f"  • Evaluation: {res_data['evaluation']}")
            return res_data
    except urllib.error.HTTPError as e:
        print(f"  [ERROR {e.code}] {e.read().decode('utf-8')}")
        return None
    except Exception as e:
        print(f"  [CONNECTION FAILED] Ensure FastAPI backend is running! Details: {e}")
        return None

def submit_step_up_mfa(totp_code="123456"):
    print(f"\n--- [Submitting Step-Up MFA (Code: {totp_code})] ---")
    data = json.dumps({"clientId": CLIENT_ID, "totpCode": totp_code}).encode("utf-8")
    req = urllib.request.Request(
        f"{API_URL}/api/v1/verify-step-up",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            res_data = json.loads(resp.read().decode("utf-8"))
            print(f"  • MFA Status: SUCCESS")
            print(f"  • Message: {res_data['message']}")
            print(f"  • New Calibrated Trust Score: {res_data['trustScore']}%")
            return res_data
    except urllib.error.HTTPError as e:
        print(f"  [MFA REJECTED {e.code}] {e.read().decode('utf-8')}")
        return None

def run_simulation():
    print("==================================================================")
    print("Zero-Trust Continuous Biometrics Simulation Starting...")
    print("==================================================================")

    # 1. Normal Baseline User typing
    normal_samples = [
        {"meanDwellMs": 114.0, "meanFlightMs": 158.0, "meanMouseVelocity": 425.0, "meanMouseJerk": 18200.0, "keystrokeCount": 24},
        {"meanDwellMs": 118.0, "meanFlightMs": 162.0, "meanMouseVelocity": 415.0, "meanMouseJerk": 18700.0, "keystrokeCount": 28}
    ]
    send_telemetry(normal_samples, "Legitimate User (Normal Baseline)")

    # 2. Moderate Behavioral Drift (e.g. fatigue or new mechanical keyboard)
    drift_samples = [
        {"meanDwellMs": 165.0, "meanFlightMs": 220.0, "meanMouseVelocity": 580.0, "meanMouseJerk": 26000.0, "keystrokeCount": 20},
        {"meanDwellMs": 172.0, "meanFlightMs": 228.0, "meanMouseVelocity": 595.0, "meanMouseJerk": 27500.0, "keystrokeCount": 22}
    ]
    send_telemetry(drift_samples, "Moderate Drift (Fatigue / New Hardware)")

    # 3. Adversarial Takeover / Session Hijack
    attack_samples = [
        {"meanDwellMs": 380.0, "meanFlightMs": 480.0, "meanMouseVelocity": 1850.0, "meanMouseJerk": 135000.0, "keystrokeCount": 15}
    ]
    res = send_telemetry(attack_samples, "ADVERSARIAL HIJACK DETECTED (High Variance)")

    # 4. Attacker attempts bad MFA
    submit_step_up_mfa("999999")

    # 5. Legitimate user submits correct TOTP -> Recalibrate & Retrain Baseline
    submit_step_up_mfa("123456")

    print("\n==================================================================")
    print("Simulation Complete! Visit http://127.0.0.1:8000 to view the HUD.")
    print("==================================================================")

if __name__ == "__main__":
    run_simulation()
