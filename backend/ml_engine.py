"""
Concept-Drift Aware Behavioral Biometrics ML Engine
Continuous Zero-Trust Authentication Core
"""

import math
import time
from typing import Dict, List, Tuple, Any

class ConceptDriftBiometricEngine:
    """
    Uncertainty-Gated Concept-Drift Biometric Engine.
    Distinguishes between:
      1. Normal Baseline User (High Trust > 80%)
      2. Benign Concept Drift (Gradual shift, e.g., fatigue or new keyboard -> Gated retraining via MFA)
      3. Adversarial Hijacking (Sudden discontinuous distribution shift -> Session Lockout)
    """

    def __init__(self):
        # Initial calibrated user baseline (means and standard deviations)
        # Keystroke dwell (ms), flight (ms), mouse velocity (px/s), mouse jerk (px/s³)
        self.baseline = {
            "meanDwellMs": {"mean": 115.0, "std": 22.0},
            "meanFlightMs": {"mean": 160.0, "std": 35.0},
            "meanMouseVelocity": {"mean": 420.0, "std": 110.0},
            "meanMouseJerk": {"mean": 18500.0, "std": 5200.0}
        }
        
        # Historical buffer of verified samples for continuous retraining
        self.verified_samples: List[Dict[str, float]] = []
        # Quarantined candidate samples waiting for Step-Up MFA verification
        self.quarantine_buffer: List[Dict[str, float]] = []
        
        # Rolling trust score (0 - 100)
        self.trust_score: float = 96.0
        self.trust_threshold: float = 65.0
        
        # Concept drift metrics
        self.drift_magnitude: float = 0.0
        self.total_retraining_events: int = 0
        self.audit_log: List[Dict[str, Any]] = []

    def log_event(self, event_type: str, details: str, severity: str = "INFO"):
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": event_type,
            "details": details,
            "severity": severity,
            "trustScore": round(self.trust_score, 1)
        }
        self.audit_log.insert(0, entry)
        if len(self.audit_log) > 50:
            self.audit_log.pop()

    def _calculate_z_scores(self, sample: Dict[str, float]) -> Dict[str, float]:
        """Compute standard deviation distances from baseline for key biometric dimensions."""
        z_scores = {}
        for feature, stats in self.baseline.items():
            val = float(sample.get(feature, stats["mean"]))
            z = abs(val - stats["mean"]) / max(stats["std"], 1e-4)
            z_scores[feature] = z
        return z_scores

    def evaluate_batch(self, samples: List[Dict[str, Any]]) -> Tuple[float, str, Dict[str, Any]]:
        """
        Evaluate an incoming batch of biometric samples from the browser extension.
        Returns:
            (new_trust_score, status_message, telemetry_metrics)
        """
        if not samples:
            return self.trust_score, "No active biometric activity", {}

        batch_z_scores = []
        for sample in samples:
            z = self._calculate_z_scores(sample)
            batch_z_scores.append(z)

        # Average Z-score across the batch
        avg_dwell_z = sum(z["meanDwellMs"] for z in batch_z_scores) / len(batch_z_scores)
        avg_flight_z = sum(z["meanFlightMs"] for z in batch_z_scores) / len(batch_z_scores)
        avg_vel_z = sum(z["meanMouseVelocity"] for z in batch_z_scores) / len(batch_z_scores)
        avg_jerk_z = sum(z["meanMouseJerk"] for z in batch_z_scores) / len(batch_z_scores)

        # Composite anomaly score (higher means greater deviation from user baseline)
        anomaly_metric = (0.35 * avg_dwell_z) + (0.25 * avg_flight_z) + (0.20 * avg_vel_z) + (0.20 * avg_jerk_z)
        self.drift_magnitude = round(float(anomaly_metric), 3)

        # Concept Drift Classification:
        # 1. Normal: anomaly < 1.8 -> Trust remains high (85-98%)
        # 2. Benign Drift Candidate: 1.8 <= anomaly < 3.2 -> Trust drops to 60-75%
        # 3. Adversarial / Severe Anomaly: anomaly >= 3.2 -> Trust plunges < 55% (LOCKOUT)
        if anomaly_metric < 1.8:
            # Baseline consistency
            recovery_delta = min(2.0, (1.8 - anomaly_metric) * 2)
            self.trust_score = min(98.0, self.trust_score + recovery_delta)
            status = "Verified: Keystroke & mouse trajectory align with user baseline"
            # Add to rolling normal samples
            self.verified_samples.extend(samples)
            if len(self.verified_samples) > 200:
                self.verified_samples = self.verified_samples[-200:]
        elif anomaly_metric < 3.2:
            # Moderate drift (fatigue, ergonomic change, or mild drift)
            penalty = anomaly_metric * 8.5
            self.trust_score = max(55.0, self.trust_score - penalty)
            status = "Drift Warning: Behavioral variation observed"
            # Place in quarantine buffer; will be merged only if user passes Step-Up MFA
            self.quarantine_buffer.extend(samples)
            self.log_event("DRIFT_WARNING", f"Moderate drift detected (Anomaly Z: {self.drift_magnitude})", "WARNING")
        else:
            # High certainty anomaly / Adversarial Session Hijack
            penalty = anomaly_metric * 14.0
            self.trust_score = max(20.0, self.trust_score - penalty)
            status = "ADVERSARIAL_ANOMALY: High deviation detected. Session lock triggered."
            self.quarantine_buffer.extend(samples)
            self.log_event("ADVERSARIAL_DRIFT", f"Severe deviation detected (Anomaly Z: {self.drift_magnitude}). Lock enforced.", "CRITICAL")

        metrics = {
            "compositeAnomaly": self.drift_magnitude,
            "avgDwellZ": round(avg_dwell_z, 2),
            "avgFlightZ": round(avg_flight_z, 2),
            "avgVelZ": round(avg_vel_z, 2),
            "avgJerkZ": round(avg_jerk_z, 2),
            "quarantinedSamples": len(self.quarantine_buffer)
        }

        return round(self.trust_score, 1), status, metrics

    def verify_mfa_and_adapt_baseline(self, success: bool) -> Tuple[bool, str]:
        """
        Human-in-the-Loop Step-Up MFA Oracle.
        Defends against adversarial model poisoning:
        - If MFA is successful: The quarantined drifted samples are confirmed to be BENIGN
          (e.g., the actual user working under different conditions). The baseline is adaptively updated!
        - If MFA fails / is rejected: The quarantined data is discarded as ADVERSARIAL POISONING attempt.
        """
        if not success:
            discarded_count = len(self.quarantine_buffer)
            self.quarantine_buffer.clear()
            self.log_event("MFA_FAILED", f"Failed Step-Up MFA attempt. Discarded {discarded_count} poisoned samples.", "CRITICAL")
            return False, "MFA Verification Failed. Quarantined data purged to prevent baseline poisoning."

        # Adaptive baseline retraining (Exponential Moving Average)
        if self.quarantine_buffer:
            n = len(self.quarantine_buffer)
            avg_dwell = sum(s.get("meanDwellMs", self.baseline["meanDwellMs"]["mean"]) for s in self.quarantine_buffer) / n
            avg_flight = sum(s.get("meanFlightMs", self.baseline["meanFlightMs"]["mean"]) for s in self.quarantine_buffer) / n
            avg_vel = sum(s.get("meanMouseVelocity", self.baseline["meanMouseVelocity"]["mean"]) for s in self.quarantine_buffer) / n
            avg_jerk = sum(s.get("meanMouseJerk", self.baseline["meanMouseJerk"]["mean"]) for s in self.quarantine_buffer) / n

            # EMA alpha weight for benign drift adaptation (e.g., 25% shift)
            alpha = 0.25
            self.baseline["meanDwellMs"]["mean"] = round(self.baseline["meanDwellMs"]["mean"] * (1 - alpha) + avg_dwell * alpha, 2)
            self.baseline["meanFlightMs"]["mean"] = round(self.baseline["meanFlightMs"]["mean"] * (1 - alpha) + avg_flight * alpha, 2)
            self.baseline["meanMouseVelocity"]["mean"] = round(self.baseline["meanMouseVelocity"]["mean"] * (1 - alpha) + avg_vel * alpha, 2)
            self.baseline["meanMouseJerk"]["mean"] = round(self.baseline["meanMouseJerk"]["mean"] * (1 - alpha) + avg_jerk * alpha, 2)

            # Move quarantined samples into verified history
            self.verified_samples.extend(self.quarantine_buffer)
            self.quarantine_buffer.clear()
            self.total_retraining_events += 1

        self.trust_score = 96.0
        self.log_event("BASELINE_RETRAINED", f"Step-Up MFA Passed. Retrained baseline with benign drift (Event #{self.total_retraining_events})", "SUCCESS")
        return True, "Identity Confirmed. Baseline adaptively retrained to accommodate benign drift."
