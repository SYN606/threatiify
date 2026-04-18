# core/detector.py

from core.config import (
    THREAT_WEIGHTS,
    MAX_SCORE,
    get_trusted_paths,
    normalize_path,
)

from core.correlator import correlate


# ─────────────────────────
# TRUST ADJUSTMENT
# ─────────────────────────
def adjust_for_trust(alert):
    path = normalize_path(alert.get("data", {}).get("path", ""))

    for trusted in get_trusted_paths():
        if path.startswith(normalize_path(trusted)):
            alert["confidence"] *= 0.5
            break

    return alert


# ─────────────────────────
# SCORING ENGINE
# ─────────────────────────
def calculate_threat_score(process_alerts,
                           startup_alerts,
                           network_alerts,
                           file_alerts=None):

    all_alerts = (
        process_alerts +
        startup_alerts +
        network_alerts +
        (file_alerts if file_alerts else [])
    )

    if not all_alerts:
        return 0

    total_score = 0
    processed_alerts = []

    for alert in all_alerts:
        alert = adjust_for_trust(alert)

        weight = THREAT_WEIGHTS.get(alert.get("type"), 0)
        severity = alert.get("severity", 1)
        confidence = alert.get("confidence", 0.5)

        score = weight * severity * confidence
        total_score += score

        processed_alerts.append(alert)

    # ─── Correlation bonus ───
    total_score += correlate(processed_alerts)

    return min(int(total_score), MAX_SCORE)


# ─────────────────────────
# RISK CLASSIFICATION
# ─────────────────────────
def get_risk_level(score):
    if score >= 85:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "SAFE"