# ─────────────────────────
# CONFIG (Weights)
# ─────────────────────────

PROCESS_WEIGHTS = {
    "Suspicious keyword": 30,
    "Running from suspicious path": 20,
    "Unknown executable path": 10,
    "High CPU usage": 10,
}

STARTUP_WEIGHTS = {
    "Runs from suspicious path": 35,
    "Suspicious keyword": 40,
    "Script-based execution": 25,
    "Executable not found": 20,
}

NETWORK_WEIGHTS = {
    "Unusual port": 10,
    "Suspicious process name": 35,
    "Abnormal state": 15,
    "Running from suspicious path": 20,
}

FILE_WEIGHTS = {
    "High frequency writes": 25,
    "Suspicious location": 20,
    "Repeated writes to log-like file": 15,
    "Hidden file activity": 15,
    "Large file activity": 10,
}


# ─────────────────────────
# HELPERS
# ─────────────────────────
def _score_from_reasons(reason_string, weight_map):
    score = 0

    for key, weight in weight_map.items():
        if key.lower() in reason_string.lower():
            score += weight

    return score


# ─────────────────────────
# CORE SCORING ENGINE
# ─────────────────────────
def calculate_threat_score(process_alerts,
                           startup_alerts,
                           network_alerts,
                           file_alerts=None):
    total_score = 0

    # ─── Process ───
    for alert in process_alerts:
        total_score += _score_from_reasons(alert["reason"], PROCESS_WEIGHTS)

    # ─── Startup ───
    for alert in startup_alerts:
        total_score += _score_from_reasons(alert["reason"], STARTUP_WEIGHTS)

    # ─── Network ───
    for alert in network_alerts:
        total_score += _score_from_reasons(alert["reason"], NETWORK_WEIGHTS)

    # ─── File (optional) ───
    if file_alerts:
        for alert in file_alerts:
            total_score += _score_from_reasons(alert["reason"], FILE_WEIGHTS)

    # ─── Normalize score ───
    # Prevent insane values when many alerts exist
    if total_score > 100:
        total_score = 100

    return total_score


# ─────────────────────────
# RISK CLASSIFICATION
# ─────────────────────────
def get_risk_level(score):
    if score < 20:
        return "SAFE"
    elif score < 50:
        return "MEDIUM"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"
