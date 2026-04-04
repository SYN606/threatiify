from threatify.core.config import (PROCESS_WEIGHTS, STARTUP_WEIGHTS,
                                   NETWORK_WEIGHTS, FILE_WEIGHTS, MAX_SCORE)


# ─────────────────────────
# HELPERS
# ─────────────────────────
def _score_from_reasons(reason_string, weight_map):
    """
    Match reason keywords with weights
    """
    score = 0
    reason_string = reason_string.lower()

    for key, weight in weight_map.items():
        if key.lower() in reason_string:
            score += weight

    return score


def _normalize_score(score, total_items):
    """
    Normalize score based on number of alerts
    """
    if total_items == 0:
        return 0

    # Normalize to avoid inflation
    normalized = score / total_items * 2
    return min(int(normalized), MAX_SCORE)


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

    # ─── File ───
    if file_alerts:
        for alert in file_alerts:
            total_score += _score_from_reasons(alert["reason"], FILE_WEIGHTS)

    # ─── Normalize ───
    total_items = (len(process_alerts) + len(startup_alerts) +
                   len(network_alerts) +
                   (len(file_alerts) if file_alerts else 0))

    return _normalize_score(total_score, total_items)


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
