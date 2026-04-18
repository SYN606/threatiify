def correlate(alerts):
    """
    Correlate alerts across sources to detect multi-stage behavior
    """

    bonus = 0

    types = [a.get("type") for a in alerts]

    has_keylog = "suspicious_keyword" in types
    has_file = any(t in ["high_freq_write", "log_pattern_write"] for t in types)
    has_network = "suspicious_connection" in types
    has_startup = "startup_persistence" in types

    # ─── Keylogger Pattern ───
    if has_keylog and has_file:
        bonus += 25

    if has_keylog and has_network:
        bonus += 30

    if has_file and has_network:
        bonus += 20

    # ─── Persistence + Activity ───
    if has_startup and (has_network or has_file):
        bonus += 25

    # ─── Multi-vector attack ───
    if sum([has_keylog, has_file, has_network, has_startup]) >= 3:
        bonus += 30

    return bonus