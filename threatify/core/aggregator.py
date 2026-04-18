from collections import defaultdict


def aggregate_by_process(process_alerts,
                         startup_alerts,
                         network_alerts,
                         file_alerts=None):
    """
    Group alerts by PID and calculate per-process threat score
    """

    processes = defaultdict(lambda: {
        "alerts": [],
        "score": 0,
        "risk": "SAFE"
    })

    all_alerts = (
        process_alerts +
        startup_alerts +
        network_alerts +
        (file_alerts if file_alerts else [])
    )

    for alert in all_alerts:
        data = alert.get("data", {})
        pid = data.get("pid")

        # Some alerts (like file/startup) may not have PID
        if pid is None:
            continue

        processes[pid]["alerts"].append(alert)

    # ─────────────────────────
    # SCORE PER PROCESS
    # ─────────────────────────
    for pid, info in processes.items():
        total = 0

        for alert in info["alerts"]:
            severity = alert.get("severity", 1)
            confidence = alert.get("confidence", 0.5)

            total += severity * confidence * 10

        score = min(int(total), 100)
        info["score"] = score

        # Risk classification
        if score >= 85:
            info["risk"] = "CRITICAL"
        elif score >= 60:
            info["risk"] = "HIGH"
        elif score >= 30:
            info["risk"] = "MEDIUM"
        else:
            info["risk"] = "SAFE"

    return processes