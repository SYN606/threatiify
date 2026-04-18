import psutil
import time
from collections import defaultdict

from core.config import (
    SAFE_PORTS,
    SUSPICIOUS_PORTS,
    SUSPICIOUS_KEYWORDS,
    SAFE_PROCESSES,
    get_trusted_paths,
    normalize_path,
)

# ─────────────────────────
# TRACKING 
# ─────────────────────────
connection_history = defaultdict(list)


# ─────────────────────────
# FILTER LAYER
# ─────────────────────────
def is_noise_connection(name, ip, port):
    """
    Filter out normal OS/network noise
    """

    # Localhost traffic
    if ip.startswith("127.") or ip == "localhost":
        return True

    # Skip common system ports
    if port in {53, 123}:  # DNS, NTP
        return True

    # Ephemeral ports (normal outbound connections)
    if port >= 30000:
        return True

    # Known safe applications
    if name in SAFE_PROCESSES:
        return True

    return False


def is_trusted_process(exe):
    """
    Reduce confidence for trusted system binaries
    """
    exe = normalize_path(exe)

    for path in get_trusted_paths():
        if exe.startswith(normalize_path(path)):
            return True

    return False


# ─────────────────────────
# CORE SCANNER
# ─────────────────────────
def scan_network(duration=5):
    """
    Monitor network activity and detect anomalies
    """

    alerts = []
    seen = set()

    start = time.time()

    while time.time() - start < duration:
        try:
            connections = psutil.net_connections(kind="inet")
        except Exception:
            return alerts

        for conn in connections:
            try:
                if not conn.raddr or not conn.pid:
                    continue

                pid = conn.pid
                raddr = conn.raddr.ip
                rport = conn.raddr.port

                key = (pid, raddr, rport)
                if key in seen:
                    continue
                seen.add(key)

                # ─── Process info ───
                try:
                    proc = psutil.Process(pid)
                    name = (proc.name() or "").lower()
                    exe = normalize_path(proc.exe() or "")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                # ─── Noise filtering ───
                if is_noise_connection(name, raddr, rport):
                    continue

                # ─── Track behavior ───
                connection_history[(pid, raddr)].append(time.time())

                reasons = []
                severity = 1
                confidence = 0.5

                # ─── Rule 1: Known malicious port ───
                if rport in SUSPICIOUS_PORTS:
                    reasons.append(f"Known suspicious port ({rport})")
                    severity = 4
                    confidence = 0.85

                # ─── Rule 2: Suspicious process name ───
                if any(k in name for k in SUSPICIOUS_KEYWORDS):
                    reasons.append("Suspicious process name")
                    severity = max(severity, 4)
                    confidence = max(confidence, 0.8)

                # ─── Rule 3: Suspicious execution path ───
                if exe and any(p in exe for p in ["temp", "appdata", "/tmp"]):
                    reasons.append("Running from suspicious path")
                    severity = max(severity, 3)
                    confidence = max(confidence, 0.7)

                # ─── Rule 4: Abnormal connection state ───
                if conn.status not in ("ESTABLISHED", "TIME_WAIT"):
                    reasons.append(f"Abnormal state ({conn.status})")
                    severity = max(severity, 2)

                # ─── Rule 5: Beaconing detection ───
                history = connection_history[(pid, raddr)]

                if len(history) > 5:
                    duration_conn = history[-1] - history[0]

                    if duration_conn > 0:
                        rate = len(history) / duration_conn

                        if rate > 2:
                            reasons.append("Frequent outbound connections (beaconing)")
                            severity = max(severity, 4)
                            confidence = max(confidence, 0.85)

                # ─── Trust reduction ───
                if exe and is_trusted_process(exe):
                    confidence *= 0.5

                # ─── Final emission filter ───
                if reasons and confidence >= 0.6:
                    alerts.append({
                        "source": "network",
                        "type": "suspicious_connection",
                        "severity": severity,
                        "confidence": round(confidence, 2),
                        "data": {
                            "pid": pid,
                            "process": name,
                            "remote": raddr,
                            "port": rport,
                        },
                        "reason": ", ".join(reasons)
                    })

            except Exception:
                continue

        time.sleep(1)

    return alerts