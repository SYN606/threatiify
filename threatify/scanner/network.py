import psutil

# ─────────────────────────
# CONFIG
# ─────────────────────────

SAFE_PORTS = {80, 443, 53}
SUSPICIOUS_KEYWORDS = ["keylog", "spy", "hook", "rat", "stealer"]

# Known safe process names (basic whitelist)
SAFE_PROCESSES = {
    "chrome", "firefox", "edge", "code", "discord", "python", "systemd",
    "explorer"
}


# ─────────────────────────
# CORE SCANNER
# ─────────────────────────
def scan_network():
    alerts = []
    seen = set()  # prevent duplicates

    try:
        connections = psutil.net_connections(kind="inet")
    except Exception:
        return alerts

    for conn in connections:
        try:
            # Skip if no remote connection
            if not conn.raddr or not conn.pid:
                continue

            pid = conn.pid

            # Unique key to avoid duplicate alerts
            key = (pid, conn.raddr.ip, conn.raddr.port)
            if key in seen:
                continue
            seen.add(key)

            # Process info
            try:
                proc = psutil.Process(pid)
                name = proc.name().lower()
                exe = proc.exe() if proc.exe() else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Skip known safe processes
            if any(safe in name for safe in SAFE_PROCESSES):
                continue

            laddr = f"{conn.laddr.ip}:{conn.laddr.port}"  # type: ignore
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}"

            reasons = []

            # ─── Rule 1: Suspicious port ───
            if conn.raddr.port not in SAFE_PORTS:
                reasons.append("Unusual port")

            # ─── Rule 2: Suspicious process name ───
            if any(k in name for k in SUSPICIOUS_KEYWORDS):
                reasons.append("Suspicious process name")

            # ─── Rule 3: Suspicious connection state ───
            if conn.status not in ("ESTABLISHED", "TIME_WAIT"):
                reasons.append(f"Abnormal state ({conn.status})")

            # ─── Rule 4: Executable path check ───
            if exe != "unknown" and any(p in exe.lower()
                                        for p in ["temp", "appdata"]):
                reasons.append("Running from suspicious path")

            # Only alert if something suspicious found
            if reasons:
                alerts.append({
                    "pid": pid,
                    "process": name,
                    "local": laddr,
                    "remote": raddr,
                    "status": conn.status,
                    "reason": ", ".join(reasons)
                })

        except Exception:
            continue

    return alerts
