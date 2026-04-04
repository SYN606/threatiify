import psutil

# ─────────────────────────
# CONFIG
# ─────────────────────────

SUSPICIOUS_KEYWORDS = [
    "keylog", "logger", "hook", "spy", "capture", "rat", "stealer"
]

SUSPICIOUS_PATHS = ["temp", "tmp", "appdata"]

SAFE_PROCESSES = {
    "system", "systemd", "explorer", "svchost", "chrome", "firefox", "edge",
    "code", "discord"
}


# ─────────────────────────
# CORE SCANNER
# ─────────────────────────
def scan_processes():
    alerts = []
    seen = set()  # prevent duplicates

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
        try:
            pid = proc.info['pid']
            name = (proc.info['name'] or "").lower()
            exe = (proc.info['exe'] or "").lower()
            cpu = proc.info.get('cpu_percent', 0)

            # Skip empty or system-safe processes
            if not name or any(safe in name for safe in SAFE_PROCESSES):
                continue

            key = (pid, name)
            if key in seen:
                continue
            seen.add(key)

            reasons = []

            # ─── Rule 1: Suspicious name ───
            if any(k in name for k in SUSPICIOUS_KEYWORDS):
                reasons.append("Suspicious keyword")

            # ─── Rule 2: Suspicious path ───
            if exe and any(p in exe for p in SUSPICIOUS_PATHS):
                reasons.append("Running from suspicious path")

            # ─── Rule 3: Missing executable path ───
            if not exe:
                reasons.append("Unknown executable path")

            # ─── Rule 4: High CPU usage (basic heuristic) ───
            if cpu and cpu > 80:
                reasons.append("High CPU usage")

            # Only flag if something suspicious
            if reasons:
                alerts.append({
                    "pid": pid,
                    "process": name,
                    "path": exe or "unknown",
                    "cpu": cpu,
                    "reason": ", ".join(reasons)
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return alerts
