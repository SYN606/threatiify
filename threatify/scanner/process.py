import psutil
import platform

from core.config import (
    SUSPICIOUS_KEYWORDS,
    SAFE_PROCESSES,
    get_suspicious_paths,
    get_trusted_paths,
    normalize_path,
)

# ─────────────────────────
# SYSTEM DETECTION
# ─────────────────────────
OS_TYPE = platform.system().lower()

IS_WINDOWS = OS_TYPE == "windows"
IS_LINUX = OS_TYPE == "linux"
IS_MAC = OS_TYPE == "darwin"


# ─────────────────────────
# FILTER LAYER (NEW)
# ─────────────────────────
def is_system_noise(name, exe, pid):
    name = name.lower()

    # Kernel/system threads (Linux/macOS)
    if not exe:
        if (
            name.startswith("k") or
            "scsi" in name or
            "rcu" in name or
            "watchdog" in name or
            "oom" in name or
            "migration" in name or
            "idle" in name
        ):
            return True

    # Very low PID → OS process
    if pid and pid < 100:
        return True

    return False


def is_safe_process(name):
    return name in SAFE_PROCESSES


def is_trusted_path(path):
    path = normalize_path(path)
    for trusted in get_trusted_paths():
        if path.startswith(normalize_path(trusted)):
            return True
    return False


def is_suspicious_path(path):
    path = normalize_path(path)
    for p in get_suspicious_paths():
        if normalize_path(p) in path:
            return True
    return False


def get_parent_name(ppid):
    try:
        parent = psutil.Process(ppid)
        return (parent.name() or "").lower()
    except Exception:
        return "unknown"


# ─────────────────────────
# CORE SCANNER
# ─────────────────────────
def scan_processes():
    alerts = []
    seen = set()

    for proc in psutil.process_iter(
        ['pid', 'name', 'exe', 'cpu_percent', 'ppid']
    ):
        try:
            pid = proc.info.get('pid')
            name = (proc.info.get('name') or "").lower()
            exe = normalize_path(proc.info.get('exe') or "")
            cpu = proc.info.get('cpu_percent', 0)
            ppid = proc.info.get('ppid')

            if not name:
                continue

            # 🔥 FILTER: remove OS noise
            if is_system_noise(name, exe, pid):
                continue

            if is_safe_process(name):
                continue

            key = (pid, name)
            if key in seen:
                continue
            seen.add(key)

            reasons = []
            severity = 1
            confidence = 0.5
            alert_type = None

            # ─── Rule 1: Suspicious keyword ───
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in name:
                    alert_type = "suspicious_keyword"
                    reasons.append(f"Keyword match: {kw}")
                    severity = 4
                    confidence = 0.85
                    break

            # ─── Rule 2: Suspicious path ───
            if exe and is_suspicious_path(exe):
                alert_type = alert_type or "suspicious_path"
                reasons.append("Running from suspicious path")
                severity = max(severity, 3)
                confidence = max(confidence, 0.7)

            # ─── Rule 3: CPU anomaly ───
            if cpu and cpu > 70:
                alert_type = alert_type or "high_cpu"
                reasons.append("High CPU usage (polling-like behavior)")
                severity = max(severity, 2)
                confidence = max(confidence, 0.6)

            # ─── Rule 4: Parent anomaly ───
            parent_name = get_parent_name(ppid)

            suspicious_parents = [
                "chrome", "firefox", "edge",
                "winword", "excel", "outlook"
            ]

            if parent_name in suspicious_parents:
                alert_type = alert_type or "suspicious_path"
                reasons.append(f"Spawned by unusual parent ({parent_name})")
                severity = max(severity, 3)
                confidence = max(confidence, 0.75)

            # ─── Rule 5: OS-specific checks ───
            if IS_WINDOWS and exe:
                if "appdata" in exe or "\\temp\\" in exe:
                    alert_type = alert_type or "suspicious_path"
                    reasons.append("Running from AppData/Temp")
                    severity = max(severity, 3)
                    confidence = max(confidence, 0.75)

            if (IS_LINUX or IS_MAC) and exe.startswith("/tmp"):
                alert_type = alert_type or "suspicious_path"
                reasons.append("Executing from /tmp")
                severity = max(severity, 3)
                confidence = max(confidence, 0.75)

            # ─── Trust reduction ───
            if exe and is_trusted_path(exe):
                confidence *= 0.5

            # FINAL FILTER: only meaningful alerts
            if reasons and confidence >= 0.6:
                alerts.append({
                    "source": "process",
                    "type": alert_type or "unknown",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "data": {
                        "pid": pid,
                        "process": name,
                        "path": exe,
                        "cpu": round(cpu, 2),
                        "ppid": ppid,
                        "parent": parent_name,
                        "os": OS_TYPE
                    },
                    "reason": ", ".join(reasons)
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return alerts