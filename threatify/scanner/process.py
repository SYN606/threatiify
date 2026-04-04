import psutil
import platform

# ─────────────────────────
# CONFIG
# ─────────────────────────

IS_LINUX = platform.system() == "Linux"

SUSPICIOUS_KEYWORDS = [
    "keylog", "logger", "hook", "spy", "capture", "rat", "stealer"
]

SUSPICIOUS_PATHS = ["temp", "tmp", "appdata", "/dev/shm"]

SAFE_PROCESSES = {
    # cross-platform
    "system",
    "systemd",
    "explorer",
    "svchost",
    "chrome",
    "firefox",
    "edge",
    "code",
    "discord",

    # linux-specific
    "dbus",
    "polkit",
    "avahi-daemon",
    "networkmanager",
    "pulseaudio",
    "pipewire",
    "xorg",
    "gnome-shell",
    "plasmashell",
    "snapd",
    "udisksd"
}


# ─────────────────────────
# HELPERS
# ─────────────────────────
def is_kernel_process(name, exe):
    """
    Detect Linux kernel threads (very important)
    """
    if not exe:
        if (name.startswith("k") or "/" in name or name.startswith("rcu")
                or name.startswith("migration") or name.startswith("idle")):
            return True
    return False


def is_safe_process(name):
    return any(safe in name for safe in SAFE_PROCESSES)


# ─────────────────────────
# CORE SCANNER
# ─────────────────────────
def scan_processes():
    alerts = []
    seen = set()

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent']):
        try:
            pid = proc.info['pid']
            name = (proc.info['name'] or "").lower()
            exe = (proc.info['exe'] or "").lower()
            cpu = proc.info.get('cpu_percent', 0)

            if not name:
                continue

            # ─── Linux kernel filtering ───
            if IS_LINUX and is_kernel_process(name, exe):
                continue

            # ─── Safe process filtering ───
            if is_safe_process(name):
                continue

            # Deduplicate
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

            # ─── Rule 3: Missing exe (only if suspicious name) ───
            if not exe and any(k in name for k in SUSPICIOUS_KEYWORDS):
                reasons.append("Unknown executable path")

            # ─── Rule 4: High CPU usage ───
            if cpu and cpu > 85:
                reasons.append("High CPU usage")

            # ─── Rule 5: Suspicious executable location ───
            if exe and exe.startswith("/tmp"):
                reasons.append("Executing from /tmp")

            # Only alert if meaningful signals exist
            if reasons:
                alerts.append({
                    "pid": pid,
                    "process": name,
                    "path": exe or "unknown",
                    "cpu": round(cpu, 2),
                    "reason": ", ".join(reasons)
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    return alerts
