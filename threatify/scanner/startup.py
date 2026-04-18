import os
import platform

from core.config import (
    SUSPICIOUS_KEYWORDS,
    get_suspicious_paths,
    normalize_path,
)

# Windows only
if platform.system() == "Windows":
    import winreg  # type: ignore

OS_TYPE = platform.system().lower()


# ─────────────────────────
# HELPERS
# ─────────────────────────
def is_suspicious_path(path):
    path = normalize_path(path)
    for p in get_suspicious_paths():
        if normalize_path(p) in path:
            return True
    return False


def build_alert(name, path, location, reasons, severity, confidence):
    return {
        "source": "startup",
        "type": "startup_persistence",
        "severity": severity,
        "confidence": confidence,
        "data": {
            "name": name,
            "path": path,
            "location": location,
            "os": OS_TYPE
        },
        "reason": ", ".join(reasons)
    }


# ─────────────────────────
# WINDOWS SCANNER
# ─────────────────────────
def _read_registry(key_root, path):
    entries = []
    try:
        key = winreg.OpenKey(key_root, path)  # type: ignore
        i = 0
        while True:
            name, value, _ = winreg.EnumValue(key, i)  # type: ignore
            entries.append((name, value))
            i += 1
    except OSError:
        pass
    return entries


def check_startup_windows():
    alerts = []
    seen = set()

    locations = [
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for root, reg_path in locations:
        entries = _read_registry(root, reg_path)

        for name, value in entries:
            key = (name.lower(), value.lower())
            if key in seen:
                continue
            seen.add(key)

            exe_path = value.split()[0].strip('"')
            exe_norm = normalize_path(exe_path)

            reasons = []
            severity = 1
            confidence = 0.5

            # Suspicious path
            if is_suspicious_path(exe_norm):
                reasons.append("Runs from suspicious path")
                severity = 3
                confidence = 0.7

            # Keyword
            if any(k in exe_norm for k in SUSPICIOUS_KEYWORDS):
                reasons.append("Suspicious keyword")
                severity = max(severity, 4)
                confidence = max(confidence, 0.8)

            # Script execution
            if "powershell" in exe_norm or "cmd.exe" in exe_norm:
                reasons.append("Script-based persistence")
                severity = max(severity, 4)
                confidence = max(confidence, 0.85)

            # Missing file
            if not os.path.exists(exe_path):
                reasons.append("Executable not found")
                severity = max(severity, 3)

            if reasons:
                alerts.append(
                    build_alert(name, value, reg_path, reasons, severity,
                                confidence))

    return alerts


# ─────────────────────────
# LINUX SCANNER
# ─────────────────────────
def check_startup_linux():
    alerts = []
    seen = set()

    autostart_path = os.path.expanduser("~/.config/autostart")

    if not os.path.exists(autostart_path):
        return alerts

    for file in os.listdir(autostart_path):
        full_path = os.path.join(autostart_path, file)

        if not file.endswith(".desktop"):
            continue

        key = (file, full_path)
        if key in seen:
            continue
        seen.add(key)

        reasons = []
        severity = 1
        confidence = 0.5

        if is_suspicious_path(full_path):
            reasons.append("Runs from suspicious path")
            severity = 3
            confidence = 0.7

        if file.startswith("."):
            reasons.append("Hidden startup entry")
            severity = max(severity, 2)

        try:
            with open(full_path, "r") as f:
                content = f.read().lower()

                if any(k in content for k in SUSPICIOUS_KEYWORDS):
                    reasons.append("Suspicious keyword in config")
                    severity = max(severity, 4)
                    confidence = max(confidence, 0.8)

                if "exec=" in content:
                    if any(p in content for p in ["bash", "sh", "python"]):
                        reasons.append("Script-based execution")
                        severity = max(severity, 3)

        except Exception:
            continue

        if reasons:
            alerts.append(
                build_alert(file, full_path, "autostart", reasons, severity,
                            confidence))

    return alerts


# ─────────────────────────
# MACOS SCANNER (NEW)
# ─────────────────────────
def check_startup_mac():
    alerts = []

    launch_agents = os.path.expanduser("~/Library/LaunchAgents")

    if not os.path.exists(launch_agents):
        return alerts

    for file in os.listdir(launch_agents):
        full_path = os.path.join(launch_agents, file)

        if not file.endswith(".plist"):
            continue

        reasons = []
        severity = 1
        confidence = 0.5

        if is_suspicious_path(full_path):
            reasons.append("Runs from suspicious path")
            severity = 3
            confidence = 0.7

        try:
            with open(full_path, "r") as f:
                content = f.read().lower()

                if any(k in content for k in SUSPICIOUS_KEYWORDS):
                    reasons.append("Suspicious keyword in plist")
                    severity = max(severity, 4)
                    confidence = max(confidence, 0.8)

        except Exception:
            continue

        if reasons:
            alerts.append(
                build_alert(file, full_path, "launch_agents", reasons,
                            severity, confidence))

    return alerts


# ─────────────────────────
# MAIN ENTRY
# ─────────────────────────
def check_startup():
    if OS_TYPE == "windows":
        return check_startup_windows()
    elif OS_TYPE == "linux":
        return check_startup_linux()
    elif OS_TYPE == "darwin":
        return check_startup_mac()
    return []