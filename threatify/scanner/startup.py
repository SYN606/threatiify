import os
import platform

# Windows only
if platform.system() == "Windows":
    import winreg  # type: ignore

# ─────────────────────────
# CONFIG
# ─────────────────────────
SUSPICIOUS_KEYWORDS = ["keylog", "spy", "hook", "rat", "stealer"]
SUSPICIOUS_PATHS = ["temp", "tmp", "appdata"]

SAFE_NAMES = {"onedrive", "securityhealth", "windows defender"}


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
        (winreg.HKEY_CURRENT_USER, # type: ignore
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, # type: ignore
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for root, path in locations:
        entries = _read_registry(root, path)

        for name, value in entries:
            name_l = name.lower()
            value_l = value.lower()

            key = (name_l, value_l)
            if key in seen:
                continue
            seen.add(key)

            # Skip safe entries
            if any(safe in name_l for safe in SAFE_NAMES):
                continue

            reasons = []

            # ─── Rule 1: Suspicious path ───
            if any(p in value_l for p in SUSPICIOUS_PATHS):
                reasons.append("Runs from suspicious path")

            # ─── Rule 2: Suspicious keyword ───
            if any(k in value_l for k in SUSPICIOUS_KEYWORDS):
                reasons.append("Suspicious keyword")

            # ─── Rule 3: Hidden execution (powershell/cmd)
            if "powershell" in value_l or "cmd.exe" in value_l:
                reasons.append("Script-based execution")

            # ─── Rule 4: Missing file
            exe_path = value.split()[0].strip('"')
            if not os.path.exists(exe_path):
                reasons.append("Executable not found")

            if reasons:
                alerts.append({
                    "name": name,
                    "path": value,
                    "location": path,
                    "reason": ", ".join(reasons)
                })

    return alerts


# ─────────────────────────
# LINUX SCANNER
# ─────────────────────────
def check_startup_linux():
    alerts = []
    seen = set()

    autostart_path = os.path.expanduser("~/.config/autostart")

    if os.path.exists(autostart_path):
        for file in os.listdir(autostart_path):
            full_path = os.path.join(autostart_path, file)

            if not file.endswith(".desktop"):
                continue

            key = (file, full_path)
            if key in seen:
                continue
            seen.add(key)

            reasons = []

            # ─── Rule 1: Suspicious path ───
            if any(p in full_path.lower() for p in SUSPICIOUS_PATHS):
                reasons.append("Runs from suspicious path")

            # ─── Rule 2: Hidden file
            if file.startswith("."):
                reasons.append("Hidden startup entry")

            # ─── Rule 3: Read content for exec
            try:
                with open(full_path, "r") as f:
                    content = f.read().lower()

                    if any(k in content for k in SUSPICIOUS_KEYWORDS):
                        reasons.append("Suspicious keyword in config")

            except Exception:
                continue

            if reasons:
                alerts.append({
                    "name": file,
                    "path": full_path,
                    "location": "autostart",
                    "reason": ", ".join(reasons)
                })

    return alerts


# ─────────────────────────
# MAIN ENTRY
# ─────────────────────────
def check_startup():
    system = platform.system()

    if system == "Windows":
        return check_startup_windows()
    elif system == "Linux":
        return check_startup_linux()
    else:
        return []
