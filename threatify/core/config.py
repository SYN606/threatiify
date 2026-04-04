import platform
from pathlib import Path

# ─────────────────────────
# SYSTEM INFO
# ─────────────────────────
OS_TYPE = platform.system()

# ─────────────────────────
# PATHS
# ─────────────────────────
HOME_DIR = Path.home()

# Linux-specific
LINUX_SUSPICIOUS_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

# Cross-platform suspicious paths
COMMON_SUSPICIOUS_PATHS = [
    "temp",
    "tmp",
    "appdata",
]

# ─────────────────────────
# PROCESS CONFIG
# ─────────────────────────
SUSPICIOUS_KEYWORDS = [
    "keylog", "logger", "hook", "spy", "capture", "rat", "stealer"
]

SAFE_PROCESSES = {
    # system
    "system",
    "systemd",
    "dbus",
    "polkit",

    # desktop
    "gnome",
    "plasmashell",
    "xorg",

    # apps
    "chrome",
    "firefox",
    "edge",
    "code",
    "discord"
}

# ─────────────────────────
# NETWORK CONFIG
# ─────────────────────────
SAFE_PORTS = {80, 443, 53}

# ─────────────────────────
# FILE MONITOR CONFIG
# ─────────────────────────
WRITE_THRESHOLD = 15
SUSPICIOUS_EXTENSIONS = [".log", ".txt", ".dat"]

# ─────────────────────────
# SCORING CONFIG
# ─────────────────────────
MAX_SCORE = 100

# ─────────────────────────
# FEATURE FLAGS
# ─────────────────────────
ENABLE_FILE_MONITOR = True
ENABLE_NETWORK_SCAN = True
ENABLE_STARTUP_SCAN = True

# ─────────────────────────
# DETECTION WEIGHTS
# ─────────────────────────

PROCESS_WEIGHTS = {
    "Suspicious keyword": 30,
    "Running from suspicious path": 20,
    "Unknown executable path": 10,
    "High CPU usage": 10,
}

STARTUP_WEIGHTS = {
    "Runs from suspicious path": 35,
    "Suspicious keyword": 40,
    "Script-based execution": 25,
    "Executable not found": 20,
}

NETWORK_WEIGHTS = {
    "Unusual port": 10,
    "Suspicious process name": 35,
    "Abnormal state": 15,
    "Running from suspicious path": 20,
}

FILE_WEIGHTS = {
    "High frequency writes": 25,
    "Suspicious location": 20,
    "Repeated writes to log-like file": 15,
    "Hidden file activity": 15,
    "Large file activity": 10,
}

MAX_SCORE = 100
