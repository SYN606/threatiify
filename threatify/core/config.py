import platform
import os
from pathlib import Path

# ─────────────────────────
# SYSTEM INFO
# ─────────────────────────
OS_TYPE = platform.system().lower()

IS_WINDOWS = OS_TYPE == "windows"
IS_LINUX = OS_TYPE == "linux"
IS_MAC = OS_TYPE == "darwin"

HOME_DIR = Path.home()

# ─────────────────────────
# PATH UTILITIES
# ─────────────────────────
def normalize_path(path: str) -> str:
    if not path:
        return ""
    return os.path.normpath(path).lower()


# ─────────────────────────
# PATH CONFIG
# ─────────────────────────
WINDOWS_SUSPICIOUS_PATHS = [
    "c:\\users\\public",
    "c:\\windows\\temp",
    str(HOME_DIR / "appdata" / "local" / "temp"),
]

LINUX_SUSPICIOUS_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
]

MAC_SUSPICIOUS_PATHS = [
    "/tmp",
    "/private/tmp",
]

COMMON_SUSPICIOUS_KEYWORDS = [
    "temp", "tmp", "cache", "appdata", "roaming"
]


def get_suspicious_paths():
    if IS_WINDOWS:
        return WINDOWS_SUSPICIOUS_PATHS
    if IS_LINUX:
        return LINUX_SUSPICIOUS_PATHS
    if IS_MAC:
        return MAC_SUSPICIOUS_PATHS
    return []


# ─────────────────────────
# TRUSTED PATHS
# ─────────────────────────
WINDOWS_TRUSTED = [
    "c:\\windows\\system32",
    "c:\\program files",
    "c:\\program files (x86)",
]

LINUX_TRUSTED = [
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
]

MAC_TRUSTED = [
    "/usr/bin",
    "/usr/sbin",
    "/system",
]


def get_trusted_paths():
    if IS_WINDOWS:
        return WINDOWS_TRUSTED
    if IS_LINUX:
        return LINUX_TRUSTED
    if IS_MAC:
        return MAC_TRUSTED
    return []


# ─────────────────────────
# PROCESS CONFIG
# ─────────────────────────
SUSPICIOUS_KEYWORDS = [
    "keylog", "logger", "hook", "spy", "capture", "rat",
    "stealer", "inject", "record", "monitor"
]

SAFE_PROCESSES = {
    "system", "systemd", "dbus", "polkit",
    "gnome", "plasmashell", "xorg",
    "chrome", "firefox", "edge", "code", "discord"
}

SUSPICIOUS_PARENTS = [
    "chrome", "firefox", "edge",
    "winword", "excel", "outlook"
]

# ─────────────────────────
# NETWORK CONFIG
# ─────────────────────────
SAFE_PORTS = {80, 443, 53, 123}

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 1337, 9001
}

BEACONING_THRESHOLD = 5  # repeated connections
BEACONING_RATE = 2       # per second

# ─────────────────────────
# FILE CONFIG
# ─────────────────────────
WRITE_THRESHOLD = 15
HIGH_WRITE_MULTIPLIER = 3

SUSPICIOUS_EXTENSIONS = [
    ".log", ".txt", ".dat", ".tmp"
]

SENSITIVE_DIRECTORIES = [
    normalize_path(str(HOME_DIR / "documents")),
    normalize_path(str(HOME_DIR / "desktop")),
]

# ─────────────────────────
# STARTUP CONFIG
# ─────────────────────────
STARTUP_LOCATIONS = {
    "windows": [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ],
    "linux": [
        "~/.config/autostart"
    ],
    "mac": [
        "~/Library/LaunchAgents"
    ]
}

# ─────────────────────────
# SCORING CONFIG
# ─────────────────────────
MAX_SCORE = 100

THREAT_WEIGHTS = {
    # Process
    "suspicious_keyword": 30,
    "suspicious_path": 25,
    "unknown_path": 15,
    "high_cpu": 10,
    "parent_anomaly": 30,

    # Startup
    "startup_persistence": 35,
    "script_execution": 25,

    # Network
    "unusual_port": 15,
    "suspicious_connection": 30,
    "beaconing": 35,

    # File
    "high_freq_write": 30,
    "log_pattern_write": 25,
    "sensitive_file_access": 35,
}

# ─────────────────────────
# CORRELATION CONFIG
# ─────────────────────────
CORRELATION_RULES = {
    "keylogger_pattern": {
        "requires": ["suspicious_keyword", "high_freq_write"],
        "score_bonus": 25
    },
    "exfiltration_pattern": {
        "requires": ["high_freq_write", "suspicious_connection"],
        "score_bonus": 30
    },
    "persistence_attack": {
        "requires": ["startup_persistence", "suspicious_connection"],
        "score_bonus": 25
    }
}

# ─────────────────────────
# CONFIDENCE TUNING
# ─────────────────────────
TRUST_REDUCTION_FACTOR = 0.5
UNKNOWN_PROCESS_BOOST = 1.2

# ─────────────────────────
# FEATURE FLAGS
# ─────────────────────────
ENABLE_PROCESS_SCAN = True
ENABLE_FILE_MONITOR = True
ENABLE_NETWORK_SCAN = True
ENABLE_STARTUP_SCAN = True
ENABLE_CORRELATION = True
ENABLE_BEHAVIOR_TRACKING = True