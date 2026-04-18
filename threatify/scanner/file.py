import time
import os
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.config import (
    SUSPICIOUS_EXTENSIONS,
    WRITE_THRESHOLD,
    get_suspicious_paths,
    normalize_path,
)

# ─────────────────────────
# CONFIG
# ─────────────────────────
IGNORE_DIRS = [
    "cache", ".cache", "node_modules", ".git",
    "mozilla", "chromium", "google-chrome"
]

IGNORE_EXTENSIONS = [
    ".tmp", ".cache", ".swp", ".lock"
]

MIN_WRITE_THRESHOLD = WRITE_THRESHOLD
HIGH_WRITE_THRESHOLD = WRITE_THRESHOLD * 3


# ─────────────────────────
# FILTER LAYER (NEW)
# ─────────────────────────
def is_noise_file(path):
    """
    Filter out normal OS/application file activity
    """

    # Ignore common noisy directories
    if any(ignored in path for ignored in IGNORE_DIRS):
        return True

    # Ignore temp/cache files
    if any(path.endswith(ext) for ext in IGNORE_EXTENSIONS):
        return True

    # Ignore very small files (frequent system noise)
    try:
        if os.path.exists(path) and os.path.getsize(path) < 512:
            return True
    except Exception:
        pass

    return False


# ─────────────────────────
# HANDLER
# ─────────────────────────
class ThreatFileHandler(FileSystemEventHandler):

    def __init__(self):
        self.activity = defaultdict(int)
        self.timestamps = defaultdict(list)

    def _track(self, path):
        path = normalize_path(path)

        if is_noise_file(path):
            return

        self.activity[path] += 1
        self.timestamps[path].append(time.time())

    def on_modified(self, event):
        if not event.is_directory:
            self._track(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._track(event.src_path)


# ─────────────────────────
# ANALYZER
# ─────────────────────────
def analyze_file_activity(activity, timestamps):
    alerts = []

    suspicious_paths = [normalize_path(p) for p in get_suspicious_paths()]

    for path, count in activity.items():
        reasons = []
        severity = 1
        confidence = 0.5

        # ─── Rule 1: High frequency writes ───
        if count > HIGH_WRITE_THRESHOLD:
            reasons.append("High frequency writes (possible keylogging)")
            severity = 4
            confidence = 0.85

        elif count > MIN_WRITE_THRESHOLD:
            reasons.append("Moderate frequent writes")
            severity = 3
            confidence = 0.7

        # ─── Rule 2: Suspicious directory ───
        if any(p in path for p in suspicious_paths):
            reasons.append("Suspicious location")
            severity = max(severity, 3)
            confidence = max(confidence, 0.7)

        # ─── Rule 3: Log-like pattern ───
        if any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            if count > 10:
                reasons.append("Repeated writes to log-like file")
                severity = max(severity, 4)
                confidence = max(confidence, 0.8)

        # ─── Rule 4: Hidden file ───
        if os.path.basename(path).startswith("."):
            reasons.append("Hidden file activity")
            severity = max(severity, 2)

        # ─── Rule 5: Write burst ───
        times = timestamps.get(path, [])
        if len(times) > 5:
            duration = times[-1] - times[0]
            if duration > 0:
                rate = len(times) / duration

                if rate > 10:
                    reasons.append("Rapid write burst detected")
                    severity = max(severity, 4)
                    confidence = max(confidence, 0.85)

        # ─── Rule 6: File size anomaly ───
        try:
            if os.path.exists(path):
                size = os.path.getsize(path)
                if size > 5 * 1024 * 1024:
                    reasons.append("Large file activity")
                    severity = max(severity, 2)
        except Exception:
            pass

        # ─── FINAL FILTER ───
        if reasons and confidence >= 0.6:
            alert_type = "high_freq_write"

            if any("log-like" in r for r in reasons):
                alert_type = "log_pattern_write"

            alerts.append({
                "source": "file",
                "type": alert_type,
                "severity": severity,
                "confidence": round(confidence, 2),
                "data": {
                    "file": path,
                    "writes": count
                },
                "reason": ", ".join(reasons)
            })

    return alerts


# ─────────────────────────
# MONITOR
# ─────────────────────────
def monitor_files(duration=60):
    handler = ThreatFileHandler()
    observer = Observer()

    watch_path = os.path.expanduser("~")

    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    start = time.time()

    try:
        while time.time() - start < duration:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

    return analyze_file_activity(handler.activity, handler.timestamps)