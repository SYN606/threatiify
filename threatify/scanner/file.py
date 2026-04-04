import time
import os
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────
# CONFIG
# ─────────────────────────
SUSPICIOUS_PATHS = ["temp", "tmp", "appdata"]
SUSPICIOUS_EXTENSIONS = [".log", ".txt", ".dat"]
IGNORE_DIRS = ["cache", ".cache", "node_modules", ".git"]

WRITE_THRESHOLD = 15


# ─────────────────────────
# HANDLER
# ─────────────────────────
class ThreatFileHandler(FileSystemEventHandler):

    def __init__(self):
        self.activity = defaultdict(int)

    def _track(self, path):
        path = path.lower()

        # Ignore noisy directories
        if any(ignored in path for ignored in IGNORE_DIRS):
            return

        self.activity[path] += 1

    def on_modified(self, event):
        if not event.is_directory:
            self._track(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._track(event.src_path)


# ─────────────────────────
# ANALYZER
# ─────────────────────────
def analyze_file_activity(activity):
    alerts = []
    seen = set()

    for path, count in activity.items():
        key = (path, )
        if key in seen:
            continue
        seen.add(key)

        reasons = []

        # ─── Rule 1: High frequency writes ───
        if count > WRITE_THRESHOLD:
            reasons.append("High frequency writes")

        # ─── Rule 2: Suspicious directory ───
        if any(p in path for p in SUSPICIOUS_PATHS):
            reasons.append("Suspicious location")

        # ─── Rule 3: Suspicious file type ───
        if any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            if count > 5:
                reasons.append("Repeated writes to log-like file")

        # ─── Rule 4: Hidden files ───
        if os.path.basename(path).startswith("."):
            reasons.append("Hidden file activity")

        # ─── Rule 5: File size check ───
        try:
            size = os.path.getsize(path)
            if size > 5 * 1024 * 1024:  # >5MB
                reasons.append("Large file activity")
        except Exception:
            pass

        if reasons:
            alerts.append({
                "file": path,
                "writes": count,
                "reason": ", ".join(reasons)
            })

    return alerts


# ─────────────────────────
# MONITOR
# ─────────────────────────
def monitor_files(duration=10):
    """
    Monitor file activity for given duration (seconds)
    """

    handler = ThreatFileHandler()
    observer = Observer()

    watch_path = os.path.expanduser("~")

    observer.schedule(handler, watch_path, recursive=True)
    observer.start()

    try:
        time.sleep(duration)
    finally:
        observer.stop()
        observer.join()

    return analyze_file_activity(handler.activity)
