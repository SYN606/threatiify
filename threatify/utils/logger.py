import logging
import sys
from datetime import datetime

LOG_FILE = "threatify.log"


class SecurityFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "time": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }

        if hasattr(record, "context"):
            base["context"] = record.context

        return str(base)


logger = logging.getLogger("threatify")
logger.setLevel(logging.INFO)

# Console handler
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(SecurityFormatter())

# File handler
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(SecurityFormatter())

logger.addHandler(ch)
logger.addHandler(fh)


# ─────────────────────────
# HELPERS
# ─────────────────────────
def log_detection(alert):
    logger.warning(
        "Detection triggered",
        extra={"context": alert}
    )


def log_scan_step(step, count=None):
    logger.info(
        f"{step} completed",
        extra={"context": {"alerts": count}}
    )


def log_error(msg, error):
    logger.error(
        msg,
        extra={"context": {"error": str(error)}}
    )