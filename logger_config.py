import logging
import os
from datetime import datetime, timezone


class UTCFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat()


def get_logger(name: str = "triage") -> logging.Logger:
    os.makedirs("output", exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        file_handler = logging.FileHandler("output/triage.log", encoding="utf-8")

        formatter = UTCFormatter(
            "%(asctime)s | %(levelname)s | %(module)s | %(message)s"
        )

        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger