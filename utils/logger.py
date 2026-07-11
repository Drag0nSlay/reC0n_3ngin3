"""
utils/logger.py
Central logger factory so every module logs consistently to both
console and a rotating file under data/recon.log.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

_CONFIGURED = False


def setup_logging(level: str = "INFO", log_file: str = "data/recon.log") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)-22s | %(message)s",
        datefmt="%H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    file_handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3)
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
