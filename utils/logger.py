"""
utils/logger.py
Central logger factory so every module logs consistently to both
console and a rotating file under data/recon.log.

Console output is colorized (by log level, and by phase/module group so
multiple phases' interleaved output is easy to tell apart at a glance).
The file handler stays plain text — no ANSI codes in data/recon.log.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_CONFIGURED = False

RESET = "\033[0m"
BOLD = "\033[1m"

LEVEL_COLORS = {
    "DEBUG": "\033[36m",     # cyan
    "INFO": "\033[37m",      # light gray/default
    "WARNING": "\033[33m",   # yellow
    "ERROR": "\033[31m",     # red
    "CRITICAL": "\033[1;41m",  # bold, red background
}

# Consistent color per module group (logger name prefix before the first dot)
# so e.g. "enum.*" is always the same color, "scan.*" another, etc. — makes
# interleaved multi-phase output easy to visually separate.
MODULE_COLORS = {
    "main": "\033[97m",         # bright white
    "orchestrator": "\033[95m", # bright magenta — phase banners
    "core": "\033[94m",         # bright blue
    "enum": "\033[36m",         # cyan
    "resolve": "\033[34m",      # blue
    "scan": "\033[32m",         # green
    "crawl": "\033[33m",        # yellow
    "secrets": "\033[31m",      # red
    "intel": "\033[35m",        # magenta
    "content": "\033[96m",      # bright cyan
    "cloud": "\033[93m",        # bright yellow
    "output": "\033[92m",       # bright green
}


class ColorFormatter(logging.Formatter):
    def __init__(self, use_color: bool):
        super().__init__(
            "%(asctime)s | %(levelname)-7s | %(name)-22s | %(message)s",
            datefmt="%H:%M:%S",
        )
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        if not self.use_color:
            return base

        module_key = record.name.split(".")[0]
        module_color = MODULE_COLORS.get(module_key, "")
        level_color = LEVEL_COLORS.get(record.levelname, "")

        # Phase banners ("=== PHASE 1: ... ===") get bolded on top of their color
        text = base
        if "===" in record.getMessage():
            return f"{BOLD}{module_color}{text}{RESET}"

        # Prefer level color for warnings/errors (more urgent than module identity),
        # module color otherwise so routine phase output stays visually grouped.
        color = level_color if record.levelname in ("WARNING", "ERROR", "CRITICAL") else module_color
        return f"{color}{text}{RESET}"


def setup_logging(level: str = "INFO", log_file: str = "data/recon.log") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Auto-disable colors when not a real terminal (e.g. output piped/redirected to a file)
    use_color = sys.stdout.isatty()

    console = logging.StreamHandler()
    console.setFormatter(ColorFormatter(use_color=use_color))
    root.addHandler(console)

    plain_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)-22s | %(message)s",
        datefmt="%H:%M:%S",
    )
    file_handler = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=3)
    file_handler.setFormatter(plain_fmt)
    root.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
