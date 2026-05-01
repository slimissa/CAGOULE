"""
logger.py — Logging structuré CAGOULE v2.0.0
"""
from __future__ import annotations
import logging, os, sys

_LOG_ENV = os.environ.get("CAGOULE_LOG_LEVEL", "WARNING").upper()

logger = logging.getLogger("cagoule")
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[%(levelname)s] cagoule.%(name)s — %(message)s"))
logger.addHandler(_handler)
try:
    logger.setLevel(getattr(logging, _LOG_ENV, logging.WARNING))
except AttributeError:
    logger.setLevel(logging.WARNING)

def get_logger(module: str) -> logging.Logger:
    return logging.getLogger(f"cagoule.{module.split('.')[-1]}")

def set_level(level: str) -> None:
    logger.setLevel(getattr(logging, level.upper(), logging.WARNING))

def enable_debug() -> None:
    set_level("DEBUG")

def enable_verbose() -> None:
    set_level("INFO")
