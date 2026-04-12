"""
logger.py — Logging structuré pour CAGOULE v1.5

Niveaux : DEBUG (détails internes) → INFO → WARNING (fallbacks) → ERROR
Activé via CAGOULE_LOG_LEVEL ou --verbose dans la CLI.
"""

from __future__ import annotations

import logging
import os
import sys


# ─── Logger central ──────────────────────────────────────────────────────────

_LOG_ENV = os.environ.get("CAGOULE_LOG_LEVEL", "WARNING").upper()

logger = logging.getLogger("cagoule")

_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter(
    "[%(levelname)s] cagoule.%(name)s — %(message)s"
))
logger.addHandler(_handler)

try:
    logger.setLevel(getattr(logging, _LOG_ENV, logging.WARNING))
except AttributeError:
    logger.setLevel(logging.WARNING)


def get_logger(module: str) -> logging.Logger:
    """
    Retourne un logger nommé pour un sous-module CAGOULE.

    Usage:
        from .logger import get_logger
        log = get_logger(__name__)
        log.debug("Round key 0 = %d", rk)
    """
    return logging.getLogger(f"cagoule.{module.split('.')[-1]}")


def set_level(level: str) -> None:
    """Change le niveau de log global (DEBUG / INFO / WARNING / ERROR)."""
    logger.setLevel(getattr(logging, level.upper(), logging.WARNING))
    for handler in logger.handlers:
        handler.setLevel(getattr(logging, level.upper(), logging.WARNING))


def enable_debug() -> None:
    """Active les logs de débogage complets."""
    set_level("DEBUG")


def enable_verbose() -> None:
    """Active les logs INFO (opérations normales)."""
    set_level("INFO")
