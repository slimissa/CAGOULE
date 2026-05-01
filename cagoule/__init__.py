""""
CAGOULE v2.1.0 — Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée

Système de chiffrement symétrique hybride.

Changements v2.1.0 :
  - omega.c : portage C de ζ(2n) → round keys (suppression mpmath en production)
  - Fix test_mauvais_mdp : mauvais mot de passe détecté même avec params= fourni
  - CagouleAuthError enrichi : .reason, .hint, .ct_size, .backend
  - CagouleFormatError enrichi : .field, .data_size, .min_size
  - CagouleParams.fast_mode : mode KDF mémorisé pour re-dérivation correcte

Usage rapide :
    from cagoule import encrypt, decrypt
    ct = encrypt(b"secret", b"password")
    pt = decrypt(ct, b"password")

API avancée (params pré-dérivés) :
    from cagoule.params import CagouleParams
    with CagouleParams.derive(b"password") as params:
        ct = encrypt(b"msg", b"password", params=params)
        pt = decrypt(ct, b"password", params=params)

Inspection du backend :
    from cagoule import __backend__, __omega_backend__
    print(__backend__)        # "C (libcagoule.so v2.1)" ou "Python pur (fallback v1.x)"
    print(__omega_backend__)  # "C (libcagoule.so v2.1)" ou "Python (mpmath fallback)"
"""

from .__version__ import __version__, __version_info__, __release_date__

# ── Exceptions ────────────────────────────────────────────────────────
from .decipher import CagouleAuthError, CagouleFormatError, CagouleError

# ── Classes principales ───────────────────────────────────────────────
from .params import CagouleParams

# ── Fonctions principales ──────────────────────────────────────────────
from .cipher   import encrypt, encrypt_with_params
from .decipher import decrypt, decrypt_with_params

# ── Format ────────────────────────────────────────────────────────────
from .format import parse, inspect, serialize, is_cgl1, OVERHEAD, MAGIC

# ── Sécurité ──────────────────────────────────────────────────────────
from .utils import (
    secure_zeroize, SensitiveBuffer, bytes_to_zeroizable,
    analyze_sbox, sbox_report,
)

# ── Logging ───────────────────────────────────────────────────────────
from .logger import get_logger, set_level, enable_verbose, enable_debug

# ── Backends ──────────────────────────────────────────────────────────
from ._binding import CAGOULE_C_AVAILABLE as _C_AVAILABLE
__backend__ = "C (libcagoule.so v2.1)" if _C_AVAILABLE else "Python pur (fallback v1.x)"

# Backend spécifique omega (v2.1.0)
try:
    from .omega import OMEGA_BACKEND as __omega_backend__
except Exception:
    __omega_backend__ = "inconnu"

__all__ = [
    # Version
    "__version__",
    "__version_info__",
    "__release_date__",
    "__backend__",
    "__omega_backend__",
    # Exceptions
    "CagouleError",
    "CagouleAuthError",
    "CagouleFormatError",
    # Classes
    "CagouleParams",
    # Fonctions principales
    "encrypt",
    "decrypt",
    "encrypt_with_params",
    "decrypt_with_params",
    # Format
    "parse",
    "inspect",
    "serialize",
    "is_cgl1",
    "OVERHEAD",
    "MAGIC",
    # Sécurité
    "secure_zeroize",
    "SensitiveBuffer",
    "analyze_sbox",
    "sbox_report",
    # Logging
    "get_logger",
    "set_level",
    "enable_verbose",
    "enable_debug",
]

__author__    = "Slim Issa"
__copyright__ = "Copyright 2026, CAGOULE Project"
__license__   = "MIT"
