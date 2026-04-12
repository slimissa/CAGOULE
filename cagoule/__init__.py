"""
CAGOULE v1.1 — Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée

Système de chiffrement symétrique hybride fusionnant des primitives
cryptographiques modernes avec des structures mathématiques pures
issues du Concours Général Sénégalais 2025.

Exemple d'utilisation:
    from cagoule import encrypt, decrypt
    
    # Chiffrement
    ciphertext = encrypt(b"Hello, World!", b"my_secret_password")
    
    # Déchiffrement
    plaintext = decrypt(ciphertext, b"my_secret_password")
    
    # Avec gestion d'erreur
    from cagoule import CagouleAuthError
    try:
        plaintext = decrypt(ciphertext, b"wrong_password")
    except CagouleAuthError:
        print("Mot de passe incorrect")
"""

from .__version__ import __version__, __version_info__, __release_date__

# Exceptions publiques
from .decipher import CagouleAuthError, CagouleFormatError, CagouleError

# Classes principales
from .params import CagouleParams

# Fonctions principales
from .cipher import encrypt
from .decipher import decrypt

# Utilitaires
from .format import parse, inspect, serialize, is_cgl1, OVERHEAD, MAGIC

# Utilitaires de sécurité
from .utils import (
    secure_zeroize, SensitiveBuffer, bytes_to_zeroizable,
    analyze_sbox, sbox_report,
)

# Logging
from .logger import get_logger, set_level, enable_verbose, enable_debug

# CLI (exposée mais pas automatiquement importée)
__all__ = [
    # Version
    "__version__",
    "__version_info__",
    "__release_date__",
    
    # Exceptions
    "CagouleError",
    "CagouleAuthError", 
    "CagouleFormatError",
    
    # Classes
    "CagouleParams",
    
    # Fonctions principales
    "encrypt",
    "decrypt",
    
    # Utilitaires
    "parse",
    "inspect", 
    "serialize",
    "is_cgl1",
    "OVERHEAD",
    "MAGIC",
    # Utilitaires
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

# Documentation du package
__docformat__ = "restructuredtext"
__author__ = "CAGOULE Team"
__copyright__ = "Copyright 2026, CAGOULE Project"
__license__ = "Proprietary - Confidential"