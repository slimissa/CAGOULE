"""
CAGOULE v3.1.0 — Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée

Système de chiffrement symétrique hybride.

Nouveautés v3.0.0 — CTR Mode :
  - Mode CTR (Counter) : chiffrement sans dépendance inter-bloc → ILP maximal
  - Pipeline 4-blocs simultanés : cagoule_ctr_encrypt_4x (C-layer)
  - Format CGL1 v0x02 : |CT| == |PT| exact, pas de PKCS7
  - Rétrocompatibilité : decrypt() dispatch automatique v0x01/v0x02
  - encrypt() / decrypt() → CTR par défaut
  - encrypt_cbc() / decrypt_cbc() → CBC explicite (v0x01)
  - IV CTR dérivé de k_master (HKDF), non stocké dans le header

Usage rapide :
    from cagoule import encrypt, decrypt

    ct = encrypt(b"secret", b"password")   # CTR v0x02 par défaut
    pt = decrypt(ct, b"password")
    assert pt == b"secret"

Bulk CTR :
    from cagoule import encrypt_bulk, decrypt_bulk

    cts = encrypt_bulk([b"msg1", b"msg2"], b"password")
    pts = decrypt_bulk(cts, b"password")

CBC explicite (rétrocompatibilité) :
    from cagoule import encrypt_cbc, decrypt_cbc

    ct_cbc = encrypt_cbc(b"secret", b"password")
    pt_cbc = decrypt_cbc(ct_cbc, b"password")

Migration CBC → CTR :
    from cagoule import migrate_cbc_to_ctr

    ct_ctr = migrate_cbc_to_ctr(ct_cbc, b"password")
"""

from .__version__  import __version__, __release_date__, __author__

# ── Imports internes ────────────────────────────────────────────────────
from ._binding  import CAGOULE_C_AVAILABLE, get_backend_info
# v3.1.0 — cagoule_api.c (API C unifiée, mono-message), exportées
# publiquement (release audit, tâche 1). c_encrypt_v3/c_decrypt_v3 sont
# les wrappers ctypes bas-niveau (retournent bytes) ; encrypt_v3/decrypt_v3
# sont les wrappers Python-friendly (retournent (bytes, bytes_written)).
# Infrastructure de TEST/KAT cross-langage -- le pipeline Python de
# production (encrypt()/encrypt_ctr()) n'utilise PAS ce chemin. Voir
# cagoule/_binding.py pour le détail des garanties de sécurité.
from ._binding  import c_encrypt_v3, c_decrypt_v3, encrypt_v3, decrypt_v3
# v3.1.0 — API de chiffrement en flux (Feature 4), C-API only pour
# v3.1.0 (pas de VERSION byte CGL1 dédié). Voir cagoule/stream.py.
from .stream    import CagouleStreamCtx
from .cipher    import encrypt as _encrypt_cbc_raw
from .decipher  import decrypt as _decrypt_cbc_raw
from .cipher_ctr   import encrypt_ctr, encrypt_bulk_ctr
from .decipher_ctr import decrypt_ctr, decrypt_bulk_ctr, _dispatch_decrypt
# v3.1.0 — VERSION 0x03, EXPÉRIMENTAL (Poly1305 seul, sans ChaCha20).
# Volontairement PAS branché sur encrypt()/decrypt() : nécessite un import
# explicite + allow_experimental=True + CAGOULE_EXPERIMENTAL_NO_AEAD=1.
# Voir cagoule/cipher_ctr_raw.py pour l'avertissement de sécurité complet.
from .cipher_ctr_raw import (
    encrypt_ctr_raw, decrypt_ctr_raw, ExperimentalModeError,
)

# ── API principale (CTR par défaut en v3.0.0) ──────────────────────────

def encrypt(message: bytes, password: bytes, **kwargs) -> bytes:
    """
    Chiffrement CAGOULE — CTR mode (v3.0.0+).

    Retourne un ciphertext CGL1 v0x02.
    Utiliser encrypt_cbc() pour forcer le mode CBC (v0x01).
    """
    return encrypt_ctr(message, password, **kwargs)

def decrypt(ciphertext: bytes, password: bytes, **kwargs) -> bytes:
    """
    Déchiffrement CAGOULE — dispatch automatique par VERSION.

    VERSION 0x01 → CBC (rétrocompatibilité v2.x)
    VERSION 0x02 → CTR (v3.0.0+)
    """
    return _dispatch_decrypt(ciphertext, password, **kwargs)


def encrypt_cbc(message: bytes, password: bytes, **kwargs) -> bytes:
    """
    Chiffrement CAGOULE en mode CBC — format CGL1 v0x01.

    Conservé pour la rétrocompatibilité et les tests de parité.
    Les nouvelles applications doivent utiliser encrypt() (CTR).
    """
    return _encrypt_cbc_raw(message, password, **kwargs)


def decrypt_cbc(ciphertext: bytes, password: bytes, **kwargs) -> bytes:
    """
    Déchiffrement CAGOULE en mode CBC — ciphertexts CGL1 v0x01 uniquement.
    """
    return _decrypt_cbc_raw(ciphertext, password, **kwargs)


def encrypt_bulk(messages: list, password: bytes, **kwargs) -> list:
    """Bulk CTR : une dérivation Argon2id pour N messages."""
    return encrypt_bulk_ctr(messages, password, **kwargs)


def decrypt_bulk(ciphertexts: list, password: bytes, **kwargs) -> list:
    """Déchiffrement bulk CTR."""
    return decrypt_bulk_ctr(ciphertexts, password, **kwargs)


def migrate_cbc_to_ctr(ciphertext_cbc: bytes, password: bytes,
                        fast_mode: bool = False) -> bytes:
    """
    Migration d'un ciphertext CGL1 v0x01 (CBC) vers v0x02 (CTR).

    Déchiffre avec CBC, rechiffre avec CTR.
    Le plaintext intermédiaire est zéroïsé après usage via ctypes.memset
    sur l'objet bytearray afin d'écraser la mémoire backing réelle
    (les bytes Python sont immuables — seul bytearray permet la zéroïsation).

    Note : si le plaintext provient de _decrypt_cbc_raw sous forme de bytes
    immuables, CPython ne garantit pas l'effacement de l'objet original.
    Pour une garantie complète, utiliser encrypt_ctr/decrypt_ctr directement
    avec une API decrypt_into(buf) (planifiée v3.2.0).
    """
    import ctypes as _ct
    # Déchiffrer CBC
    plaintext = _decrypt_cbc_raw(ciphertext_cbc, password, fast_mode=fast_mode)
    # Rechiffrer CTR avant toute zéroïsation
    result = encrypt_ctr(plaintext, password, fast_mode=fast_mode)
    # Zéroïser via bytearray (mutable — ctypes.memset écrase la mémoire backing)
    pt_ba = bytearray(plaintext)
    _ct.memset((_ct.c_char * len(pt_ba)).from_buffer(pt_ba), 0, len(pt_ba))
    del pt_ba, plaintext
    return result


# ── Métadonnées backend ─────────────────────────────────────────────────

backend_info = get_backend_info()
__backend__  = "C (libcagoule.so v3.0.0)" if CAGOULE_C_AVAILABLE else "Python pur (fallback)"

__all__ = [
    "__version__", "__release_date__", "__author__",
    "__backend__", "backend_info",
    # API principale
    "encrypt", "decrypt",
    # CTR explicite
    "encrypt_ctr", "decrypt_ctr",
    "encrypt_bulk", "decrypt_bulk",
    "encrypt_bulk_ctr", "decrypt_bulk_ctr",
    # CBC explicite (rétrocompatibilité)
    "encrypt_cbc", "decrypt_cbc",
    # Migration
    "migrate_cbc_to_ctr",
    # v3.1.0 — VERSION 0x03 EXPÉRIMENTAL (voir cipher_ctr_raw.py)
    "encrypt_ctr_raw", "decrypt_ctr_raw", "ExperimentalModeError",
    # v3.1.0 — API C unifiée mono-message (cagoule_api.c), infra TEST/KAT
    "encrypt_v3", "decrypt_v3", "c_encrypt_v3", "c_decrypt_v3",
    # v3.1.0 — API de chiffrement en flux (cagoule_stream.c)
    "CagouleStreamCtx",
    # Backend
    "CAGOULE_C_AVAILABLE",
]
