"""
omega.py — Pilier Ω : ζ(2n) → Round Keys — CAGOULE v2.1.0

Hiérarchie des backends (par ordre de priorité) :
  1. C natif via libcagoule.so (cagoule_omega_generate_round_keys)
     → ~40-60% plus rapide que le backend Python pur
     → Résultats bit-à-bit identiques à Python pour n ≤ 32
  2. Python pur (mpmath) — actif si libcagoule.so absent ou trop ancien
     → Comportement identique à v2.0.0

API 100% compatible v1.x / v2.0.x — aucun breaking change.

Inspection du backend actif :
    from cagoule.omega import OMEGA_BACKEND
    print(OMEGA_BACKEND)
"""

from __future__ import annotations

import ctypes
from typing import List

from ._binding import CAGOULE_C_AVAILABLE, _lib

# ── Détection des symboles omega dans libcagoule.so ──────────────────────────
_OMEGA_C_SYMBOLS_OK = False

if CAGOULE_C_AVAILABLE and _lib is not None:
    try:
        # Vérification que les symboles v2.1.0 sont bien présents
        _ = _lib.cagoule_omega_generate_round_keys
        _ = _lib.cagoule_omega_zeta_2n
        _ = _lib.cagoule_omega_fourier_coeff
        _ = _lib.cagoule_omega_block_add_rk
        _ = _lib.cagoule_omega_block_sub_rk

        # Signatures ctypes
        _lib.cagoule_omega_generate_round_keys.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        _lib.cagoule_omega_generate_round_keys.restype = ctypes.c_int

        _lib.cagoule_omega_zeta_2n.argtypes = [ctypes.c_int]
        _lib.cagoule_omega_zeta_2n.restype  = ctypes.c_double

        _lib.cagoule_omega_fourier_coeff.argtypes = [ctypes.c_int, ctypes.c_int]
        _lib.cagoule_omega_fourier_coeff.restype  = ctypes.c_double

        _lib.cagoule_omega_block_add_rk.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
            ctypes.c_uint64, ctypes.c_uint64,
        ]
        _lib.cagoule_omega_block_add_rk.restype = None

        _lib.cagoule_omega_block_sub_rk.argtypes = [
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
            ctypes.c_uint64, ctypes.c_uint64,
        ]
        _lib.cagoule_omega_block_sub_rk.restype = None

        _OMEGA_C_SYMBOLS_OK = True

    except AttributeError:
        # libcagoule.so v2.0.x — symboles omega absents
        import warnings
        warnings.warn(
            "cagoule: libcagoule.so ne contient pas cagoule_omega_* "
            "(probable v2.0.x). Recompilez : cd cagoule/c && make && make install. "
            "Fallback mpmath actif.",
            RuntimeWarning, stacklevel=2
        )

# ── Backend actif ────────────────────────────────────────────────────────────
OMEGA_BACKEND: str = (
    "C (libcagoule.so v2.1)"
    if _OMEGA_C_SYMBOLS_OK
    else "Python (mpmath fallback)"
)

# ── Chargement conditionnel de mpmath ────────────────────────────────────────
_mpmath_available = False
_mpmath = None

if not _OMEGA_C_SYMBOLS_OK:
    try:
        import mpmath as _mpmath
        _mpmath_available = True
    except ImportError:
        raise ImportError(
            "cagoule: ni les symboles omega dans libcagoule.so, ni mpmath. "
            "Compilez libcagoule.so v2.1.0 (cd cagoule/c && make) "
            "ou installez mpmath (pip install mpmath)."
        )

# ── Caches mpmath ────────────────────────────────────────────────────────────
_ZETA_PRECISION_DPS = 32
_ZETA_CACHE: dict = {}
_FOURIER_COEFFS_CACHE: dict = {}
_TWO_DIV_PI = None
_SCALE_2_32 = None


# ═══════════════════════════════════════════════════════════════════════════
#  Backend C — implémentations internes
# ═══════════════════════════════════════════════════════════════════════════

def _c_generate_round_keys(n: int, salt: bytes, p: int, num_keys: int) -> List[int]:
    keys_arr = (ctypes.c_uint64 * num_keys)()
    salt_arr = (ctypes.c_uint8 * len(salt)).from_buffer_copy(salt)
    ret = _lib.cagoule_omega_generate_round_keys(
        ctypes.c_int(n),
        salt_arr,
        ctypes.c_size_t(len(salt)),
        ctypes.c_uint64(p),
        ctypes.c_int(num_keys),
        keys_arr,
    )
    if ret != 0:
        raise RuntimeError(
            f"cagoule_omega_generate_round_keys a retourné le code d'erreur {ret}. "
            "Codes : -1=NULL, -2=PARAM invalide, -3=OpenSSL, -4=alloc."
        )
    return [int(keys_arr[i]) for i in range(num_keys)]


# ═══════════════════════════════════════════════════════════════════════════
#  Backend Python (mpmath) — conservé pour fallback + vérification
# ═══════════════════════════════════════════════════════════════════════════

def _init_mpmath_constants() -> None:
    global _TWO_DIV_PI, _SCALE_2_32
    if _TWO_DIV_PI is None:
        with _mpmath.workdps(_ZETA_PRECISION_DPS):
            _TWO_DIV_PI = _mpmath.mpf(2) / _mpmath.pi
            _SCALE_2_32 = _mpmath.mpf(2 ** 32)


def _py_fourier_coefficient(k: int, n: int, precision_dps: int):
    if k < 1:
        raise ValueError(f"k doit être ≥1, reçu {k}")
    _init_mpmath_constants()
    cache_key = (k, n, precision_dps)
    if cache_key not in _FOURIER_COEFFS_CACHE:
        with _mpmath.workdps(precision_dps):
            sign = 1 if (k % 2 == 1) else -1
            _FOURIER_COEFFS_CACHE[cache_key] = (
                _TWO_DIV_PI * sign / _mpmath.power(k, 2 * n)
            )
    return _FOURIER_COEFFS_CACHE[cache_key]


def _py_coefficient_to_seed(ak) -> bytes:
    _init_mpmath_constants()
    with _mpmath.workdps(_ZETA_PRECISION_DPS):
        scaled = int(abs(ak) * _SCALE_2_32) & 0xFFFFFFFFFFFFFFFF
        return scaled.to_bytes(8, 'big')


def _py_hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(key_material)


def _py_generate_round_keys(n: int, salt: bytes, p: int,
                             num_keys: int, precision_dps: int) -> List[int]:
    round_keys = []
    n_bytes = n.to_bytes(4, 'big')
    for k in range(1, num_keys + 1):
        ak = _py_fourier_coefficient(k, n, precision_dps)
        ak_seed = _py_coefficient_to_seed(ak)
        info = b'CAGOULE_ROUND_KEY_' + k.to_bytes(4, 'big')
        key_material = ak_seed + salt + n_bytes
        rk_bytes = _py_hkdf_derive(key_material, info, 32)
        round_keys.append(int.from_bytes(rk_bytes, 'big') % p)
    return round_keys


# ═══════════════════════════════════════════════════════════════════════════
#  API publique — inchangée depuis v1.x
# ═══════════════════════════════════════════════════════════════════════════

def generate_round_keys(n: int, salt: bytes, p: int,
                        num_keys: int = 64,
                        precision_dps: int = _ZETA_PRECISION_DPS) -> List[int]:
    """
    Génère les round keys à partir de ζ(2n) et HKDF-SHA256.

    v2.1.0 : backend C si libcagoule.so ≥ v2.1.0, sinon mpmath.
    Résultats bit-à-bit identiques pour n ≤ 32.

    Args:
        n:             Taille de bloc, paramètre ζ(2n) (entier ≥ 1)
        salt:          Sel de 32 octets (depuis CagouleParams)
        p:             Premier de travail Z/pZ (≥ 2)
        num_keys:      Nombre de clés (défaut 64, max 256)
        precision_dps: Précision mpmath (ignoré si backend C actif)

    Returns:
        Liste de num_keys entiers dans [0, p)
    """
    if _OMEGA_C_SYMBOLS_OK:
        return _c_generate_round_keys(n, salt, p, num_keys)
    return _py_generate_round_keys(n, salt, p, num_keys, precision_dps)


def compute_zeta(n: int, precision_dps: int = _ZETA_PRECISION_DPS):
    """Calcule ζ(2n). API inchangée."""
    if n < 1:
        raise ValueError(f"n doit être ≥1, reçu {n}")
    if _OMEGA_C_SYMBOLS_OK:
        return _lib.cagoule_omega_zeta_2n(ctypes.c_int(n))
    cache_key = (n, precision_dps)
    if cache_key not in _ZETA_CACHE:
        with _mpmath.workdps(precision_dps):
            _ZETA_CACHE[cache_key] = _mpmath.zeta(2 * n)
    return _ZETA_CACHE[cache_key]


def fourier_coefficient(k: int, n: int, precision_dps: int = _ZETA_PRECISION_DPS):
    """Calcule c_k = (2/π)×(−1)^k / k^(2n). API inchangée."""
    if _OMEGA_C_SYMBOLS_OK:
        return _lib.cagoule_omega_fourier_coeff(ctypes.c_int(k), ctypes.c_int(n))
    return _py_fourier_coefficient(k, n, precision_dps)


def fourier_coefficients(n: int, num_terms: int = 64,
                          precision_dps: int = _ZETA_PRECISION_DPS) -> list:
    """k = 1..num_terms. API inchangée."""
    return [fourier_coefficient(k, n, precision_dps) for k in range(1, num_terms + 1)]


def apply_round_key(block: list, round_key: int, p: int) -> list:
    """Ajoute la round key au bloc (mod p). API inchangée."""
    if _OMEGA_C_SYMBOLS_OK and block:
        arr = (ctypes.c_uint64 * len(block))(*block)
        _lib.cagoule_omega_block_add_rk(
            arr, ctypes.c_size_t(len(block)),
            ctypes.c_uint64(round_key), ctypes.c_uint64(p)
        )
        return list(arr)
    return [(x + round_key) % p for x in block]


def remove_round_key(block: list, round_key: int, p: int) -> list:
    """Retire la round key du bloc (mod p). API inchangée."""
    if _OMEGA_C_SYMBOLS_OK and block:
        arr = (ctypes.c_uint64 * len(block))(*block)
        _lib.cagoule_omega_block_sub_rk(
            arr, ctypes.c_size_t(len(block)),
            ctypes.c_uint64(round_key), ctypes.c_uint64(p)
        )
        return list(arr)
    return [(x - round_key) % p for x in block]


def clear_caches() -> None:
    """Vide les caches internes mpmath (no-op si backend C actif)."""
    _ZETA_CACHE.clear()
    _FOURIER_COEFFS_CACHE.clear()


def get_cache_info() -> dict:
    """Statistiques backend + caches."""
    return {
        "backend":                 OMEGA_BACKEND,
        "c_symbols_ok":            _OMEGA_C_SYMBOLS_OK,
        "mpmath_available":        _mpmath_available,
        "zeta_cache_size":         len(_ZETA_CACHE),
        "fourier_coeffs_cache":    len(_FOURIER_COEFFS_CACHE),
        "precision_dps":           _ZETA_PRECISION_DPS,
    }