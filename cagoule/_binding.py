"""
_binding.py — Chargeur ctypes pour libcagoule.so — CAGOULE v2.1.0

Nouveautés v2.1.0 :
  - Vérification version 2.1.0 via cagoule_version() si présent
  - Les symboles cagoule_omega_* sont détectés dans omega.py (pas ici)
    pour éviter le chargement circulaire au démarrage

Expose :
  - CagouleMatrix + cagoule_matrix_*
  - CagouleSBox64 + cagoule_sbox_*
  - cagoule_cbc_encrypt / cagoule_cbc_decrypt
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import warnings
from typing import Optional, List

# ── Constantes ────────────────────────────────────────────────────────
CAGOULE_N         = 16
CAGOULE_P32_PRIME = 4294967291   # plus grand premier < 2^32

CAGOULE_OK          =  0
CAGOULE_ERR_NULL    = -1
CAGOULE_ERR_SIZE    = -2
CAGOULE_ERR_CORRUPT = -3


# ── Localisation de libcagoule.so ─────────────────────────────────────

def _find_lib() -> Optional[pathlib.Path]:
    candidates = [
        pathlib.Path(__file__).parent / "libcagoule.so",
        pathlib.Path(__file__).parent / "c" / "libcagoule.so",
    ]
    env_path = os.environ.get("LIBCAGOULE_PATH")
    if env_path:
        candidates.insert(0, pathlib.Path(env_path))
    for p in candidates:
        if p.exists():
            return p
    return None


_lib_path = _find_lib()
_lib: Optional[ctypes.CDLL] = None
CAGOULE_C_AVAILABLE = False

if _lib_path is not None:
    try:
        _lib = ctypes.CDLL(str(_lib_path))
        CAGOULE_C_AVAILABLE = True
    except OSError as e:
        warnings.warn(
            f"cagoule: impossible de charger {_lib_path}: {e}. "
            "Fallback Python pur (performances v1.x).",
            RuntimeWarning, stacklevel=2
        )
else:
    warnings.warn(
        "cagoule: libcagoule.so non trouvé. "
        "Compiler : cd cagoule/c && make && make install. "
        "Fallback Python pur actif.",
        RuntimeWarning, stacklevel=2
    )


# ── Structures ctypes ─────────────────────────────────────────────────

class CagouleMatrixC(ctypes.Structure):
    _fields_ = [
        ("fwd",  (ctypes.c_uint64 * CAGOULE_N) * CAGOULE_N),
        ("inv",  (ctypes.c_uint64 * CAGOULE_N) * CAGOULE_N),
        ("p",    ctypes.c_uint64),
        ("kind", ctypes.c_int),
    ]


class CagouleSBox64C(ctypes.Structure):
    _fields_ = [
        ("p",           ctypes.c_uint64),
        ("rk0",         ctypes.c_uint64),
        ("rk1",         ctypes.c_uint64),
        ("d",           ctypes.c_uint64),
        ("d_inv",       ctypes.c_uint64),
        ("use_feistel", ctypes.c_int),
    ]


# ── Signatures ctypes ─────────────────────────────────────────────────

if CAGOULE_C_AVAILABLE and _lib is not None:

    # Matrix
    _lib.cagoule_matrix_build.argtypes = [
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_uint64]
    _lib.cagoule_matrix_build.restype = ctypes.POINTER(CagouleMatrixC)

    _lib.cagoule_matrix_free.argtypes = [ctypes.POINTER(CagouleMatrixC)]
    _lib.cagoule_matrix_free.restype  = None

    _lib.cagoule_matrix_mul.argtypes = [
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64)]
    _lib.cagoule_matrix_mul.restype = None

    _lib.cagoule_matrix_mul_inv.argtypes = [
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64)]
    _lib.cagoule_matrix_mul_inv.restype = None

    _lib.cagoule_matrix_verify.argtypes = [ctypes.POINTER(CagouleMatrixC)]
    _lib.cagoule_matrix_verify.restype  = ctypes.c_int

    # S-Box
    _lib.cagoule_sbox_init.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    _lib.cagoule_sbox_init.restype = None

    _lib.cagoule_sbox_forward.argtypes = [
        ctypes.POINTER(CagouleSBox64C), ctypes.c_uint64]
    _lib.cagoule_sbox_forward.restype  = ctypes.c_uint64

    _lib.cagoule_sbox_inverse.argtypes = [
        ctypes.POINTER(CagouleSBox64C), ctypes.c_uint64]
    _lib.cagoule_sbox_inverse.restype  = ctypes.c_uint64

    _lib.cagoule_sbox_block_forward.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_size_t]
    _lib.cagoule_sbox_block_forward.restype = None

    _lib.cagoule_sbox_block_inverse.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_size_t]
    _lib.cagoule_sbox_block_inverse.restype = None

    # CBC Pipeline
    _cbc_argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
        ctypes.c_uint64,
    ]
    _lib.cagoule_cbc_encrypt.argtypes = _cbc_argtypes
    _lib.cagoule_cbc_encrypt.restype  = ctypes.c_int
    _lib.cagoule_cbc_decrypt.argtypes = _cbc_argtypes
    _lib.cagoule_cbc_decrypt.restype  = ctypes.c_int


# ── Utilitaires ───────────────────────────────────────────────────────

def list_to_uint64_array(lst: List[int]) -> ctypes.Array:
    return (ctypes.c_uint64 * len(lst))(*lst)


def uint64_array_to_list(arr: ctypes.Array, n: int) -> List[int]:
    return [int(arr[i]) for i in range(n)]


def bytes_to_c_uint8(data: bytes) -> ctypes.Array:
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def c_uint8_to_bytes(arr: ctypes.Array, n: int) -> bytes:
    return bytes(arr[:n])


def cagoule_p_bytes(p: int) -> int:
    """Nombre d'octets pour un élément de Z/pZ."""
    return 8 if p > 0xFFFFFFFF else 4


def free_matrix(matrix_ptr) -> None:
    if CAGOULE_C_AVAILABLE and _lib and matrix_ptr:
        _lib.cagoule_matrix_free(matrix_ptr)
