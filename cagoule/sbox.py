"""
sbox.py — S-box CAGOULE v2.0.0

Délègue à libcagoule.so (C) si disponible.
Fallback Python v1.x (x^d) si .so absent.

Changements v2.0.0 :
  - S-box Feistel 32-bit pour p ≥ THRESHOLD → ratio decrypt/encrypt ≈ 1×
  - S-box x^d pour petits p < THRESHOLD (tests) — comportement v1.x
  - Les clés de ronde Feistel (rk0, rk1) sont dérivées de delta via HKDF
"""

from __future__ import annotations

import ctypes
import math
import warnings

from ._binding import (
    CAGOULE_C_AVAILABLE, _lib,
    CagouleSBox64C,
    list_to_uint64_array, uint64_array_to_list,
    CAGOULE_N, CAGOULE_P32_PRIME,
)
from .logger import get_logger

_log = get_logger(__name__)

# Seuil au-dessus duquel on utilise le Feistel (doit correspondre au C)
_LARGE_PRIME_THRESHOLD = 1 << 32
# Seuil v1.x pour la vérification exhaustive de bijectivité
_EXHAUSTIVE_THRESHOLD = 100


# ════════════════════════════════════════════════════════════════════════
# Implémentation C (chemin rapide — Feistel)
# ════════════════════════════════════════════════════════════════════════

class SBoxC:
    """Wrapper Python autour de CagouleSBox64 (C)."""

    def __init__(self, struct: CagouleSBox64C) -> None:
        self._s = struct

    @classmethod
    def from_delta(cls, delta: int, p: int) -> "SBoxC":
        """Construit la S-box depuis delta (valeur HKDF)."""
        s = CagouleSBox64C()
        # Dériver rk0 et rk1 depuis delta
        rk0 = (delta % (CAGOULE_P32_PRIME - 1)) + 1
        rk1 = ((delta >> 32) % (CAGOULE_P32_PRIME - 1)) + 1
        _lib.cagoule_sbox_init(ctypes.byref(s), p, rk0, rk1)
        return cls(s)

    def get_ptr(self):
        """Retourne le pointeur C pour utilisation directe."""
        return ctypes.byref(self._s)

    def forward(self, x: int) -> int:
        return int(_lib.cagoule_sbox_forward(self.get_ptr(), x))

    def inverse(self, y: int) -> int:
        return int(_lib.cagoule_sbox_inverse(self.get_ptr(), y))

    def forward_block(self, block: list[int]) -> list[int]:
        n = len(block)
        v_in = list_to_uint64_array(block)
        v_out = (ctypes.c_uint64 * n)()
        _lib.cagoule_sbox_block_forward(self.get_ptr(), v_in, v_out, n)
        return uint64_array_to_list(v_out, n)

    def inverse_block(self, block: list[int]) -> list[int]:
        n = len(block)
        v_in = list_to_uint64_array(block)
        v_out = (ctypes.c_uint64 * n)()
        _lib.cagoule_sbox_block_inverse(self.get_ptr(), v_in, v_out, n)
        return uint64_array_to_list(v_out, n)

    def zeroize(self):
        """Efface les données sensibles en mémoire C."""
        if self._s is not None:
            self._s.rk0 = 0
            self._s.rk1 = 0
            self._s.d = 0
            self._s.d_inv = 0
            self._s.p = 0
            self._s.use_feistel = 0
            _log.debug("SBoxC zeroized")

    def is_fallback(self) -> bool:
        return self._s is not None and self._s.use_feistel == 0

    def __repr__(self) -> str:
        if self._s is None:
            return "SBox[C] (détruit)"
        if self._s.use_feistel:
            return f"SBox[C Feistel](rk0={self._s.rk0}, rk1={self._s.rk1}, p={self._s.p})"
        return f"SBox[C x^{self._s.d}](p={self._s.p})"


# ════════════════════════════════════════════════════════════════════════
# Implémentation Python (fallback v1.x — inchangée)
# ════════════════════════════════════════════════════════════════════════

_FALLBACK_CACHE: dict = {}


def _compute_fallback_params(p: int) -> tuple[int, int]:
    """Calcule d et d_inv pour le fallback x^d."""
    if p in _FALLBACK_CACHE:
        return _FALLBACK_CACHE[p]
    if p <= 3:
        d = d_inv = 1
    else:
        pm1 = p - 1
        d = 3
        while d < min(pm1, 100):
            if math.gcd(d, pm1) == 1:
                break
            d += 2
        # Utiliser pow avec module pour l'inverse modulaire
        d_inv = pow(d, -1, pm1)
    _FALLBACK_CACHE[p] = (d, d_inv)
    return d, d_inv


class SBoxPython:
    """S-box Python pure — fallback x^d (comportement v1.x)."""

    def __init__(self, p: int, c: int | None = None, d: int | None = None,
                 use_fallback: bool = True) -> None:
        self.p = p
        self.c = c
        self.use_fallback = use_fallback or c is None
        if self.use_fallback:
            self.d, self.d_inv = _compute_fallback_params(p)
        else:
            self.d = d or 0
            self.d_inv = None

    def get_ptr(self):
        """Retourne None (pas de pointeur C en mode Python)."""
        return None

    @classmethod
    def from_delta(cls, delta: int, p: int) -> "SBoxPython":
        # Pour p >= _EXHAUSTIVE_THRESHOLD : fallback systématique (v1.x)
        if p >= _EXHAUSTIVE_THRESHOLD:
            return cls(p=p, use_fallback=True)
        # Petits p : chercher un c cubique valide
        for offset in range(500):
            c = (delta + offset) % p
            if c == 0:
                continue
            seen = set()
            ok = True
            for x in range(p):
                y = (pow(x, 3, p) + c * x) % p
                if y in seen:
                    ok = False
                    break
                seen.add(y)
            if ok:
                return cls(p=p, c=c, use_fallback=False)
        return cls(p=p, use_fallback=True)

    def forward(self, x: int) -> int:
        if self.use_fallback:
            return pow(x, self.d, self.p)
        return (pow(x, 3, self.p) + self.c * x) % self.p

    def inverse(self, y: int) -> int:
        if self.use_fallback:
            return pow(y, self.d_inv, self.p)
        # Newton pour petits p (v1.x behavior)
        for x in range(self.p):
            if (pow(x, 3, self.p) + self.c * x) % self.p == y:
                return x
        raise ValueError(f"SBox inverse: pas de solution pour y={y}")

    def forward_block(self, block: list[int]) -> list[int]:
        return [self.forward(x) for x in block]

    def inverse_block(self, block: list[int]) -> list[int]:
        return [self.inverse(y) for y in block]

    def zeroize(self):
        """Efface les données sensibles."""
        self.d = 0
        self.d_inv = 0
        self.c = 0
        self.p = 0
        self.use_fallback = False
        _log.debug("SBoxPython zeroized")

    def is_fallback(self) -> bool:
        return self.use_fallback

    def __repr__(self) -> str:
        if self.use_fallback:
            return f"SBox[Python x^{self.d}](p={self.p})"
        return f"SBox[Python x³+{self.c}x](p={self.p})"


# ════════════════════════════════════════════════════════════════════════
# API publique unifiée — identique à v1.x
# ════════════════════════════════════════════════════════════════════════

class SBox:
    """
    API publique — même interface qu'en v1.x.
    Utilise SBoxC (Feistel C) si libcagoule.so disponible,
    sinon SBoxPython (x^d, v1.x behavior).
    """

    def __new__(cls, *args, **kwargs):
        raise TypeError("Utiliser SBox.from_delta()")

    @staticmethod
    def from_delta(delta: int, p: int,
                   max_attempts: int = 500):
        """Construit la S-box depuis delta (valeur HKDF)."""
        if CAGOULE_C_AVAILABLE:
            _log.debug("Utilisation de SBoxC (Feistel C) pour p=%d", p)
            return SBoxC.from_delta(delta, p)
        _log.debug("Utilisation de SBoxPython (fallback x^d) pour p=%d", p)
        return SBoxPython.from_delta(delta, p)