"""
sbox.py — S-box CAGOULE v3.1.0
Dispatch automatique vers l'implémentation C (libcagoule.so) si disponible,
sinon fallback Python v1.x (x^d) pour environnements sans .so.
Changements v3.0.1 :
  - Pour p >= _LARGE_PRIME_THRESHOLD (≈ 2^32), implémentation Feistel 2-rounds identique au C (cagoule_sbox.c)

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
    """
    S-box Python pure — fallback pour environnements sans libcagoule.so.

    CORRECTIF v3.0.1 : pour les premiers de production (p >= _LARGE_PRIME_THRESHOLD),
    implémente le réseau de Feistel 2-rounds identique au C (cagoule_sbox.c).
    L'ancien code utilisait x³ mod p (public, indépendant de delta/k_master) pour
    tout p >= _EXHAUSTIVE_THRESHOLD — S-box non keyed, faille de confidentialité
    totale en mode Python pur.

    Construction Feistel 2-rounds sur Z/pZ (p >= 2^32) :
      - rk0 = (delta % (P32_PRIME-1)) + 1
      - rk1 = ((delta >> 32) % (P32_PRIME-1)) + 1
      - f(x32, rk) = (x32 * rk) % P32_PRIME   [fonction de round P32-linéaire]
      - Round 1 : L1 = R0, R1 = L0 XOR f(R0, rk0)   [masqué uint32]
      - Round 2 : L2 = R1, R2 = L1 XOR f(R1, rk1)   [masqué uint32]
      - Output  : L2 * 2^32 + R2   (reconstruction big-endian dans Z/pZ)

      CORRECTIF (audit round 2) : ce docstring disait "mod p" / "+" (addition)
      pour la combinaison round -- le code réel (_feistel_forward ci-dessous)
      utilise XOR (^), pas une addition modulaire. Vérifié directement dans
      l'implémentation : `R1 = (L0 ^ int((L1 * self.rk0) % P32)) & 0xFFFFFFFF`.
      Le code était correct (identique au C, déjà testé/fuzzé), seul ce
      commentaire décrivait la mauvaise opération.

    Pour les petits premiers (p < _LARGE_PRIME_THRESHOLD) : comportement v1.x
    conservé (x³+cx ou x^d selon p).
    """

    def __init__(self, p: int, rk0: int = 0, rk1: int = 0,
                 c: int | None = None, d: int | None = None,
                 use_feistel: bool = False, use_fallback: bool = True) -> None:
        self.p = p
        self.use_feistel = use_feistel
        self.use_fallback = use_fallback and not use_feistel
        if use_feistel:
            self.rk0 = rk0
            self.rk1 = rk1
            self.d = self.d_inv = self.c = 0
        elif not use_fallback and c is not None:
            self.c = c
            self.d = self.d_inv = 0
            self.rk0 = self.rk1 = 0
        else:
            self.d, self.d_inv = _compute_fallback_params(p)
            self.c = self.rk0 = self.rk1 = 0

    def get_ptr(self):
        return None

    @classmethod
    def from_delta(cls, delta: int, p: int) -> "SBoxPython":
        """
        Construit la S-box depuis delta.

        CORRECTIF v3.0.1 : pour p >= _LARGE_PRIME_THRESHOLD, utilise le Feistel
        2-rounds keyed avec delta (identique à SBoxC.from_delta / cagoule_sbox.c).
        Plus de substitution silencieuse par x³ indépendant de la clé.
        """
        if p >= _LARGE_PRIME_THRESHOLD:
            # Feistel 2-rounds — même dérivation que le C
            rk0 = (delta % (CAGOULE_P32_PRIME - 1)) + 1
            rk1 = ((delta >> 32) % (CAGOULE_P32_PRIME - 1)) + 1
            return cls(p=p, rk0=rk0, rk1=rk1, use_feistel=True, use_fallback=False)
        if p >= _EXHAUSTIVE_THRESHOLD:
            # Petit premier moyen : fallback x^d (comport. v1.x, delta ignoré)
            return cls(p=p, use_fallback=True, use_feistel=False)
        # Très petit p : chercher x³+cx bijectif
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
                return cls(p=p, c=c, use_fallback=False, use_feistel=False)
        return cls(p=p, use_fallback=True, use_feistel=False)

    def _feistel_forward(self, x: int) -> int:
        """2-round Feistel avec cycle-walking — identique à cagoule_sbox_forward() C."""
        P32 = CAGOULE_P32_PRIME
        p = self.p

        def _pass(v: int) -> int:
            L0 = (v >> 32) & 0xFFFFFFFF
            R0 = v & 0xFFFFFFFF
            L1 = R0
            R1 = (L0 ^ int((L1 * self.rk0) % P32)) & 0xFFFFFFFF
            L2 = R1
            R2 = (L1 ^ int((L2 * self.rk1) % P32)) & 0xFFFFFFFF
            return (L2 << 32) | R2

        r = _pass(x)
        while r >= p:
            r = _pass(r)
        return r

    def _feistel_inverse(self, y: int) -> int:
        """Inverse Feistel avec cycle-walking — identique à cagoule_sbox_inverse() C.
        Correction: R0=L1 (pas R1). XOR masqué à uint32 comme la truncation C.
        """
        P32 = CAGOULE_P32_PRIME
        p = self.p

        def _pass_inv(v: int) -> int:
            L2 = (v >> 32) & 0xFFFFFFFF
            R2 = v & 0xFFFFFFFF
            R1 = L2
            L1 = (R2 ^ int((L2 * self.rk1) % P32)) & 0xFFFFFFFF
            R0 = L1                # FIX: R0=L1 pas R1
            L0 = (R1 ^ int((L1 * self.rk0) % P32)) & 0xFFFFFFFF
            return (L0 << 32) | R0

        r = _pass_inv(y)
        while r >= p:
            r = _pass_inv(r)
        return r

    def forward(self, x: int) -> int:
        if self.use_feistel:
            return self._feistel_forward(x)
        if self.use_fallback:
            return pow(x, self.d, self.p)
        return (pow(x, 3, self.p) + self.c * x) % self.p

    def inverse(self, y: int) -> int:
        if self.use_feistel:
            return self._feistel_inverse(y)
        if self.use_fallback:
            return pow(y, self.d_inv, self.p)
        for x in range(self.p):
            if (pow(x, 3, self.p) + self.c * x) % self.p == y:
                return x
        raise ValueError(f"SBox inverse: pas de solution pour y={y}")

    def forward_block(self, block: list[int]) -> list[int]:
        return [self.forward(x) for x in block]

    def inverse_block(self, block: list[int]) -> list[int]:
        return [self.inverse(y) for y in block]

    def zeroize(self):
        self.d = self.d_inv = self.c = self.rk0 = self.rk1 = self.p = 0
        self.use_fallback = self.use_feistel = False
        _log.debug("SBoxPython zeroized")

    def is_fallback(self) -> bool:
        return self.use_fallback

    def __repr__(self) -> str:
        if self.use_feistel:
            return f"SBox[Python Feistel](rk0={self.rk0}, rk1={self.rk1}, p={self.p})"
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