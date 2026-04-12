"""
omega.py — Pilier Ω : Fonction Zêta de Riemann + Round Keys

Ω = ζ(2n) = Σ(k=1..∞) 1/k^(2n)   [identité CGS2025 : n=4 → π⁸/9450]

Coefficients de Fourier :
    aₖ = (2/π) × (-1)^(k+1) / k^(2n)

Round key k :
    K_k = HKDF-SHA256(⌊|aₖ| × 2³²⌋ || salt || n)

Les 64 round keys sont dérivées depuis les coefficients a₁..a₆₄.
Sans n, les round keys sont mathématiquement irrécupérables.
Espace : n ∈ [4, 65536] → 16 bits d'entropie sur n.

Requis par : params.py, cipher.py, decipher.py
"""

from __future__ import annotations

import struct

import mpmath
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ------------------------------------------------------------------ #
#  Précision mpmath                                                    #
# ------------------------------------------------------------------ #

_ZETA_PRECISION_DPS = 60    # chiffres décimaux significatifs


# ------------------------------------------------------------------ #
#  Calcul de ζ(2n)                                                    #
# ------------------------------------------------------------------ #

def compute_zeta(n: int, precision_dps: int = _ZETA_PRECISION_DPS) -> mpmath.mpf:
    """
    Calcule ζ(2n) = Σ(k=1..∞) 1/k^(2n) avec précision arbitraire.

    Identité CGS2025 vérifiée : n=4 → ζ(8) = π⁸/9450.

    n             : entier ∈ [4, 65536]
    precision_dps : chiffres décimaux de précision (défaut : 60)
    """
    if n < 1:
        raise ValueError(f"n doit être >= 1, reçu {n}")

    with mpmath.workdps(precision_dps):
        return mpmath.zeta(2 * n)


def verify_cgs2025_identity(precision_dps: int = 50) -> bool:
    """
    Vérifie l'identité CGS2025 : ζ(8) = π⁸/9450.
    Retourne True si l'égalité tient à la précision demandée.
    """
    with mpmath.workdps(precision_dps):
        zeta8 = mpmath.zeta(8)
        expected = mpmath.pi ** 8 / 9450
        return mpmath.almosteq(zeta8, expected, 10 ** (-(precision_dps - 5)))


# ------------------------------------------------------------------ #
#  Coefficients de Fourier                                             #
# ------------------------------------------------------------------ #

def fourier_coefficient(k: int, n: int,
                        precision_dps: int = _ZETA_PRECISION_DPS) -> mpmath.mpf:
    """
    Calcule le k-ième coefficient de Fourier de la série de Riemann.

    aₖ = (2/π) × (-1)^(k+1) / k^(2n)

    k : indice (1-based)
    n : paramètre de la fonction zêta
    """
    with mpmath.workdps(precision_dps):
        sign = mpmath.mpf(1) if (k + 1) % 2 == 0 else mpmath.mpf(-1)
        # (-1)^(k+1) : +1 si k impair, -1 si k pair
        sign = mpmath.mpf(1) if k % 2 == 1 else mpmath.mpf(-1)
        return (2 / mpmath.pi) * sign / mpmath.power(k, 2 * n)


def fourier_coefficients(n: int, num_terms: int = 64,
                          precision_dps: int = _ZETA_PRECISION_DPS) -> list[mpmath.mpf]:
    """
    Calcule les num_terms premiers coefficients de Fourier.

    Retourne [a₁, a₂, ..., a_{num_terms}].
    """
    with mpmath.workdps(precision_dps):
        return [fourier_coefficient(k, n, precision_dps)
                for k in range(1, num_terms + 1)]


# ------------------------------------------------------------------ #
#  Dérivation des round keys                                           #
# ------------------------------------------------------------------ #

def _hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 local."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)


def _coefficient_to_seed(ak: mpmath.mpf) -> bytes:
    """
    Convertit un coefficient de Fourier en graine de 8 octets.

    Formule : ⌊|aₖ| × 2³²⌋ → entier sur 8 octets (big-endian).
    """
    with mpmath.workdps(_ZETA_PRECISION_DPS):
        abs_ak = abs(ak)
        scaled = int(abs_ak * mpmath.power(2, 32))
        # Limiter à 8 octets (64 bits)
        scaled = scaled & 0xFFFFFFFFFFFFFFFF
        return scaled.to_bytes(8, 'big')


def derive_round_key(k: int, n: int, salt: bytes,
                     precision_dps: int = _ZETA_PRECISION_DPS) -> bytes:
    """
    Dérive la round key K_k depuis aₖ.

    K_k = HKDF-SHA256(⌊|aₖ|×2³²⌋ || salt || n_bytes)

    Retourne 32 octets.
    """
    ak = fourier_coefficient(k, n, precision_dps)
    ak_seed = _coefficient_to_seed(ak)
    n_bytes = n.to_bytes(4, 'big')
    info = b'CAGOULE_ROUND_KEY_' + k.to_bytes(4, 'big')
    key_material = ak_seed + salt + n_bytes
    return _hkdf_derive(key_material, info, 32)


def generate_round_keys(n: int, salt: bytes,
                        p: int,
                        num_keys: int = 64,
                        precision_dps: int = _ZETA_PRECISION_DPS) -> list[int]:
    """
    Génère num_keys round keys comme entiers dans Z/pZ.

    Chaque K_k est un entier dérivé de HKDF-SHA256 et réduit mod p.

    n       : paramètre Zêta (entropie sur les round keys)
    salt    : sel de session (32 octets)
    p       : nombre premier de travail
    num_keys: nombre de round keys (défaut : 64)

    Retourne une liste de num_keys entiers dans [0, p-1].
    """
    coeffs = fourier_coefficients(n, num_keys, precision_dps)
    round_keys = []

    for k, ak in enumerate(coeffs, 1):
        ak_seed = _coefficient_to_seed(ak)
        n_bytes = n.to_bytes(4, 'big')
        info = b'CAGOULE_ROUND_KEY_' + k.to_bytes(4, 'big')
        key_material = ak_seed + salt + n_bytes
        rk_bytes = _hkdf_derive(key_material, info, 32)
        rk_int = int.from_bytes(rk_bytes, 'big') % p
        round_keys.append(rk_int)

    return round_keys


# ------------------------------------------------------------------ #
#  Application des round keys à un bloc                               #
# ------------------------------------------------------------------ #

def apply_round_key(block: list[int], round_key: int, p: int) -> list[int]:
    """
    Ajoute la round key à chaque élément du bloc mod p.

    block     : liste de N entiers dans Z/pZ
    round_key : entier dans Z/pZ
    p         : nombre premier
    """
    return [(x + round_key) % p for x in block]


def remove_round_key(block: list[int], round_key: int, p: int) -> list[int]:
    """
    Soustrait la round key de chaque élément du bloc mod p.
    Opération inverse de apply_round_key.
    """
    return [(x - round_key) % p for x in block]


# ------------------------------------------------------------------ #
#  Informations et diagnostics                                         #
# ------------------------------------------------------------------ #

class OmegaInfo:
    """
    Informations sur le pilier Ω pour un paramètre n donné.
    Utile pour le débogage et la validation.
    """

    def __init__(self, n: int, precision_dps: int = _ZETA_PRECISION_DPS) -> None:
        self.n = n
        self.precision_dps = precision_dps

        with mpmath.workdps(precision_dps):
            self.omega = mpmath.zeta(2 * n)
            # Pour n=4 : vérification CGS2025
            if n == 4:
                self.cgs2025_value = mpmath.pi ** 8 / 9450
                self.cgs2025_match = mpmath.almosteq(
                    self.omega, self.cgs2025_value, 10 ** (-(precision_dps - 5))
                )
            else:
                self.cgs2025_value = None
                self.cgs2025_match = None

    def __repr__(self) -> str:
        base = f"OmegaInfo(n={self.n}, ζ(2n)={float(self.omega):.6e})"
        if self.cgs2025_match is not None:
            base += f" [CGS2025 identité: {'✓' if self.cgs2025_match else '✗'}]"
        return base