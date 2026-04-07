"""
constants.py — Constantes mathématiques CAGOULE v1.1

Issues du Concours Général Sénégalais 2025.
Valeurs précalculées avec mpmath (60 chiffres significatifs).
"""

from __future__ import annotations

import mpmath
from typing import Union

# ------------------------------------------------------------------ #
#  Précision de travail                                              #
# ------------------------------------------------------------------ #

_DPS: int = 60   # chiffres décimaux significatifs
mpmath.mp.dps = _DPS

# Type alias pour les constantes (mpmath ou castée en float si besoin)
Constant = Union[mpmath.mpf, float]


# ------------------------------------------------------------------ #
#  Constantes CGS2025 (format mpmath pour préserver la précision)    #
# ------------------------------------------------------------------ #

def _compute_golden_ratio() -> mpmath.mpf:
    """ρ = (1 + √5) / 2 — nombre d'or"""
    with mpmath.workdps(_DPS):
        return (1 + mpmath.sqrt(5)) / 2


def _compute_beta() -> mpmath.mpf:
    """β = (8π/81)(55ρ + 34) — volume du solide (S), CGS2025"""
    with mpmath.workdps(_DPS):
        rho = _compute_golden_ratio()
        return (8 * mpmath.pi / 81) * (55 * rho + 34)


def _compute_omega_zeta8() -> mpmath.mpf:
    """Ω = ζ(8) = π⁸/9450 — identité CGS2025 (cas n=4)"""
    with mpmath.workdps(_DPS):
        return mpmath.zeta(8)


def _compute_pi8_over_9450() -> mpmath.mpf:
    """π⁸/9450 — forme alternative de ζ(8)"""
    with mpmath.workdps(_DPS):
        return mpmath.pi ** 8 / 9450


def _compute_x0() -> mpmath.mpf:
    """
    x₀ = 3π — solution de cos(π/4 - x/3) = -√2/2 (équation F, CGS2025)
    
    Vérification:
        cos(π/4 - 3π/3) = cos(π/4 - π) = cos(-3π/4) = -√2/2 ✓
    """
    with mpmath.workdps(_DPS):
        return 3 * mpmath.pi


# ------------------------------------------------------------------ #
#  Exports publics (précision mpmath)                                #
# ------------------------------------------------------------------ #

GOLDEN_RATIO: mpmath.mpf = _compute_golden_ratio()
BETA: mpmath.mpf = _compute_beta()
OMEGA_N4: mpmath.mpf = _compute_omega_zeta8()
PI8_OVER_9450: mpmath.mpf = _compute_pi8_over_9450()
X0_CGS2025: mpmath.mpf = _compute_x0()

# δ = 12 = |(Z/13Z)*| — ordre du groupe multiplicatif Z/13Z
# Inspiration pour la théorie des groupes de la couche µ
DELTA_GROUP_ORDER: int = 12


# ------------------------------------------------------------------ #
#  Versions float (perte de précision — usage occasionnel)          #
# ------------------------------------------------------------------ #

def as_float() -> dict[str, float]:
    """Version float des constantes (perte de précision — pour debug/affichage)"""
    return {
        'golden_ratio': float(GOLDEN_RATIO),
        'beta': float(BETA),
        'omega_n4': float(OMEGA_N4),
        'pi8_over_9450': float(PI8_OVER_9450),
        'x0': float(X0_CGS2025),
    }


# ------------------------------------------------------------------ #
#  Vérifications de cohérence                                        #
# ------------------------------------------------------------------ #

def verify_all() -> dict[str, bool]:
    """
    Vérifie que toutes les constantes sont cohérentes.
    Retourne un dictionnaire {nom: bool}.
    """
    with mpmath.workdps(_DPS * 2):  # précision double pour la vérif
        results = {}

        # Vérification 1 : ζ(8) = π⁸/9450
        diff_zeta = abs(OMEGA_N4 - PI8_OVER_9450)
        results['zeta_8_identity'] = diff_zeta < mpmath.mpf(1e-30)
        
        # Vérification 2 : x₀ = 3π satisfait cos(π/4 - x/3) = -√2/2
        lhs = mpmath.cos(mpmath.pi / 4 - X0_CGS2025 / 3)
        rhs = -mpmath.sqrt(2) / 2
        results['x0_equation'] = abs(lhs - rhs) < mpmath.mpf(1e-30)
        
        # Vérification 3 : β positif
        results['beta_positive'] = BETA > 0
        
        # Vérification 4 : ρ ≈ 1.618...
        results['golden_ratio_range'] = mpmath.mpf(1.618) < GOLDEN_RATIO < mpmath.mpf(1.619)

        return results


# ------------------------------------------------------------------ #
#  Repr pour inspection                                              #
# ------------------------------------------------------------------ #

def summary() -> str:
    fvals = as_float()
    verif = verify_all()
    verif_str = "✓" if all(verif.values()) else "✗"
    
    return (
        f"CAGOULE Constants (CGS2025) — verification: {verif_str}\n"
        f"  ρ (golden ratio)  = {fvals['golden_ratio']:.15f}\n"
        f"  β (volume S)      = {fvals['beta']:.15f}\n"
        f"  Ω = ζ(8)          = {fvals['omega_n4']:.15f}\n"
        f"    π⁸/9450         = {fvals['pi8_over_9450']:.15f}\n"
        f"  x₀ = 3π           = {fvals['x0']:.15f}\n"
        f"  δ = |(Z/13Z)*|    = {DELTA_GROUP_ORDER}\n"
        f"  précision mpmath  = {_DPS} digits"
    )


# ------------------------------------------------------------------ #
#  Test rapide (si exécuté directement)                              #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    print(summary())
    print("\nVérifications détaillées:")
    for name, ok in verify_all().items():
        print(f"  {name}: {'✓' if ok else '✗'}")