"""
mu.py — Génération de µ, racine de x⁴ + x² + 1 = 0

Équation issue du Concours Général Sénégalais 2025.

Stratégie A→C :
  A : résoudre x⁴ + x² + 1 = 0 dans Z/pZ (timeout configurable)
  B : (réservé — non utilisé en v1.1)
  C : si p ≡ 2 (mod 3), pas de racine dans Z/pZ → extension quadratique
      Fp² = Z/pZ[t]/(t²+t+1), poser µ = t (générateur)

Le système ne crashe jamais — µ est toujours trouvé.

Requis par : params.py
"""

from __future__ import annotations

import time
from typing import Union

from .fp2 import Fp2Element
from .logger import get_logger as _get_logger
_log = _get_logger(__name__)

# µ peut être un entier (dans Z/pZ) ou un Fp2Element (dans Fp²)
MuType = Union[int, Fp2Element]


# ------------------------------------------------------------------ #
#  Stratégie A : résolution dans Z/pZ                                 #
# ------------------------------------------------------------------ #

def _solve_in_zp(p: int, timeout_s: float = 5.0) -> int | None:
    """
    Cherche une racine de f(x) = x⁴ + x² + 1 dans Z/pZ.

    Factorisation : x⁴ + x² + 1 = (x² + x + 1)(x² - x + 1).
    On cherche les racines de ces deux facteurs quadratiques.

    Retourne la première racine trouvée, ou None si aucune.
    Respecte le timeout.
    """
    deadline = time.monotonic() + timeout_s

    # ----------------------------------------------------------------
    # Facteur 1 : g(x) = x² + x + 1 → discriminant Δ = 1 - 4 = -3
    # Racines : x = (-1 ± √(-3)) / 2 mod p
    # ----------------------------------------------------------------
    root = _solve_quadratic(1, 1, 1, p)
    if root is not None:
        return root

    if time.monotonic() > deadline:
        return None

    # ----------------------------------------------------------------
    # Facteur 2 : h(x) = x² - x + 1 → discriminant Δ = 1 - 4 = -3
    # Racines : x = (1 ± √(-3)) / 2 mod p
    # ----------------------------------------------------------------
    root = _solve_quadratic(1, p - 1, 1, p)   # coefficients : 1, -1, 1
    if root is not None:
        return root

    return None


def _solve_quadratic(a: int, b: int, c_coeff: int, p: int) -> int | None:
    """
    Résout ax² + bx + c ≡ 0 mod p.

    Retourne une racine ou None si inexistante.
    """
    if p == 2:
        for x in range(2):
            if (a * x * x + b * x + c_coeff) % 2 == 0:
                return x
        return None

    # Discriminant : Δ = b² - 4ac mod p
    delta = (b * b - 4 * a * c_coeff) % p

    # Racine carrée de Δ mod p
    sqrt_delta = _sqrt_mod(delta, p)
    if sqrt_delta is None:
        return None

    inv2a = pow(2 * a, p - 2, p)
    x1 = ((-b + sqrt_delta) * inv2a) % p
    return x1


def _sqrt_mod(n: int, p: int) -> int | None:
    """Racine carrée de n dans Z/pZ. Retourne None si inexistante."""
    if n == 0:
        return 0
    if p == 2:
        return n % 2
    # Test de Legendre
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    # Tonelli-Shanks
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # Cas général
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m_ts = s
    c_ts = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        i, temp = 1, t * t % p
        while temp != 1:
            temp = temp * temp % p
            i += 1
        b = pow(c_ts, 1 << (m_ts - i - 1), p)
        m_ts = i
        c_ts = b * b % p
        t = t * c_ts % p
        r = r * b % p


def _verify_root_zp(mu: int, p: int) -> bool:
    """Vérifie que µ est racine de x⁴ + x² + 1 dans Z/pZ."""
    mu2 = pow(mu, 2, p)
    mu4 = pow(mu, 4, p)
    return (mu4 + mu2 + 1) % p == 0


# ------------------------------------------------------------------ #
#  Stratégie C : extension Fp²                                         #
# ------------------------------------------------------------------ #

def _mu_in_fp2(p: int) -> Fp2Element:
    """
    Retourne µ = t dans Fp² = Z/pZ[t]/(t²+t+1).

    t est une racine primitive cubique de l'unité : t³ = 1, t ≠ 1.
    Comme t² + t + 1 = 0, on a t⁴ + t² + 1 = (t²+t+1)·(t²-t+1) mod... 
    Vérifions : t⁴ + t² + 1 dans Fp².
    
    Dans Fp²/(t²+t+1) : t² = -t - 1
    t³ = t·t² = t(-t-1) = -t² - t = (t+1) - t = 1
    t⁴ = t·t³ = t
    t⁴ + t² + 1 = t + (-t-1) + 1 = 0 ✓
    
    Donc µ = t est bien une racine de x⁴+x²+1 dans Fp².
    """
    return Fp2Element.t_generator(p)


def _verify_root_fp2(mu: Fp2Element, p: int) -> bool:
    """Vérifie que µ est racine de x⁴ + x² + 1 dans Fp²."""
    mu2 = mu ** 2
    mu4 = mu ** 4
    one = Fp2Element(1, 0, p)
    zero = Fp2Element(0, 0, p)
    result = mu4 + mu2 + one
    return result == zero


# ------------------------------------------------------------------ #
#  Point d'entrée principal                                            #
# ------------------------------------------------------------------ #

class MuResult:
    """
    Résultat de la génération de µ.

    Attributs :
        mu       : la valeur de µ (int ou Fp2Element)
        in_fp2   : True si µ est dans Fp²
        strategy : 'A' (Z/pZ) ou 'C' (Fp²)
        p        : le nombre premier utilisé
    """

    def __init__(self, mu: MuType, in_fp2: bool, strategy: str, p: int) -> None:
        self.mu = mu
        self.in_fp2 = in_fp2
        self.strategy = strategy
        self.p = p

    def is_fp2(self) -> bool:
        return self.in_fp2

    def as_int(self) -> int:
        """Retourne µ comme entier (uniquement si strategy == 'A')."""
        if self.in_fp2:
            raise TypeError("µ est dans Fp², pas dans Z/pZ")
        return int(self.mu)

    def as_fp2(self) -> Fp2Element:
        """Retourne µ comme Fp2Element."""
        if not self.in_fp2:
            # Plonger l'entier dans Fp²
            return Fp2Element.from_int(self.mu, self.p)
        return self.mu

    def __repr__(self) -> str:
        return (
            f"MuResult(strategy={self.strategy!r}, "
            f"mu={self.mu!r}, "
            f"in_fp2={self.in_fp2}, p={self.p})"
        )


def generate_mu(p: int, timeout_s: float = 5.0) -> MuResult:
    """
    Génère µ selon la stratégie A→C.

    Stratégie A : cherche µ dans Z/pZ (solution de x⁴+x²+1=0).
                  Timeout configurable (défaut : 5 secondes).
    Stratégie C : si A échoue → µ = t dans Fp² = Z/pZ[t]/(t²+t+1).

    Le système ne crashe jamais.

    p         : nombre premier de travail
    timeout_s : timeout pour la stratégie A
    """
    # ------------------------------------------------------------------
    # Stratégie A : résolution dans Z/pZ
    # ------------------------------------------------------------------
    mu_int = _solve_in_zp(p, timeout_s=timeout_s)

    if mu_int is not None:
        # Vérification de cohérence
        if not _verify_root_zp(mu_int, p):
            raise ArithmeticError(
                f"Bug interne : µ={mu_int} trouvé mais ne vérifie pas x⁴+x²+1=0 mod {p}"
            )
        _log.debug("µ trouvé dans Z/pZ (strat. A) : %d", mu_int)
        return MuResult(mu=mu_int, in_fp2=False, strategy="A", p=p)

    # ------------------------------------------------------------------
    # Stratégie C : extension quadratique Fp²
    # ------------------------------------------------------------------
    mu_fp2 = _mu_in_fp2(p)
    if not _verify_root_fp2(mu_fp2, p):
        raise ArithmeticError(
            f"Bug interne : µ=t n'est pas racine de x⁴+x²+1 dans Fp² pour p={p}"
        )
    _log.info("µ non trouvé dans Z/pZ → extension Fp² (strat. C)")
    return MuResult(mu=mu_fp2, in_fp2=True, strategy="C", p=p)


# ------------------------------------------------------------------ #
#  Génération des nœuds Vandermonde à partir de µ                     #
# ------------------------------------------------------------------ #

def generate_vandermonde_nodes(mu_result: MuResult, n: int,
                               k_master_bytes: bytes,
                               hkdf_fn) -> list[int]:
    """
    Génère les N nœuds α₀, α₁, ..., α_{N-1} pour la matrice de Vandermonde.

    α₀ = µ mod p  (nœud de base)
    αᵢ = HKDF(K_master, b'NODE_i', 8) % p  pour i = 1..N-1

    Si µ est dans Fp², on utilise µ.a (la partie réelle) comme α₀.

    mu_result     : résultat de generate_mu
    n             : nombre de nœuds (taille de bloc)
    k_master_bytes: clé maître (bytes)
    hkdf_fn       : fonction HKDF(key, info, length) → int
    """
    p = mu_result.p

    if mu_result.in_fp2:
        alpha0 = mu_result.mu.a   # partie réelle de t dans Fp²
    else:
        alpha0 = int(mu_result.mu) % p

    nodes = [alpha0]
    for i in range(1, n):
        info = f"NODE_{i}".encode()
        node = hkdf_fn(k_master_bytes, info, 8) % p
        nodes.append(node)

    return nodes


def generate_cauchy_beta(n: int, k_master_bytes: bytes, hkdf_fn) -> list[int]:
    """
    Génère les N valeurs β pour la matrice de Cauchy (fallback).

    βᵢ = HKDF(K_master, b'CAUCHY_BETA_i', 8) % p
    """
    beta = []
    for i in range(n):
        info = f"CAUCHY_BETA_{i}".encode()
        val = hkdf_fn(k_master_bytes, info, 8)
        beta.append(val)
    return beta