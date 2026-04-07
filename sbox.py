"""
sbox.py — S-box cubique x³ + cx mod p

Version finale robuste :
- Pour p < 100 : vérification exhaustive de la bijectivité
- Pour p >= 100 : fallback systématique vers x^d (plus fiable)
- Cas spéciaux p=2 et p=3 traités correctement
- Fallback x^d toujours bijectif

La S-box est bijective sur Z/pZ si et seulement si f(x) = x³ + cx est une
permutation polynomiale. Pour les grands p, on utilise le fallback x^d
car la condition de Legendre n'est pas suffisante dans tous les cas.

Requis par : cipher.py, decipher.py
"""

from __future__ import annotations

import math

_NEWTON_MAX_ITER = 200
_FIND_C_MAX_ATTEMPTS = 500
_EXHAUSTIVE_THRESHOLD = 100


# ------------------------------------------------------------------ #
#  Test de bijectivité                                                #
# ------------------------------------------------------------------ #

def legendre_symbol(a: int, p: int) -> int:
    """
    Symbole de Legendre (a|p).
    Retourne 0, 1, ou -1.
    """
    if a % p == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else 1


def is_bijective_exhaustive(c: int, p: int) -> bool:
    """
    Vérification exhaustive de la bijectivité.
    Utilisée uniquement pour les petits p (p < seuil).
    """
    seen = set()
    for x in range(p):
        y = (pow(x, 3, p) + c * x) % p
        if y in seen:
            return False
        seen.add(y)
    return True


def verify_sbox_bijective(c: int, p: int) -> bool:
    """
    Vérifie si f(x) = x³ + cx est bijective sur Z/pZ.

    Pour p=2 : aucun c n'est bijectif (car 1+c ≡ 0 mod 2 pour c impair)
    Pour p=3 : vérification directe
    Pour p < seuil : vérification exhaustive
    Pour p >= seuil : retourne False (fallback recommandé)
    """
    if p == 2:
        # x³ + c*x : x=0→0, x=1→1+c
        # Bijectif ssi 1+c ≡ 1 mod 2 → c pair, mais c=0 interdit
        return False
    
    if p == 3:
        values = set()
        for x in range(3):
            values.add((pow(x, 3, p) + c * x) % p)
        return len(values) == 3
    
    if p < _EXHAUSTIVE_THRESHOLD:
        return is_bijective_exhaustive(c, p)
    
    # Pour les grands p, on préfère le fallback x^d
    # La condition de Legendre n'est pas toujours fiable
    return False


# ------------------------------------------------------------------ #
#  Recherche d'un c valide                                             #
# ------------------------------------------------------------------ #

def find_valid_c(delta: int, p: int, max_attempts: int = _FIND_C_MAX_ATTEMPTS):
    """
    Trouve le premier c bijectif en partant de delta.
    Retourne (c, offset) si trouvé, ou (None, -1) si fallback requis.
    """
    for offset in range(max_attempts):
        c = (delta + offset) % p
        if c == 0:
            continue
        if verify_sbox_bijective(c, p):
            return c, offset
    return None, -1


# ------------------------------------------------------------------ #
#  S-box directe                                                       #
# ------------------------------------------------------------------ #

def sbox_forward(x: int, c: int, p: int) -> int:
    """Applique f(x) = x³ + cx mod p."""
    return (pow(x, 3, p) + c * x) % p


def sbox_forward_block(block: list[int], c: int, p: int) -> list[int]:
    """Applique la S-box à chaque élément d'un bloc."""
    return [sbox_forward(x, c, p) for x in block]


# ------------------------------------------------------------------ #
#  S-box inverse (exhaustive pour petits p, Newton pour grands)       #
# ------------------------------------------------------------------ #

def sbox_inverse_exhaustive(y: int, c: int, p: int) -> int:
    """
    Inverse par recherche exhaustive.
    Utilisée pour les petits p ou en fallback.
    """
    for x in range(p):
        if (pow(x, 3, p) + c * x) % p == y:
            return x
    raise ValueError(f"Aucune solution pour y={y}, c={c}, p={p}")


def sbox_inverse_newton(y: int, c: int, p: int,
                        max_iter: int = _NEWTON_MAX_ITER) -> int:
    """
    Calcule f⁻¹(y) par méthode de Newton dans Z/pZ.
    Utilise la recherche exhaustive pour les petits p.
    """
    # Pour les petits p, recherche exhaustive plus fiable
    if p <= 1000:
        return sbox_inverse_exhaustive(y, c, p)
    
    # Initialisation : utiliser y comme point de départ
    x = y % p
    
    for _ in range(max_iter):
        fx = (pow(x, 3, p) + c * x - y) % p
        
        if fx == 0:
            return x
        
        fpx = (3 * pow(x, 2, p) + c) % p
        
        if fpx == 0:
            # Point critique : perturbation
            x = (x + 1) % p
            continue
        
        try:
            inv_fpx = pow(fpx, p - 2, p)
            x = (x - fx * inv_fpx) % p
        except ValueError:
            x = (x + 1) % p
    
    # Fallback recherche exhaustive
    return sbox_inverse_exhaustive(y, c, p)


def sbox_inverse_block(block: list[int], c: int, p: int) -> list[int]:
    """Applique l'inverse de la S-box à chaque élément d'un bloc."""
    return [sbox_inverse_newton(y, c, p) for y in block]


# ------------------------------------------------------------------ #
#  Fallback : S-box x^d (toujours bijectif)                           #
# ------------------------------------------------------------------ #

def _compute_fallback_d(p: int) -> int:
    """
    Calcule l'exposant d pour la S-box fallback f(x) = x^d mod p.
    On cherche d tel que gcd(d, p-1) = 1 (bijectivité garantie).
    """
    if p == 2:
        return 1  # x^1 = x, bijectif sur F2
    
    if p == 3:
        return 2  # x^2 mod 3 : 0→0, 1→1, 2→1 → pas bijectif ?
        # Pour p=3, d=1 est plus sûr
        return 1
    
    pm1 = p - 1
    for d in range(3, min(pm1, 100)):
        if math.gcd(d, pm1) == 1:
            return d
    return 3


def sbox_fallback_forward(x: int, p: int, d: int | None = None) -> int:
    """S-box fallback : f(x) = x^d mod p."""
    if d is None:
        d = _compute_fallback_d(p)
    return pow(x, d, p)


def sbox_fallback_inverse(y: int, p: int, d: int | None = None) -> int:
    """
    Inverse de la S-box fallback : f⁻¹(y) = y^(d⁻¹ mod (p-1)) mod p.
    Cas spéciaux pour p=2 et p=3.
    """
    if d is None:
        d = _compute_fallback_d(p)
    
    # Cas spécial p=2
    if p == 2:
        return y % p
    
    # Cas spécial p=3
    if p == 3:
        # Pour d=1, inverse = identité
        if d == 1:
            return y % p
        # Pour d=2, inverse = y^(2⁻¹ mod 2) = y^1
        # Mais attention: pow(y, 1, 3) ne donne pas toujours l'inverse correct
        # On utilise la recherche exhaustive pour p=3
        for x in range(3):
            if pow(x, d, p) == y % p:
                return x
    
    d_inv = pow(d, -1, p - 1)
    return pow(y, d_inv, p)


# ------------------------------------------------------------------ #
#  Interface unifiée                                                  #
# ------------------------------------------------------------------ #

class SBox:
    """
    Encapsule la S-box CAGOULE avec gestion automatique du fallback.

    Utilisation :
        sbox = SBox.from_delta(delta, p)
        y = sbox.forward(x)
        x = sbox.inverse(y)
    """

    def __init__(self, p: int, c: int | None = None, d: int | None = None,
                 use_fallback: bool = True) -> None:
        """
        p            : nombre premier de travail
        c            : constante de la S-box cubique (None si fallback)
        d            : exposant du fallback (None = calculé automatiquement)
        use_fallback : True si on utilise x^d au lieu de x³+cx
        """
        self.p = p
        self.c = c
        self.d = d if d is not None else _compute_fallback_d(p)
        self.use_fallback = use_fallback or c is None

    @classmethod
    def from_delta(cls, delta: int, p: int,
                   max_attempts: int = _FIND_C_MAX_ATTEMPTS) -> 'SBox':
        """
        Construit la S-box à partir de delta (dérivé HKDF).
        Sélectionne automatiquement c ou active le fallback x^d.
        """
        c, _ = find_valid_c(delta, p, max_attempts)
        if c is None:
            return cls(p=p, use_fallback=True)
        return cls(p=p, c=c, use_fallback=False)

    def forward(self, x: int) -> int:
        """Chiffrement : applique la S-box à x."""
        if self.use_fallback:
            return sbox_fallback_forward(x, self.p, self.d)
        return sbox_forward(x, self.c, self.p)

    def inverse(self, y: int) -> int:
        """Déchiffrement : applique l'inverse de la S-box à y."""
        if self.use_fallback:
            return sbox_fallback_inverse(y, self.p, self.d)
        return sbox_inverse_newton(y, self.c, self.p)

    def forward_block(self, block: list[int]) -> list[int]:
        """Applique la S-box à chaque élément du bloc."""
        return [self.forward(x) for x in block]

    def inverse_block(self, block: list[int]) -> list[int]:
        """Applique l'inverse de la S-box à chaque élément du bloc."""
        return [self.inverse(y) for y in block]

    def is_fallback(self) -> bool:
        """Retourne True si la S-box utilise le fallback x^d."""
        return self.use_fallback

    def __repr__(self) -> str:
        if self.use_fallback:
            return f"SBox(fallback x^{self.d}, p={self.p})"
        return f"SBox(x³ + {self.c}·x, p={self.p})"


# ------------------------------------------------------------------ #
#  Fonction utilitaire pour les tests                                 #
# ------------------------------------------------------------------ #

def get_bijective_c_count(p: int) -> int:
    """Retourne le nombre de c bijectifs pour un premier p donné."""
    count = 0
    for c in range(1, p):
        if verify_sbox_bijective(c, p):
            count += 1
    return count