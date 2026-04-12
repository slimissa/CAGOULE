"""
fp2.py — Arithmétique dans Fp² = Z/pZ[t]/(t²+t+1)

Extension quadratique utilisée quand µ n'existe pas dans Z/pZ (Stratégie C).
Un élément de Fp² est représenté comme (a, b) signifiant a + b·t,
où t satisfait t² + t + 1 = 0, i.e. t² = -t - 1 mod p.

Requis par : mu.py (Stratégie C fallback)
"""

from __future__ import annotations


class Fp2Element:
    """
    Élément de Fp² = Z/pZ[t]/(t²+t+1).
    Représentation : a + b*t  où a, b ∈ Z/pZ.
    """

    __slots__ = ("a", "b", "p")

    def __init__(self, a: int, b: int, p: int) -> None:
        if p < 2:
            raise ValueError(f"p doit être un nombre premier >= 2, reçu {p}")
        self.a = a % p
        self.b = b % p
        self.p = p

    # ------------------------------------------------------------------ #
    #  Représentation                                                       #
    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return f"Fp2({self.a} + {self.b}·t, p={self.p})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Fp2Element):
            return self.a == other.a and self.b == other.b and self.p == other.p
        if isinstance(other, int):
            return self.b == 0 and self.a == other % self.p
        return NotImplemented

    def is_zero(self) -> bool:
        return self.a == 0 and self.b == 0

    def is_one(self) -> bool:
        return self.a == 1 and self.b == 0

    # ------------------------------------------------------------------ #
    #  Opérations de base                                                  #
    # ------------------------------------------------------------------ #

    def __add__(self, other: Fp2Element) -> Fp2Element:
        _check_same_field(self, other)
        return Fp2Element(self.a + other.a, self.b + other.b, self.p)

    def __sub__(self, other: Fp2Element) -> Fp2Element:
        _check_same_field(self, other)
        return Fp2Element(self.a - other.a, self.b - other.b, self.p)

    def __neg__(self) -> Fp2Element:
        return Fp2Element(-self.a, -self.b, self.p)

    def __mul__(self, other: Fp2Element | int) -> Fp2Element:
        if isinstance(other, int):
            return Fp2Element(self.a * other, self.b * other, self.p)
        _check_same_field(self, other)
        # (a + b·t)(c + d·t) = ac + (ad+bc)·t + bd·t²
        # t² = -t - 1  →  bd·t² = -bd·t - bd
        # Résultat : (ac - bd) + (ad + bc - bd)·t
        p = self.p
        ac = self.a * other.a % p
        bd = self.b * other.b % p
        ad_bc = (self.a * other.b + self.b * other.a) % p
        real_part = (ac - bd) % p
        imag_part = (ad_bc - bd) % p
        return Fp2Element(real_part, imag_part, p)

    def __rmul__(self, scalar: int) -> Fp2Element:
        return self.__mul__(scalar)

    def __pow__(self, exp: int) -> Fp2Element:
        """Exponentiation rapide (square-and-multiply)."""
        if exp < 0:
            return self.inverse() ** (-exp)
        p = self.p
        result = Fp2Element(1, 0, p)
        base = Fp2Element(self.a, self.b, p)
        e = exp
        while e > 0:
            if e & 1:
                result = result * base
            base = base * base
            e >>= 1
        return result

    # ------------------------------------------------------------------ #
    #  Inversion                                                           #
    # ------------------------------------------------------------------ #

    def inverse(self) -> Fp2Element:
        """
        Inverse de (a + b·t) dans Fp².
        Norme : N = a² - ab + b²
        Inverse : (a - b·t - b·1) / N = ((a-b) + (-b)·t) / N
        """
        p = self.p
        if self.is_zero():
            raise ZeroDivisionError("Inversion de zéro dans Fp²")
        norm = (self.a * self.a - self.a * self.b + self.b * self.b) % p
        if norm == 0:
            raise ZeroDivisionError(f"Norme nulle pour {self!r} — diviseur de zéro")
        norm_inv = pow(norm, p - 2, p)
        a_conj = (self.a - self.b) % p
        b_conj = (-self.b) % p
        return Fp2Element(a_conj * norm_inv % p, b_conj * norm_inv % p, p)

    # ------------------------------------------------------------------ #
    #  Racine carrée (version stable)                                     #
    # ------------------------------------------------------------------ #

    def sqrt(self) -> Fp2Element:
        """
        Racine carrée dans Fp².
        
        Pour les petits p (≤ 257) : recherche exhaustive (rapide pour les tests)
        Pour p > 257 : utilise la formule de Tonelli-Shanks généralisée.
        """
        p = self.p
        
        if self.is_zero():
            return Fp2Element(0, 0, p)
        
        # Pour les petits p (tests), recherche exhaustive
        # p=13 → 169 essais, p=97 → 9409 essais, très rapide
        if p <= 257:
            for a in range(p):
                for b in range(p):
                    root = Fp2Element(a, b, p)
                    if root * root == self:
                        return root
            raise ValueError(f"Pas de racine carrée trouvée pour {self} dans Fp² (p={p})")
        
        # Pour p > 257 : formule directe
        # Si p ≡ 3 mod 4, x = self^((p²+1)//4) donne la racine
        exp = (p * p + 1) // 4
        candidate = self ** exp
        if candidate * candidate == self:
            return candidate
        
        # Fallback : Tonelli-Shanks pour les cas résiduels
        return _tonelli_shanks_fp2_simple(self, p)

    # ------------------------------------------------------------------ #
    #  Conversion                                                          #
    # ------------------------------------------------------------------ #

    def to_int(self) -> int:
        """Convertit en entier si l'élément est dans Fp (b == 0)."""
        if self.b != 0:
            raise ValueError(f"{self!r} n'est pas dans Fp (b ≠ 0)")
        return self.a

    @classmethod
    def from_int(cls, x: int, p: int) -> Fp2Element:
        """Plonge un entier de Fp dans Fp²."""
        return cls(x % p, 0, p)

    @classmethod
    def t_generator(cls, p: int) -> Fp2Element:
        """Retourne le générateur t de Fp², avec t² + t + 1 = 0."""
        return cls(0, 1, p)


# ------------------------------------------------------------------ #
#  Helpers internes                                                    #
# ------------------------------------------------------------------ #

def _check_same_field(x: Fp2Element, y: Fp2Element) -> None:
    if x.p != y.p:
        raise ValueError(
            f"Les éléments appartiennent à des corps différents : p={x.p} vs p={y.p}"
        )


def _sqrt_fp(a: int, p: int) -> int | None:
    """Racine carrée dans Z/pZ. Retourne None si inexistante."""
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p == 2:
        return a % 2
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # Tonelli-Shanks pour p ≡ 1 mod 4
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)
    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        i, temp = 1, t * t % p
        while temp != 1:
            temp = temp * temp % p
            i += 1
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = b * b % p
        t = t * c % p
        r = r * b % p


def _tonelli_shanks_fp2_simple(alpha: Fp2Element, p: int) -> Fp2Element:
    """
    Racine carrée dans Fp² via recherche de non-résidu quadratique.
    Version simplifiée avec limite d'itérations.
    """
    # |Fp²*| = p² - 1 = 2^s * q
    order = p * p - 1
    q, s = order, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    
    # Trouver un non-résidu quadratique
    g = _find_non_qr_fp2_simple(p)
    
    m = s
    c = g ** q
    t = alpha ** q
    r = alpha ** ((q + 1) // 2)
    
    # Limite de sécurité (évite les boucles infinies)
    for _ in range(100):
        if t.is_zero():
            return Fp2Element(0, 0, p)
        if t.is_one():
            return r
        
        # Trouver le plus petit i tel que t^(2^i) = 1
        i, temp = 1, t * t
        for _ in range(1, m):
            if temp.is_one():
                break
            temp = temp * temp
            i += 1
        
        b = c ** (1 << (m - i - 1))
        m = i
        c = b * b
        t = t * c
        r = r * b
    
    raise ArithmeticError("Tonelli-Shanks Fp² n'a pas convergé après 100 itérations")


def _find_non_qr_fp2_simple(p: int) -> Fp2Element:
    """Trouve un non-résidu quadratique dans Fp² (version simple)."""
    order = p * p - 1
    exp = order // 2
    
    # Essayer d'abord t (le générateur)
    t = Fp2Element(0, 1, p)
    if not (t ** exp).is_one():
        return t
    
    # Essayer t+1
    t1 = Fp2Element(1, 1, p)
    if not (t1 ** exp).is_one():
        return t1
    
    # Essayer des éléments aléatoires simples
    for a in range(p):
        for b in range(p):
            if a == 0 and b == 0:
                continue
            elem = Fp2Element(a, b, p)
            if not (elem ** exp).is_one():
                return elem
    
    raise ArithmeticError(f"Pas de non-résidu quadratique trouvé dans Fp² pour p={p}")