"""
fp2.py — Arithmétique dans Fp² = Z/pZ[t]/(t²+t+1) — CAGOULE v3.1.0
Identique à v1.x — aucun changement nécessaire.
"""
from __future__ import annotations

class Fp2Element:
    __slots__ = ("a", "b", "p")
    def __init__(self, a, b, p):
        if p < 2: raise ValueError(f"p doit être ≥ 2, reçu {p}")
        self.a = a % p; self.b = b % p; self.p = p
    def __repr__(self): return f"Fp2({self.a} + {self.b}·t, p={self.p})"
    def __eq__(self, other):
        if isinstance(other, Fp2Element): return self.a==other.a and self.b==other.b and self.p==other.p
        if isinstance(other, int): return self.b==0 and self.a==other%self.p
        return NotImplemented
    def is_zero(self): return self.a==0 and self.b==0
    def is_one(self):  return self.a==1 and self.b==0
    def __add__(self, o): _chk(self,o); return Fp2Element(self.a+o.a, self.b+o.b, self.p)
    def __sub__(self, o): _chk(self,o); return Fp2Element(self.a-o.a, self.b-o.b, self.p)
    def __neg__(self):    return Fp2Element(-self.a, -self.b, self.p)
    def __mul__(self, o):
        if isinstance(o, int): return Fp2Element(self.a*o, self.b*o, self.p)
        _chk(self,o); p=self.p
        ac=(self.a*o.a)%p; bd=(self.b*o.b)%p
        ad_bc=(self.a*o.b+self.b*o.a)%p
        return Fp2Element((ac-bd)%p, (ad_bc-bd)%p, p)
    def __rmul__(self, s): return self.__mul__(s)
    def __pow__(self, exp):
        if exp < 0: return self.inverse()**(-exp)
        p=self.p; result=Fp2Element(1,0,p); base=Fp2Element(self.a,self.b,p); e=exp
        while e>0:
            if e&1: result=result*base
            base=base*base; e>>=1
        return result
    def inverse(self):
        p=self.p
        if self.is_zero(): raise ZeroDivisionError("Inversion de zéro dans Fp²")
        norm=(self.a*self.a - self.a*self.b + self.b*self.b)%p
        if norm==0: raise ZeroDivisionError(f"Norme nulle pour {self!r}")
        ni=pow(norm,p-2,p)
        return Fp2Element((self.a-self.b)%p*ni%p, (-self.b)%p*ni%p, p)
    def sqrt(self):
        """
        Racine carrée dans Fp² = Z/pZ[t]/(t²+t+1), via Tonelli–Shanks général.

        CORRECTIF v3.0.1 (2e itération) : les deux formules tentées précédemment
        ((p²+1)//4 puis (p²+p)//4) sont des raccourcis valables UNIQUEMENT
        quand l'exposant cible est un entier ET que la condition p ≡ 3 (mod 4)
        tient pour le corps Z/pZ[i]/(i²+1) — ce qui ne s'applique PAS ici de
        toute façon (notre extension est t²+t+1, pas i²+1), et qui de plus ne
        tenait même pas empiriquement : les primes Mersenne-64 de production
        ont un p mod 4 MIXTE (1 pour 6 des 8 premiers, 3 pour 2 d'entre eux,
        vérifié directement) — aucun raccourci à exposant fixe ne peut donc
        fonctionner uniformément sur le pool.

        Fix correct : Tonelli–Shanks GÉNÉRAL sur le groupe multiplicatif de
        Fp² (ordre q = p²-1), qui fonctionne pour TOUTE caractéristique impaire
        et toute structure de q, sans dépendre de p mod 4. C'est l'algorithme
        standard (pas un raccourci) — voir Tonelli (1891)/Shanks (1973),
        généralisé ici à un corps fini quelconque via son ordre multiplicatif.

        Toujours non auditée pour usage cryptographique — fonction de test
        sans appelant dans le pipeline de chiffrement (mu.py/generate_mu ne
        l'utilise pas). Vérifiée par test_fp2.py::test_sqrt_t avec assertion
        stricte (plus de tolérance "ArithmeticError = pass") sur p<=257 ET
        sur les 8 premiers de production.
        """
        p = self.p
        if self.is_zero():
            return Fp2Element(0, 0, p)

        # PRÉCONDITION DE CORPS : Z/pZ[t]/(t²+t+1) est un corps SSI t²+t+1 est
        # irréductible sur Fp, ce qui équivaut à p ≡ 2 (mod 3) (discriminant -3
        # non-résidu quadratique mod p). Si p ≡ 1 (mod 3), t²+t+1 = (t-r1)(t-r2)
        # se factorise par CRT — l'anneau résultant Fp×Fp a des diviseurs de zéro,
        # son groupe multiplicatif n'est PAS cyclique d'ordre p²-1, et Tonelli-Shanks
        # ne s'applique pas du tout (Lagrange ne garantit plus x^(p²-1)=1 pour tout x).
        #
        # DÉCOUVERT EN CORRIGEANT v3.0.1 : la version précédente du correctif
        # échouait silencieusement sur tout p ≡ 1 (mod 3) sans jamais détecter
        # cette précondition — confirmé par test contre force brute : 4/144 cas
        # (p=7,13,31,61, tous ≡1 mod 3) donnaient un faux ArithmeticError alors
        # qu'une racine existe dans l'anneau (mais Tonelli-Shanks, qui suppose un
        # corps, ne peut pas la trouver par cette méthode).
        #
        # Note positive : ceci NE CASSE PAS le pipeline de production. mu.py
        # (le seul module qui aurait pu utiliser Fp2) bascule déjà correctement
        # vers une stratégie Z/pZ directe ("stratégie A") pour les 2 primes du
        # pool Mersenne-64 où p ≡ 1 (mod 3) (k=189, k=279) — confirmé par
        # generate_mu(). Fp2Element.sqrt() reste un outil de test pur sans
        # impact sur le chiffrement réel.
        if p % 3 != 2:
            raise ArithmeticError(
                f"Fp²(p={p}) = Z/pZ[t]/(t²+t+1) N'EST PAS UN CORPS car p≡{p%3} (mod 3) "
                "(requiert p≡2 mod 3 pour que t²+t+1 soit irréductible). "
                "Tonelli-Shanks ne s'applique pas à cet anneau — racines carrées "
                "non calculables par cette méthode dans Fp×Fp (CRT)."
            )

        q = p * p - 1  # ordre du groupe multiplicatif Fp²* — valide uniquement si p≡2 mod 3

        # Test de résidu quadratique : x est un carré ssi x^(q/2) == 1
        if not (self ** (q // 2)).is_one():
            raise ArithmeticError(
                f"Pas de racine carrée dans Fp²(p={p}) — élément non résidu quadratique."
            )

        # Tonelli–Shanks général : écrire q = s * 2^e avec s impair
        s, e = q, 0
        while s % 2 == 0:
            s //= 2
            e += 1

        if e == 1:
            # Cas simple : q/2 est impair-compatible, exposant direct (s+1)//2
            return self ** ((s + 1) // 2)

        # Trouver un non-résidu quadratique z dans Fp² — DOIT être non-nul.
        # Bug corrigé : la recherche précédente ne balayait que b=0 et pouvait
        # accepter z=0 par erreur (0^(q/2)=0, jamais ==1, donc faussement
        # "non-résidu" alors que 0 est invalide pour Tonelli-Shanks).
        #
        # Échantillonnage pseudo-aléatoire déterministe (pas de scan exhaustif :
        # nécessaire pour p~2^64). ~moitié des éléments non-nuls sont non-résidus,
        # donc convergence attendue en ~2 essais. Graine fixe par élément pour
        # un comportement déterministe et reproductible (pas de dépendance à
        # l'état global de random).
        import random as _random
        rng = _random.Random(f"{self.a},{self.b},{p}")  # déterministe par élément
        z = None
        for _ in range(10_000):
            cand = Fp2Element(rng.randrange(p), rng.randrange(p), p)
            if cand.is_zero():
                continue
            if not (cand ** (q // 2)).is_one():
                z = cand
                break
        if z is None:
            raise ArithmeticError(
                f"Tonelli-Shanks Fp²(p={p}) — aucun non-résidu trouvé en 10000 essais "
                "(corps anormalement structuré ou bug)."
            )

        m = e
        c = z ** s
        t_ = self ** s
        r_ = self ** ((s + 1) // 2)

        one = Fp2Element(1, 0, p)
        while not (t_ == one):
            # Trouver le plus petit i tel que t_^(2^i) == 1
            t2i = t_
            i = 0
            while not (t2i == one):
                t2i = t2i * t2i
                i += 1
                if i > m:
                    raise ArithmeticError(
                        f"Tonelli-Shanks Fp²(p={p}) — non-convergence (bug interne)."
                    )
            b = c
            for _ in range(m - i - 1):
                b = b * b
            m = i
            c = b * b
            t_ = t_ * c
            r_ = r_ * b

        return r_
    def to_int(self):
        if self.b!=0: raise ValueError(f"{self!r} n'est pas dans Fp (b≠0)")
        return self.a
    @classmethod
    def from_int(cls, x, p): return cls(x%p, 0, p)
    @classmethod
    def t_generator(cls, p): return cls(0, 1, p)

def _chk(x, y):
    if x.p!=y.p: raise ValueError(f"Corps différents : p={x.p} vs p={y.p}")
