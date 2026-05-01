"""
fp2.py — Arithmétique dans Fp² = Z/pZ[t]/(t²+t+1) — CAGOULE v2.0.0
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
        p=self.p
        if self.is_zero(): return Fp2Element(0,0,p)
        if p<=257:
            for a in range(p):
                for b in range(p):
                    r=Fp2Element(a,b,p)
                    if r*r==self: return r
            raise ValueError(f"Pas de racine carrée dans Fp² (p={p})")
        exp=(p*p+1)//4; c=self**exp
        if c*c==self: return c
        raise ArithmeticError("Pas de racine carrée trouvée")
    def to_int(self):
        if self.b!=0: raise ValueError(f"{self!r} n'est pas dans Fp (b≠0)")
        return self.a
    @classmethod
    def from_int(cls, x, p): return cls(x%p, 0, p)
    @classmethod
    def t_generator(cls, p): return cls(0, 1, p)

def _chk(x, y):
    if x.p!=y.p: raise ValueError(f"Corps différents : p={x.p} vs p={y.p}")
