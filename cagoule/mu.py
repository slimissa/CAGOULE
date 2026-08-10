"""
mu.py — Génération de µ racine de x⁴+x²+1 — CAGOULE v3.1.0
CORRECTIF v3.0.1 : la génération de µ dans Z/pZ (stratégie A) échoue pour certaines primes Mersenne-64 de production
(pas de bug dans l'algorithme, mais un bug de conception : la stratégie A n'est pas garantie de réussir pour toutes les p, et la stratégie C n'était pas implémentée).
Identique à v1.x.
"""
from __future__ import annotations
import time
from typing import Union
from .fp2 import Fp2Element
from .logger import get_logger as _get_logger
_log = _get_logger(__name__)

MuType = Union[int, Fp2Element]

def _sqrt_mod(n, p):
    if n==0: return 0
    if p==2: return n%2
    if pow(n,(p-1)//2,p)!=1: return None
    if p%4==3: return pow(n,(p+1)//4,p)
    q,s=p-1,0
    while q%2==0: q//=2; s+=1
    z=2
    while pow(z,(p-1)//2,p)!=p-1: z+=1
    m,c,t,r=s,pow(z,q,p),pow(n,q,p),pow(n,(q+1)//2,p)
    while True:
        if t==0: return 0
        if t==1: return r
        i,tmp=1,t*t%p
        while tmp!=1: tmp=tmp*tmp%p; i+=1
        b=pow(c,1<<(m-i-1),p); m=i; c=b*b%p; t=t*c%p; r=r*b%p

def _solve_quadratic(a,b,c_coeff,p):
    if p==2:
        for x in range(2):
            if (a*x*x+b*x+c_coeff)%2==0: return x
        return None
    delta=(b*b-4*a*c_coeff)%p
    sq=_sqrt_mod(delta,p)
    if sq is None: return None
    inv2a=pow(2*a,p-2,p)
    return ((-b+sq)*inv2a)%p

def _solve_in_zp(p, timeout_s=5.0):
    deadline=time.monotonic()+timeout_s
    r=_solve_quadratic(1,1,1,p)
    if r is not None: return r
    if time.monotonic()>deadline: return None
    return _solve_quadratic(1,p-1,1,p)

def _verify_root_zp(mu,p):
    return (pow(mu,4,p)+pow(mu,2,p)+1)%p==0

def _mu_in_fp2(p):
    return Fp2Element.t_generator(p)

def _verify_root_fp2(mu,p):
    one=Fp2Element(1,0,p); zero=Fp2Element(0,0,p)
    return mu**4+mu**2+one==zero

class MuResult:
    def __init__(self,mu,in_fp2,strategy,p):
        self.mu=mu; self.in_fp2=in_fp2; self.strategy=strategy; self.p=p
    def is_fp2(self): return self.in_fp2
    def as_int(self):
        if self.in_fp2: raise TypeError("µ est dans Fp², pas dans Z/pZ")
        return int(self.mu)
    def as_fp2(self):
        if not self.in_fp2: return Fp2Element.from_int(self.mu,self.p)
        return self.mu
    def __repr__(self):
        return f"MuResult(strategy={self.strategy!r}, mu={self.mu!r}, in_fp2={self.in_fp2}, p={self.p})"

def generate_mu(p, timeout_s=5.0):
    mu_int=_solve_in_zp(p,timeout_s=timeout_s)
    if mu_int is not None:
        if not _verify_root_zp(mu_int,p):
            raise ArithmeticError(f"Bug: µ={mu_int} ne vérifie pas x⁴+x²+1=0 mod {p}")
        _log.debug("µ trouvé dans Z/pZ (strat. A): %d", mu_int)
        return MuResult(mu=mu_int,in_fp2=False,strategy="A",p=p)
    mu_fp2=_mu_in_fp2(p)
    if not _verify_root_fp2(mu_fp2,p):
        raise ArithmeticError(f"Bug: µ=t n'est pas racine dans Fp² pour p={p}")
    _log.info("µ non trouvé dans Z/pZ → Fp² (strat. C)")
    return MuResult(mu=mu_fp2,in_fp2=True,strategy="C",p=p)

def generate_vandermonde_nodes(mu_result, n, k_master_bytes, hkdf_fn):
    """
    DÉPRÉCIÉ — FONCTION MORTE — NE PAS UTILISER.

    CORRECTIF v3.0.1 : cette fonction n'a aucun appelant dans le codebase
    (grep confirmé). Elle présente un bug de sécurité : pas d'évitement de
    collision entre nœuds générés, contrairement à params._derive_nodes()
    qui est la fonction de production (avec retry loop et max_attempts=10000).
    Un futur développeur qui câblerait cette fonction par erreur réintroduirait
    exactement le bug que params._derive_nodes() a corrigé.

    Utiliser exclusivement params._derive_nodes() pour la dérivation des nœuds
    Vandermonde en production.
    """
    raise NotImplementedError(
        "generate_vandermonde_nodes est dépréciée et ne doit pas être utilisée. "
        "Utiliser params._derive_nodes() qui inclut l'évitement de collision."
    )
    p=mu_result.p
    alpha0=mu_result.mu.a if mu_result.in_fp2 else int(mu_result.mu)%p
    nodes=[alpha0]
    for i in range(1,n):
        info=f"NODE_{i}".encode()
        node=hkdf_fn(k_master_bytes,info,8)%p
        nodes.append(node)
    return nodes

def generate_cauchy_beta(n, k_master_bytes, hkdf_fn):
    """
    DÉPRÉCIÉ — FONCTION MORTE — NE PAS UTILISER.

    CORRECTIF v3.0.1 : trouvée lors de l'audit du correctif precedent comme
    fonction sœur de generate_vandermonde_nodes (même fichier, même catégorie
    "code mort"), avec exactement le même défaut : aucun évitement de collision
    entre les coefficients beta générés, contrairement à la construction
    Cauchy de production (matrix.py::_cauchy_matrix / cagoule_matrix.c) qui
    vérifie explicitement alpha[i]+beta[j] != 0 et relève toute collision.

    Zéro appelant dans le codebase. Câbler cette fonction par erreur
    réintroduirait un risque de matrice Cauchy singulière ou de coefficients
    dégénérés, exactement le bug que la construction de production évite.

    Utiliser exclusivement matrix.py::_cauchy_matrix (Python) ou
    cagoule_matrix.c::_make_distinct (C) pour la génération de coefficients
    Cauchy en production.
    """
    raise NotImplementedError(
        "generate_cauchy_beta est dépréciée et ne doit pas être utilisée. "
        "Utiliser matrix.py::_cauchy_matrix qui inclut l'évitement de collision "
        "(vérification alpha[i]+beta[j] != 0)."
    )
