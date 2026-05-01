"""
mu.py — Génération de µ racine de x⁴+x²+1 — CAGOULE v2.0.0
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
    p=mu_result.p
    alpha0=mu_result.mu.a if mu_result.in_fp2 else int(mu_result.mu)%p
    nodes=[alpha0]
    for i in range(1,n):
        info=f"NODE_{i}".encode()
        node=hkdf_fn(k_master_bytes,info,8)%p
        nodes.append(node)
    return nodes

def generate_cauchy_beta(n, k_master_bytes, hkdf_fn):
    beta=[]
    for i in range(n):
        info=f"CAUCHY_BETA_{i}".encode()
        beta.append(hkdf_fn(k_master_bytes,info,8))
    return beta
