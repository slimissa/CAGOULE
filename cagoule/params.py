"""
params.py — Dérivation complète des paramètres CAGOULE v2.1.0

Changements v2.1.0 :
  - Attribut fast_mode stocké dans CagouleParams
    → decipher.decrypt() peut re-dériver avec le bon mode KDF
    → Corrige test_mauvais_mdp (mauvais mdp détecté même avec params=)
  - Round keys via omega.py v2.1.0 (C si libcagoule.so ≥ v2.1)
  - Commentaire "omega.c prévu v2.1" → mis à jour
"""
from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .fp2    import Fp2Element
from .mu     import generate_mu, MuResult
from .sbox   import SBox
from .matrix import DiffusionMatrix
from .logger import get_logger
from ._binding import cagoule_p_bytes

_log = get_logger(__name__)

_BENCHMARK_CACHE: dict = {}

SALT_SIZE      = 32
K_MASTER_SIZE  = 64
K_STREAM_SIZE  = 32
P_SEED_BYTES   = 8
BLOCK_SIZE_N   = 16
NUM_ROUND_KEYS = 64
_SCRYPT_N_PROD = 2**17
_SCRYPT_N_TEST = 2**14
_MAX_NODE_ATTEMPTS = 10000


# ── KDF ──────────────────────────────────────────────────────────────

def _kdf_argon2id(password, salt):
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(secret=password, salt=salt,
                           time_cost=3, memory_cost=65536,
                           parallelism=1, hash_len=K_MASTER_SIZE, type=Type.ID)

def _kdf_scrypt(password, salt, scrypt_n=_SCRYPT_N_PROD):
    kdf = Scrypt(salt=salt, length=K_MASTER_SIZE, n=scrypt_n, r=8, p=1)
    return kdf.derive(password)

def derive_k_master(password, salt, fast_mode=False):
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt doit faire {SALT_SIZE} octets, reçu {len(salt)}")
    try:
        return _kdf_argon2id(password, salt)
    except ImportError:
        n = _SCRYPT_N_TEST if fast_mode else _SCRYPT_N_PROD
        return _kdf_scrypt(password, salt, scrypt_n=n)


# ── HKDF ─────────────────────────────────────────────────────────────

def hkdf_derive(key_material, info, length):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(key_material)

def hkdf_int(key_material, info, length):
    return int.from_bytes(hkdf_derive(key_material, info, length), 'big')


# ── Nombres premiers ──────────────────────────────────────────────────

def _is_prime_miller_rabin(n):
    if n < 2: return False
    if n in (2,3,5,7,11,13): return True
    if n % 2 == 0: return False
    r, d = 0, n-1
    while d%2==0: r+=1; d//=2
    for a in [2,3,5,7,11,13,17,19,23,29,31,37]:
        if a >= n: continue
        x = pow(a, d, n)
        if x==1 or x==n-1: continue
        for _ in range(r-1):
            x = x*x%n
            if x==n-1: break
        else: return False
    return True

def nextprime(n):
    if n <= 2: return 2
    candidate = n if n%2!=0 else n+1
    while not _is_prime_miller_rabin(candidate):
        candidate += 2
    return candidate


# ── Nœuds de la matrice ───────────────────────────────────────────────

def _derive_nodes(k_master, mu, n, p):
    alpha0 = mu.mu.a % p if mu.in_fp2 else int(mu.mu) % p
    nodes = [alpha0]
    seen  = {alpha0}
    for i in range(1, n):
        info = f"CAGOULE_NODE_{i}".encode()
        raw  = hkdf_int(k_master, info, 8) % p
        attempts = 0
        while raw in seen and attempts < _MAX_NODE_ATTEMPTS:
            raw = (raw + 1) % p
            attempts += 1
        if raw in seen:
            raise RuntimeError(
                f"Impossible de générer un nœud distinct après {_MAX_NODE_ATTEMPTS} tentatives"
            )
        nodes.append(raw)
        seen.add(raw)
    return nodes


# ── CagouleParams ─────────────────────────────────────────────────────

class CagouleParams:
    """
    Paramètres CAGOULE v2.1.0.

    Nouveauté v2.1.0 :
      - Attribut fast_mode stocké → permet à decipher.decrypt() de re-dériver
        avec le bon mode KDF quand password est fourni avec params= existant.
      - Round keys via omega.py v2.1.0 (backend C si libcagoule.so ≥ v2.1).
    """

    def __init__(self):
        self.salt:       bytes           = b''
        self.k_master:   bytes           = b''
        self.n:          int             = BLOCK_SIZE_N
        self.p:          int             = 0
        self.mu:         MuResult | None = None
        self.sbox:       object | None   = None
        self.diffusion:  object | None   = None
        self.k_stream:   bytes           = b''
        self.round_keys: list[int]       = []
        # v2.1.0 : mémorise le mode KDF pour permettre la re-dérivation
        self.fast_mode:  bool            = False

    @property
    def p_bytes(self) -> int:
        return cagoule_p_bytes(self.p)

    @classmethod
    def derive(cls, password: bytes | str, salt: bytes | None = None,
               timeout_mu: float = 5.0, fast_mode: bool = False) -> "CagouleParams":
        if isinstance(password, str):
            password = password.encode('utf-8')
        if salt is None:
            salt = os.urandom(SALT_SIZE)
        if len(salt) != SALT_SIZE:
            raise ValueError(f"Salt doit faire {SALT_SIZE} octets")

        params            = cls()
        params.salt       = salt
        params.fast_mode  = fast_mode   # ← v2.1.0 : stocké

        params.k_master = derive_k_master(password, salt, fast_mode=fast_mode)
        _log.debug("K_master dérivé (%d octets)", len(params.k_master))

        n_raw    = hkdf_int(params.k_master, b'CAGOULE_N', 2)
        params.n = (n_raw % (65536 - 4 + 1)) + 4

        p_seed   = hkdf_int(params.k_master, b'CAGOULE_P', P_SEED_BYTES) | (1 << 63)
        params.p = nextprime(p_seed)
        _log.debug("p=%d (%d bits)", params.p, params.p.bit_length())

        params.mu = generate_mu(params.p, timeout_s=timeout_mu)
        _log.info("µ — strat=%s in_fp2=%s", params.mu.strategy, params.mu.in_fp2)

        delta        = hkdf_int(params.k_master, b'CAGOULE_DELTA', 8) % params.p
        params.sbox  = SBox.from_delta(delta, params.p)

        nodes             = _derive_nodes(params.k_master, params.mu, BLOCK_SIZE_N, params.p)
        params.diffusion  = DiffusionMatrix.from_nodes(nodes, params.p)

        params.k_stream = hkdf_derive(params.k_master, b'CAGOULE_ENC', K_STREAM_SIZE)

        # v2.1.0 : omega.py délègue au backend C si libcagoule.so ≥ v2.1
        from .omega import generate_round_keys
        params.round_keys = generate_round_keys(params.n, params.salt, params.p)

        return params

    @classmethod
    def derive_for_benchmark(cls, password: bytes,
                              fast_mode: bool = False,
                              salt: Optional[bytes] = None) -> "CagouleParams":
        """Cache opt-in pour benchmarks — ne pas utiliser en production."""
        if salt is None:
            salt = b'\xca\xf0' * 16
        cache_key = (password, fast_mode, salt)
        if cache_key not in _BENCHMARK_CACHE:
            _BENCHMARK_CACHE[cache_key] = cls.derive(password, salt=salt, fast_mode=fast_mode)
        return _BENCHMARK_CACHE[cache_key]

    @classmethod
    def clear_benchmark_cache(cls) -> None:
        for p in _BENCHMARK_CACHE.values():
            if hasattr(p, 'zeroize'):
                p.zeroize()
        _BENCHMARK_CACHE.clear()

    def zeroize(self) -> None:
        from .utils import secure_zeroize
        if self.k_master:
            _buf = bytearray(self.k_master)
            secure_zeroize(_buf)
            self.k_master = b""
        if self.k_stream:
            _buf = bytearray(self.k_stream)
            secure_zeroize(_buf)
            self.k_stream = b""
        if self.round_keys:
            for i in range(len(self.round_keys)):
                self.round_keys[i] = 0
            self.round_keys = []
        if hasattr(self.sbox, 'zeroize'):
            self.sbox.zeroize()
        if hasattr(self.diffusion, 'zeroize'):
            self.diffusion.zeroize()
        self.sbox      = None
        self.diffusion = None
        self.mu        = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.zeroize()

    def __reduce__(self):
        return (self._reconstruct,
                (self.salt, self.k_master, self.n, self.p, self.mu, self.fast_mode))

    @classmethod
    def _reconstruct(cls, salt, k_master, n, p, mu, fast_mode=False):
        params           = cls()
        params.salt      = salt
        params.k_master  = k_master
        params.n         = n
        params.p         = p
        params.mu        = mu
        params.fast_mode = fast_mode   # ← v2.1.0

        delta            = hkdf_int(k_master, b'CAGOULE_DELTA', 8) % p
        params.sbox      = SBox.from_delta(delta, p)

        nodes            = _derive_nodes(k_master, mu, BLOCK_SIZE_N, p)
        params.diffusion = DiffusionMatrix.from_nodes(nodes, p)

        params.k_stream  = hkdf_derive(k_master, b'CAGOULE_ENC', K_STREAM_SIZE)

        from .omega import generate_round_keys
        params.round_keys = generate_round_keys(n, salt, p)
        return params