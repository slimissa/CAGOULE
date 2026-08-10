"""
params.py — Dérivation complète des paramètres CAGOULE v3.1.0

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
P_SEED_BYTES   = 8  # v2.5.0: no longer used (Mersenne pool replaced random prime)
BLOCK_SIZE_N   = 16
NUM_ROUND_KEYS = 64

# ── v2.5.0 — Pool Mersenne-64 ─────────────────────────────────────────
# 8 premiers de la forme p = 2^64 − k, vérifiés Miller-Rabin (13 témoins).
# k < 2^10 → mulmod_mersenne64x4 en ~13 instructions vs Barrett ~22.
MERSENNE_POOL = [
    (59,  18446744073709551557),  # 2^64 -  59
    (83,  18446744073709551533),  # 2^64 -  83
    (95,  18446744073709551521),  # 2^64 -  95
    (179, 18446744073709551437),  # 2^64 - 179
    (189, 18446744073709551427),  # 2^64 - 189
    (257, 18446744073709551359),  # 2^64 - 257
    (279, 18446744073709551337),  # 2^64 - 279
    (323, 18446744073709551293),  # 2^64 - 323
]
Z_OFFSET_N   = 16    # nombre d'offsets (= BLOCK_SIZE_N)
Z_OFFSET_BYTES = 128 # Z_OFFSET_N * 8 octets
_MAX_NODE_ATTEMPTS = 10000


# ── KDF ──────────────────────────────────────────────────────────────

class CagouleDependencyError(RuntimeError):
    """
    Levée quand une dépendance déclarée comme OBLIGATOIRE (pyproject.toml
    `dependencies = [...]`, pas `optional-dependencies`) est absente à
    l'exécution.

    CORRECTIF (audit round 2, N3) : avant ce correctif, `derive_k_master()`
    retombait SILENCIEUSEMENT sur scrypt (`_kdf_scrypt`) si `argon2-cffi`
    n'était pas importable — aucun avertissement, aucune exception. `scrypt`
    n'est documenté nulle part (pas dans README.md, pas dans SECURITY.md,
    pas dans pyproject.toml) : c'était un filet de sécurité interne pour
    un cas censé être impossible, puisque `argon2-cffi>=23.0.0` est une
    dépendance OBLIGATOIRE du paquet, pas optionnelle.

    Conséquence du silence : deux machines chiffrant/déchiffrant avec le
    même (password, salt) produisaient des k_master DIFFÉRENTS selon que
    argon2-cffi soit installé ou non, sans aucune indication de la cause.
    La couche C (cagoule_kdf_argon2id) n'a AUCUN filet scrypt — elle échoue
    à la compilation/liaison si libargon2 est absent. Ce correctif aligne
    le comportement Python sur celui de C : échec explicite plutôt que
    substitution silencieuse d'un KDF différent.
    """
    pass


def _kdf_argon2id(password, salt):
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(secret=password, salt=salt,
                           time_cost=3, memory_cost=65536,
                           parallelism=1, hash_len=K_MASTER_SIZE, type=Type.ID)

def derive_k_master(password, salt, fast_mode=False):
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt doit faire {SALT_SIZE} octets, reçu {len(salt)}")
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError as exc:
        raise CagouleDependencyError(
            "argon2-cffi n'est pas installé, mais c'est une dépendance "
            "OBLIGATOIRE de CAGOULE (pyproject.toml: dependencies, pas "
            "optional-dependencies). CAGOULE refuse de dériver k_master "
            "avec un KDF de repli non documenté (scrypt) : cela produirait "
            "des clés silencieusement incompatibles avec toute installation "
            "correcte de CAGOULE (Python avec argon2-cffi, ou la couche C "
            "qui n'a aucun filet de repli). Corriger avec : "
            "pip install argon2-cffi>=23.0.0"
        ) from exc
    # CORRECTIF v3.1.0 (Finding 4) : fast_mode appliqué aussi au chemin Argon2id.
    # Avant ce correctif, fast_mode=True était silencieusement ignoré quand
    # argon2-cffi était installé → tests mesurant le coût KDF + chiffrement
    # voyaient toujours le coût KDF complet, rendant les benchmarks trompeurs.
    if fast_mode:
        # Paramètres réduits pour tests : ~3ms au lieu de ~113ms
        return hash_secret_raw(secret=password, salt=salt,
                               time_cost=1, memory_cost=8192,
                               parallelism=1, hash_len=K_MASTER_SIZE, type=Type.ID)
    return _kdf_argon2id(password, salt)


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

# v2.5.0: nextprime() conservée pour compatibilité — no longer called by derive().
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
    Paramètres CAGOULE v2.5.0.

    Nouveautés v2.5.0 :
      - Pool Mersenne-64 (8 premiers p = 2^64-k), sélection HKDF.
      - Z-Domain Shifting : z_offset ∈ Z/pZ^16, dérivé de k_master.
      - k_mersenne : constante k telle que p = 2^64 - k.

    Nouveauté v2.1.0 :
      - Attribut fast_mode stocké → permet à decipher.decrypt() de re-dériver
        avec le bon mode KDF quand password est fourni avec params= existant.
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
        # v2.5.0
        self.k_mersenne: int             = 0    # k tel que p = 2^64 - k (0 si non-Mersenne)
        self.z_offset:   list[int]       = []   # 16 offsets Z-Domain Shift ∈ Z/pZ

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

        # v2.5.0 : sélection du premier Mersenne depuis le pool
        prime_idx           = hkdf_derive(params.k_master, b'CAGOULE_PRIME_SEL_V25', 1)[0] % len(MERSENNE_POOL)
        params.k_mersenne, params.p = MERSENNE_POOL[prime_idx]
        _log.debug("p=2^64-%d (pool idx=%d, %d bits)", params.k_mersenne, prime_idx, params.p.bit_length())

        params.mu = generate_mu(params.p, timeout_s=timeout_mu)
        _log.info("µ — strat=%s in_fp2=%s", params.mu.strategy, params.mu.in_fp2)

        # CORRECTIF v3.1.0 (Finding 5 sbox.c cross-fix) : contraindre delta à [1, p-1]
        # pour éviter delta==0 qui rendrait le S-box constant (feistel(x,0) = 0).
        # En C, cagoule_sbox_init remplace silencieusement rk==0 par 1.
        # Ici on garantit que la couche Python dérive la même valeur que le C
        # en évitant 0 à la source plutôt qu'en corrigeant silencieusement.
        raw_delta    = hkdf_int(params.k_master, b'CAGOULE_DELTA', 8)
        delta        = (raw_delta % (params.p - 1)) + 1  # ∈ [1, p-1]
        params.sbox  = SBox.from_delta(delta, params.p)

        nodes             = _derive_nodes(params.k_master, params.mu, BLOCK_SIZE_N, params.p)
        params.diffusion  = DiffusionMatrix.from_nodes(nodes, params.p)

        params.k_stream = hkdf_derive(params.k_master, b'CAGOULE_ENC', K_STREAM_SIZE)

        # v2.1.0 : omega.py délègue au backend C si libcagoule.so ≥ v2.1
        from .omega import generate_round_keys
        params.round_keys = generate_round_keys(params.n, params.salt, params.p)

        # v2.5.0 : Z-Domain Shifting — 16 offsets additifs dans Z/pZ
        # Dérivés de k_master : imprévisibles sans connaître le mot de passe.
        z_raw = hkdf_derive(params.k_master, b'CAGOULE_Z_SHIFT_V25', Z_OFFSET_BYTES)
        params.z_offset = [
            int.from_bytes(z_raw[i*8:(i+1)*8], 'big') % params.p
            for i in range(Z_OFFSET_N)
        ]
        _log.debug("z_offset[0]=%d (16 offsets Z-Shift dérivés)", params.z_offset[0])

        return params

    @classmethod
    def derive_for_benchmark(
        cls,
        password: bytes | str,
        fast_mode: bool = False,
        salt: bytes | None = None,
        ) -> "CagouleParams":
        """
        Alias de derive() avec signature compatible cagoule-bench v2.0.
        Le bench appelle derive_for_benchmark(pwd, fast_mode=..., salt=...)
        ce qui correspond exactement à derive(pwd, salt, fast_mode).
        """
        return cls.derive(password, salt=salt, fast_mode=fast_mode)

    @classmethod
    def clear_benchmark_cache(cls) -> None:
        for p in _BENCHMARK_CACHE.values():
            if hasattr(p, 'zeroize'):
                p.zeroize()
        _BENCHMARK_CACHE.clear()

    def zeroize(self) -> None:
        """Tente d'effacer le matériel de clé de la mémoire du processus.

        LIMITATION CONNUE (Bug 4 / Finding 1) : k_master et k_stream sont des
        objets bytes Python immuables. bytearray(self.k_master) crée une COPIE —
        secure_zeroize efface la copie, pas l'original. L'objet bytes original
        reste en mémoire jusqu'à ce que le GC CPython le réutilise.

        Fix complet prévu v3.2.0 : stocker k_master/k_stream comme
        ctypes.create_string_buffer dès la dérivation → zéroisation réelle.

        Mitigation actuelle : appeler params.zeroize() le plus tôt possible
        pour minimiser la fenêtre d'exposition, et utiliser le context manager
        (with params:) pour garantir l'appel même en cas d'exception.
        """
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
        # v2.5.0
        if self.z_offset:
            for i in range(len(self.z_offset)):
                self.z_offset[i] = 0
            self.z_offset = []
        self.k_mersenne = 0
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
        # CORRECTIF v3.0.1 — SÉCURITÉ : la sérialisation pickle de k_master
        # en clair via ProcessPoolExecutor (pattern recommandé dans la docstring
        # d'encrypt_bulk_ctr) expose le matériel de clé maître dans les pipes IPC
        # du système d'exploitation, annulant les garanties de zéroïsation.
        # k_master est le secret unique duquel dérivent p, la S-box, la matrice,
        # k_stream, les round_keys et z_offset — le compromettre une fois casse
        # toute la session sans dépendre d'Argon2id.
        # Solution : interdire le pickle. Pour le parallélisme multi-processus,
        # utiliser un champ partagé bas-niveau (multiprocessing.Value/Array) ou
        # passer uniquement (password, salt) aux workers et re-dériver dans chaque
        # worker (Argon2id est amortissable au niveau des processus via fork avant
        # la dérivation, pas via pickle après).
        raise TypeError(
            "CagouleParams ne peut pas être sérialisé par pickle. "
            "k_master serait exposé en clair dans les pipes IPC de ProcessPoolExecutor, "
            "annulant les garanties de zéroïsation et d'isolation du matériel de clé. "
            "Pour le parallélisme multi-processus, passer (password, salt) aux workers "
            "et appeler CagouleParams.derive() dans chaque worker."
        )

    @classmethod
    def _reconstruct(cls, salt, k_master, n, p, mu, fast_mode=False):
        params           = cls()
        params.salt      = salt
        params.k_master  = k_master
        params.n         = n
        params.p         = p
        params.mu        = mu
        params.fast_mode = fast_mode   # ← v2.1.0

        # CORRECTIF (audit round 2, H2, Option B) : formule alignée sur
        # derive() -- (raw % (p-1)) + 1, ∈ [1, p-1]. L'ancienne formule
        # (`% p`, pouvant valoir 0) divergeait de derive() sans raison
        # documentée. _reconstruct() n'a aucun appelant dans la base de
        # code actuelle (vérifié) -- ce correctif n'a donc aucun effet sur
        # un chemin vivant, mais évite qu'un futur appelant produise une
        # S-box différente de celle de derive() pour le même k_master.
        delta            = (hkdf_int(k_master, b'CAGOULE_DELTA', 8) % (p - 1)) + 1
        params.sbox      = SBox.from_delta(delta, p)

        nodes            = _derive_nodes(k_master, mu, BLOCK_SIZE_N, p)
        params.diffusion = DiffusionMatrix.from_nodes(nodes, p)

        params.k_stream  = hkdf_derive(k_master, b'CAGOULE_ENC', K_STREAM_SIZE)

        from .omega import generate_round_keys
        params.round_keys = generate_round_keys(n, salt, p)
        # v2.5.0: set k_mersenne from Mersenne pool (0 if legacy prime)
        params.k_mersenne = 0
        for k_m, p_m in MERSENNE_POOL:
            if p_m == p:
                params.k_mersenne = k_m
                break
        # v2.5.0: re-dériver z_offset si prime Mersenne (sinon [])
        # z_offset est déterministe depuis k_master — toujours re-dérivable.
        if params.k_mersenne > 0:
            z_raw = hkdf_derive(k_master, b'CAGOULE_Z_SHIFT_V25', Z_OFFSET_BYTES)
            params.z_offset = [
                int.from_bytes(z_raw[i*8:(i+1)*8], 'big') % p
                for i in range(Z_OFFSET_N)
            ]
        else:
            params.z_offset = []
        return params