"""
cipher_ctr.py — Chiffrement CTR CAGOULE v3.1.0

Pipeline CTR :
  1. Dériver CagouleParams depuis (password, salt=os.urandom(32))
  2. IV = HKDF(k_master, b'CAGOULE_CTR_V31', 8) — 8 octets, unique par session
  3. Appel cagoule_ctr_encrypt (C-layer) ou fallback Python
  4. Chiffrement AEAD ChaCha20-Poly1305 du ciphertext CTR
  5. Retour format CGL1 v0x02

Format CGL1 v0x02 :
  MAGIC(4) | VERSION=b'\\x02'(1) | SALT(32) | NONCE(12) | CT(n) | TAG(16)

Différences vs CBC (v0x01) :
  - VERSION = 0x02
  - Pas de PKCS7 : |CT| == |plaintext| exact
  - IV CTR dérivé de k_master, non stocké dans le header
  - encrypt = decrypt côté C (CTR symétrique)
  - Plus grande flexibilité de taille (pas de contrainte de bloc)

Rétrocompatibilité :
  - Les fonctions encrypt() et decrypt() dans __init__.py produisent v0x02 par défaut
  - encrypt_cbc() force v0x01 (explicite)
  - decrypt() dispatch automatique sur VERSION
"""
from __future__ import annotations

import ctypes
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .params   import CagouleParams, BLOCK_SIZE_N
from .cipher   import (
    MAGIC, NONCE_SIZE,
    _get_matrix_ptr, _get_sbox_ptr,
    _get_out_buf, _get_input_buf, _get_rk_arr,
    _acquire_out_buf, _release_out_buf,
    _zeroize_buf, c_uint8_to_bytes,
)
from ._binding import CAGOULE_C_AVAILABLE, CAGOULE_OK, _lib
from .logger import get_logger
from . import format as _cgl1_format

_log = get_logger(__name__)

# ── Constantes format CGL1 v0x02 ──────────────────────────────────────
VERSION_CTR  = b'\x02'
VERSION_CBC  = b'\x01'
SALT_SIZE    = 32
N            = BLOCK_SIZE_N

# Taille minimale d'un ciphertext CGL1 v0x02 (header + tag vide)
CGL1_V2_MIN_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE + 16

# ── Dérivation IV CTR ──────────────────────────────────────────────────

def _derive_ctr_iv(params: CagouleParams, nonce: bytes) -> bytes:
    """
    Dérive l'IV CTR de 8 octets depuis k_master et le nonce ChaCha20.

    CORRECTIF v3.0.1 — 3e itération (fix définitif) :

    Les deux itérations précédentes liaient l'IV au header_salt (le sel Argon2id).
    Ce design brisait l'invariant fondamental CGL1 : dans le mode params= partagé,
    header_salt != params.salt → k_stream dérivé d'un sel, IV dérivé d'un autre →
    déchiffrement impossible hors de la session d'origine.

    Fix correct :

        IV = HKDF(k_master, b'CAGOULE_CTR_V31' + nonce, 8)

    Le nonce ChaCha20 (12 octets, os.urandom par appel) est :
      - Déjà aléatoire et unique par message (garantit l'unicité de l'IV)
      - Déjà présent dans le header CGL1 v0x02 (MAGIC|VERSION|SALT|NONCE|CT|TAG)
      - Indépendant du sel Argon2id (ne pose aucun problème de concordance)
      - Disponible côté decrypt par lecture directe du header

    Le header_salt (32 octets) reste params.salt dans le mode partagé, ou un
    os.urandom(32) frais dans le mode own_params — dans les deux cas il sert
    uniquement à re-dériver params.k_master/k_stream côté decrypt, exactement
    comme en v3.0.0 d'origine.

    Propriétés garanties :
      1. Unicité IV : nonce différent par appel → IV différent → pas de two-time-pad
      2. Reproductibilité : decrypt lit le nonce depuis le header → même IV garanti
      3. Invariant CGL1 : header_salt == params.salt → k_stream re-dérivable depuis
         (password, header_salt) sans garder params en mémoire (cross-session)
      4. Formule unique sans branche conditionnelle
    """
    from .params import hkdf_derive
    return hkdf_derive(params.k_master, b'CAGOULE_CTR_V31' + bytes(nonce), 8)


# ── CTR C-layer ────────────────────────────────────────────────────────

def _ctr_encrypt_c(plaintext: bytes, params: CagouleParams, nonce: bytes) -> Optional[bytes]:
    """
    Appel C cagoule_ctr_encrypt via ctypes.
    Retourne les bytes du ciphertext CTR (|CT| == |PT|), ou None si non disponible.
    """
    if not CAGOULE_C_AVAILABLE or _lib is None:
        return None

    mat_ptr  = _get_matrix_ptr(params)
    sbox_ptr = _get_sbox_ptr(params)
    if mat_ptr is None or sbox_ptr is None:
        return None

    # Vérifier que cagoule_ctr_encrypt est dans libcagoule.so
    try:
        fn = _lib.cagoule_ctr_encrypt
    except AttributeError:
        _log.warning("cagoule_ctr_encrypt non trouvé dans libcagoule.so — fallback Python")
        return None

    iv      = _derive_ctr_iv(params, nonce)
    pt_len  = len(plaintext)
    if pt_len == 0:
        return b''

    # Buffer pool : réutilisation TLS
    pt_c    = _get_input_buf(pt_len)
    # CORRECTIF v3.1.0 (Finding 1) : vérification taille buffer avant memmove
    assert ctypes.sizeof(pt_c) >= pt_len, (
        f"_get_input_buf sous-alloué : {ctypes.sizeof(pt_c)} < {pt_len}"
    )
    ctypes.memmove(pt_c, plaintext, pt_len)
    # CORRECTIF (audit round 2, M4) : _acquire_out_buf()/_release_out_buf()
    # existaient dans _buffer_pool.py depuis v3.1.0 (garde de re-entrance
    # documentée dans _get_out_buf()) mais n'étaient appelés nulle part --
    # la garde elle-même (le flag _out_buf_in_use vérifié dans
    # _get_out_buf) était donc toujours inerte : un appel encrypt imbriqué
    # sur le même thread (ex: handler de log qui chiffre) corromprait le
    # buffer TLS partagé sans que rien ne le détecte. try/finally pour
    # garantir la libération même en cas d'exception ctypes.
    ct_buf  = _acquire_out_buf(pt_len)
    try:
        # IV : 8 octets
        iv_c    = (ctypes.c_uint8 * 8)(*iv)

        # Round keys
        rk_arr  = _get_rk_arr(len(params.round_keys))
        _rk_type = (ctypes.c_uint64 * len(params.round_keys))
        ctypes.memmove(rk_arr, _rk_type(*params.round_keys),
                       len(params.round_keys) * 8)

        # z_offset
        if getattr(params, 'z_offset', None) and len(params.z_offset) == 16:
            _zo_arr = (ctypes.c_uint64 * 16)(*params.z_offset)
            _zo_ptr = ctypes.cast(_zo_arr, ctypes.POINTER(ctypes.c_uint64))
            _zo_n   = ctypes.c_size_t(16)
        else:
            _zo_ptr = ctypes.cast(ctypes.c_void_p(0), ctypes.POINTER(ctypes.c_uint64))
            _zo_n   = ctypes.c_size_t(0)

        # Configure la signature si pas encore fait
        ret = fn(
            pt_c, ctypes.c_size_t(pt_len),
            iv_c,
            mat_ptr, sbox_ptr,
            rk_arr, ctypes.c_size_t(len(params.round_keys)),
            ctypes.c_uint64(params.p),
            _zo_ptr, _zo_n,
            ct_buf, ctypes.c_size_t(pt_len),
        )

        if ret == CAGOULE_OK:
            result = c_uint8_to_bytes(ct_buf, pt_len)
            _zeroize_buf(pt_c, pt_len)
            _zeroize_buf(ct_buf, pt_len)
            _zeroize_buf(rk_arr, len(params.round_keys) * 8)
            return result

        _zeroize_buf(pt_c, pt_len)
        _zeroize_buf(ct_buf, pt_len)
        _zeroize_buf(rk_arr, len(params.round_keys) * 8)
        _log.warning("cagoule_ctr_encrypt retourné %d, fallback Python", ret)
        return None
    finally:
        _release_out_buf()


def _ctr_decrypt_c(ciphertext: bytes, params: CagouleParams, nonce: bytes) -> Optional[bytes]:
    """
    Appel C cagoule_ctr_decrypt via ctypes.
    CTR est symétrique — identique à _ctr_encrypt_c mais appelé sur CT.
    """
    if not CAGOULE_C_AVAILABLE or _lib is None:
        return None

    mat_ptr  = _get_matrix_ptr(params)
    sbox_ptr = _get_sbox_ptr(params)
    if mat_ptr is None or sbox_ptr is None:
        return None

    try:
        fn = _lib.cagoule_ctr_decrypt
    except AttributeError:
        return None

    iv     = _derive_ctr_iv(params, nonce)
    ct_len = len(ciphertext)
    if ct_len == 0:
        return b''

    ct_c   = _get_input_buf(ct_len)
    assert ctypes.sizeof(ct_c) >= ct_len, (
        f"_get_input_buf sous-alloué : {ctypes.sizeof(ct_c)} < {ct_len}"
    )
    ctypes.memmove(ct_c, ciphertext, ct_len)
    pt_buf = _acquire_out_buf(ct_len)
    try:
        iv_c   = (ctypes.c_uint8 * 8)(*iv)

        rk_arr = _get_rk_arr(len(params.round_keys))
        _rk_type = (ctypes.c_uint64 * len(params.round_keys))
        ctypes.memmove(rk_arr, _rk_type(*params.round_keys),
                       len(params.round_keys) * 8)

        if getattr(params, 'z_offset', None) and len(params.z_offset) == 16:
            _zo_arr = (ctypes.c_uint64 * 16)(*params.z_offset)
            _zo_ptr = ctypes.cast(_zo_arr, ctypes.POINTER(ctypes.c_uint64))
            _zo_n   = ctypes.c_size_t(16)
        else:
            _zo_ptr = ctypes.cast(ctypes.c_void_p(0), ctypes.POINTER(ctypes.c_uint64))
            _zo_n   = ctypes.c_size_t(0)

        ret = fn(
            ct_c, ctypes.c_size_t(ct_len),
            iv_c,
            mat_ptr, sbox_ptr,
            rk_arr, ctypes.c_size_t(len(params.round_keys)),
            ctypes.c_uint64(params.p),
            _zo_ptr, _zo_n,
            pt_buf, ctypes.c_size_t(ct_len),
        )

        if ret == CAGOULE_OK:
            result = c_uint8_to_bytes(pt_buf, ct_len)
            _zeroize_buf(ct_c, ct_len)
            _zeroize_buf(pt_buf, ct_len)
            _zeroize_buf(rk_arr, len(params.round_keys) * 8)
            return result

        _zeroize_buf(ct_c, ct_len)
        _zeroize_buf(pt_buf, ct_len)
        _zeroize_buf(rk_arr, len(params.round_keys) * 8)
        return None
    finally:
        _release_out_buf()


# ── CTR Python fallback ────────────────────────────────────────────────

def _ctr_encrypt_py(plaintext: bytes, params: CagouleParams, nonce: bytes) -> bytes:
    """
    Fallback Python pour le chiffrement CTR.

    Utilisé si libcagoule.so n'est pas disponible ou si cagoule_ctr_encrypt
    n'est pas exporté (version < v3.0.0).

    Performance : ~0.5 MB/s (Python pur — utiliser le backend C en production).
    """
    p   = params.p
    rk  = params.round_keys
    nrk = len(rk)
    iv  = _derive_ctr_iv(params, nonce)

    # z_offset (byte domain)
    # CORRECTIF (audit round 2) : `z % 256` ne garde que l'octet bas de
    # chaque z_offset[i] (uint64, 64 bits) -- 16 x 8 = 128 bits d'entropie
    # effective sur les 16 x 64 = 1024 bits de matériel z_offset dérivé.
    # Intentionnel : ce Z-shift est une couche d'obfuscation par octet
    # (domaine plaintext 0-255), pas une clé cryptographique indépendante --
    # 128 bits sont largement suffisants pour cet usage. Documenté ici pour
    # éviter qu'un futur lecteur suppose 1024 bits d'entropie réelle.
    zo_byte = bytes(z % 256 for z in params.z_offset) if params.z_offset else None

    out = bytearray(len(plaintext))
    n_full   = len(plaintext) // N
    residual = len(plaintext) % N

    for bi in range(n_full + (1 if residual else 0)):
        # Construire le bloc compteur : IV (8 octets) + bi (8 octets)
        counter_block = bytearray(16)
        for j in range(8):
            counter_block[j] = iv[j]
        bi_bytes = bi.to_bytes(8, 'big')
        for j in range(8):
            counter_block[8 + j] = bi_bytes[j]

        # Pipeline : éléments [0..15] dans Z/pZ via diffusion + sbox + rk
        block_ints = [int(b) % p for b in counter_block]
        w = params.diffusion.apply(block_ints)
        u = params.sbox.forward_block(w)
        ks_ints = [(u[j] + rk[bi % nrk]) % p for j in range(N)]
        ks = bytes(int(x) & 0xFF for x in ks_ints)

        # XOR + Z-shift
        block_len = N if bi < n_full else residual
        src_off   = bi * N
        if zo_byte:
            for j in range(block_len):
                out[src_off + j] = (
                    ((plaintext[src_off + j] + zo_byte[j % N]) & 0xFF) ^ ks[j]
                )
        else:
            for j in range(block_len):
                out[src_off + j] = plaintext[src_off + j] ^ ks[j]

    # NOTE (audit round 2, M2) : contrairement à _ctr_decrypt_py, `out`
    # ici contient le CIPHERTEXT (destiné à être publié/transmis), pas le
    # plaintext -- rien à zéroïser avant retour. Le plaintext source lui
    # (paramètre `plaintext`) est un `bytes` immuable fourni par
    # l'appelant, hors du contrôle de cette fonction.
    return bytes(out)


def _ctr_decrypt_py(ciphertext: bytes, params: CagouleParams, nonce: bytes) -> bytes:
    """
    Fallback Python pour le déchiffrement CTR.

    CTR est quasi-symétrique — seule différence : inversion du Z-shift.
    """
    p   = params.p
    rk  = params.round_keys
    nrk = len(rk)
    iv  = _derive_ctr_iv(params, nonce)
    # CORRECTIF (audit round 2) : `z % 256` ne garde que l'octet bas de
    # chaque z_offset[i] (uint64, 64 bits) -- 16 x 8 = 128 bits d'entropie
    # effective sur les 16 x 64 = 1024 bits de matériel z_offset dérivé.
    # Intentionnel : ce Z-shift est une couche d'obfuscation par octet
    # (domaine plaintext 0-255), pas une clé cryptographique indépendante --
    # 128 bits sont largement suffisants pour cet usage. Documenté ici pour
    # éviter qu'un futur lecteur suppose 1024 bits d'entropie réelle.
    zo_byte = bytes(z % 256 for z in params.z_offset) if params.z_offset else None

    out = bytearray(len(ciphertext))
    n_full   = len(ciphertext) // N
    residual = len(ciphertext) % N

    for bi in range(n_full + (1 if residual else 0)):
        counter_block = bytearray(16)
        for j in range(8):
            counter_block[j] = iv[j]
        bi_bytes = bi.to_bytes(8, 'big')
        for j in range(8):
            counter_block[8 + j] = bi_bytes[j]

        block_ints = [int(b) % p for b in counter_block]
        w = params.diffusion.apply(block_ints)
        u = params.sbox.forward_block(w)
        ks_ints = [(u[j] + rk[bi % nrk]) % p for j in range(N)]
        ks = bytes(int(x) & 0xFF for x in ks_ints)

        block_len = N if bi < n_full else residual
        src_off   = bi * N
        if zo_byte:
            for j in range(block_len):
                raw = ciphertext[src_off + j] ^ ks[j]
                out[src_off + j] = (raw - zo_byte[j % N] + 256) & 0xFF
        else:
            for j in range(block_len):
                out[src_off + j] = ciphertext[src_off + j] ^ ks[j]

    # CORRECTIF (audit round 2, M2) : `out` contient le plaintext en clair.
    # `bytes(out)` en fait une copie immuable (celle qu'on retourne) mais
    # laisse le bytearray original au GC sans le nettoyer -- le plaintext
    # reste lisible en mémoire tant que l'allocateur ne réutilise pas cette
    # zone. Zéroïsation en place avant retour (mutation réelle sur
    # bytearray, pas d'optimisation possible par l'interpréteur ici,
    # contrairement au risque classique en C sans `volatile`).
    result = bytes(out)
    for i in range(len(out)):
        out[i] = 0
    return result


# ── Format CGL1 v0x02 ─────────────────────────────────────────────────

def _build_cgl1_v2(salt: bytes) -> bytes:
    """
    Construit l'AAD pour ChaCha20-Poly1305 (format v0x02).

    NOTE (audit round 2, doc) : cet AAD n'inclut PAS le nonce (voir
    SECURITY.md §6.7 pour le suivi). C'est actuellement sûr, PAS un oubli
    silencieux : `nonce` est passé directement en paramètre AEAD à
    chacha.encrypt(nonce, ct_alg, aad) / chacha.decrypt(nonce, ct_aead, aad)
    aux deux sites d'appel (voir encrypt_ctr()/encrypt_bulk_ctr() ici et
    decipher_ctr.py côté déchiffrement) -- ChaCha20-Poly1305 (RFC 8439)
    lie cryptographiquement (clé, nonce) pour dériver la clé Poly1305
    à usage unique. Falsifier le nonce en transit change donc la clé de
    vérification et fait échouer l'authentification, même sans qu'il
    apparaisse dans les octets AAD explicites.

    Cette sûreté dépend d'un invariant simple mais réel : le `nonce`
    utilisé pour l'appel chacha.encrypt/decrypt() doit toujours être
    EXACTEMENT celui extrait du ciphertext (jamais reconstruit ou
    validé séparément). Si un futur refactor découple la construction
    de l'AAD de la sélection du nonce -- par exemple un chemin qui
    reconstruit `aad` sans avoir le `nonce` réel sous la main, ou qui
    accepte un nonce "de confiance" distinct de celui réellement utilisé
    pour chiffrer -- cette garantie disparaît silencieusement. C'est
    justement le risque que SECURITY.md §6.7 documente et que le plan
    v3.2.0 (AAD = MAGIC||VERSION||SALT||NONCE, changement de format)
    élimine explicitement au lieu de dépendre de cet invariant implicite.
    """
    return MAGIC + VERSION_CTR + salt


def _parse_cgl1_v2(data: bytes):
    """
    Parse un ciphertext CGL1 v0x02.
    Retourne (salt, nonce, ct_aead) ou lève ValueError.
    """
    if len(data) < CGL1_V2_MIN_SIZE:
        raise ValueError(
            f"Ciphertext CGL1 v0x02 trop court : {len(data)} < {CGL1_V2_MIN_SIZE}"
        )
    magic   = data[:4]
    version = data[4:5]
    if magic != MAGIC:
        raise ValueError(f"Magic invalide : {magic!r} != {MAGIC!r}")
    if version != VERSION_CTR:
        raise ValueError(
            f"Version inattendue : {version!r} "
            f"(attendu {VERSION_CTR!r} pour CTR). "
            "Utiliser decrypt_cbc() pour les ciphertexts v0x01."
        )
    salt    = data[5 : 5 + SALT_SIZE]
    nonce   = data[5 + SALT_SIZE : 5 + SALT_SIZE + NONCE_SIZE]
    ct_aead = data[5 + SALT_SIZE + NONCE_SIZE:]
    if len(ct_aead) < 16:
        raise ValueError("Ciphertext CGL1 v0x02 tronqué (tag Poly1305 manquant)")
    return salt, nonce, ct_aead


# ── API publique ───────────────────────────────────────────────────────

def _ctr_encrypt(message_bytes: bytes, params: CagouleParams, nonce: bytes) -> bytes:
    """
    Chiffrement CTR-layer (sans AEAD).

    nonce doit être le nonce ChaCha20 12-octet de ce message — il est
    mélangé dans l'IV pour garantir l'unicité du keystream même quand params
    (k_master) est partagé entre plusieurs appels.
    """
    result = _ctr_encrypt_c(message_bytes, params, nonce)
    if result is not None:
        return result
    _log.debug("CTR fallback Python (libcagoule.so non disponible ou version < 3.0.0)")
    return _ctr_encrypt_py(message_bytes, params, nonce)


def _ctr_decrypt(ciphertext_bytes: bytes, params: CagouleParams, nonce: bytes) -> bytes:
    """
    Déchiffrement CTR-layer (sans AEAD, reçoit les octets CT bruts).

    nonce doit être le nonce ChaCha20 extrait du header CGL1 v0x02 —
    identique à celui utilisé lors du chiffrement pour dériver le même IV.
    """
    result = _ctr_decrypt_c(ciphertext_bytes, params, nonce)
    if result is not None:
        return result
    return _ctr_decrypt_py(ciphertext_bytes, params, nonce)


def encrypt_ctr(message: bytes, password: bytes,
                params: Optional[CagouleParams] = None,
                fast_mode: bool = False) -> bytes:
    """
    Chiffrement CTR CAGOULE v3.0.0.

    Retourne un ciphertext au format CGL1 v0x02 :
      MAGIC(4) | VERSION=0x02(1) | SALT(32) | NONCE(12) | CT(n) | TAG(16)

    |CT| == |message| exactement. Pas de PKCS7.

    Args:
        message:   Plaintext arbitraire (longueur quelconque, y compris 0)
        password:  Mot de passe bytes
        params:    CagouleParams pré-dérivés (optionnel — pour encrypt_bulk_ctr)
        fast_mode: KDF rapide pour les tests (déconseillé en production)

    Returns:
        Ciphertext CGL1 v0x02
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message doit être bytes, reçu {type(message).__name__}")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError(f"password doit être bytes, reçu {type(password).__name__}")

    own_params = params is None

    if own_params:
        # Mode autonome : dériver params depuis un sel frais
        salt = os.urandom(SALT_SIZE)
        params = CagouleParams.derive(password, salt=salt, fast_mode=fast_mode)
    else:
        # Mode params partagé : utiliser params.salt pour l'invariant CGL1
        # (password + header_salt → k_master/k_stream doit être reproductible
        #  cross-session sans garder l'objet params en mémoire)
        salt = bytes(params.salt)

    try:
        # 1. Générer le nonce ChaCha20 AVANT de dériver l'IV CTR
        nonce = os.urandom(NONCE_SIZE)

        # 2. Chiffrement CTR algébrique — IV lié au nonce (pas au salt)
        ct_alg = _ctr_encrypt(bytes(message), params, nonce)

        # 3. Chiffrement AEAD ChaCha20-Poly1305
        aad    = _build_cgl1_v2(salt)
        chacha = ChaCha20Poly1305(params.k_stream)
        ct_aead = chacha.encrypt(nonce, ct_alg, aad)

        # 4. Assemblage CGL1 v0x02
        # CORRECTIF (audit round 2, consolidation) : délègue à
        # format.serialize_from_aead() au lieu de la concaténation inline.
        return _cgl1_format.serialize_from_aead(
            salt, nonce, ct_aead, version=_cgl1_format.VERSION_CTR)

    finally:
        if own_params:
            params.zeroize()

def encrypt_bulk_ctr(messages: list, password: bytes,
                     fast_mode: bool = False,
                     params: Optional[CagouleParams] = None) -> list:
    """
    Chiffrement CTR bulk.

    Si params= est fourni, k_master est partagé entre tous les messages
    (vrai amortissement KDF — une seule dérivation Argon2id).
    Chaque message reçoit un NONCE unique (12 octets, os.urandom) qui
    garantit l'unicité du keystream CTR -- PAS un sel unique. Le sel de
    chaque message dans ce mode est params.salt, IDENTIQUE pour tous les
    messages du batch (invariant CGL1 : password + header_salt doit
    suffire à re-dériver k_master/k_stream cross-session). C'est un choix
    délibéré, PAS un bug : voir SECURITY.md "Propriétés bulk : Python vs C"
    pour le compromis correspondant (linkabilité batch vs récupération
    par mot de passe seul), qui est l'INVERSE du bulk C (cagoule_api.c),
    lequel utilise un sel frais par message et sacrifie la récupération
    par mot de passe seul pour l'absence de linkabilité.

    Si params= est None, chaque message dérive ses propres paramètres
    (sel unique → k_master unique). Compatible avec le comportement v3.0.0.

    Usage recommandé :
        # Vrai amortissement (1 dérivation KDF pour N messages)
        p = CagouleParams.derive(password, fast_mode=False)
        cts = encrypt_bulk_ctr(messages, password, params=p)
        p.zeroize()

        # Mode indépendant (chaque message a son propre k_master)
        cts = encrypt_bulk_ctr(messages, password)
    """
    if not messages:
        return []

    own_params = params is None
    results = []

    # CORRECTIF v3.1.0 (Finding 5) : instancier ChaCha20Poly1305 une seule
    # fois pour le mode partagé (k_stream identique pour tous les messages).
    # En mode own_params, chaque message a son propre k_stream → None ici.
    chacha_shared = ChaCha20Poly1305(params.k_stream) if not own_params else None

    for i, msg in enumerate(messages):
        # CORRECTIF v3.1.0 (Finding 3) : validation du type de chaque élément
        # avant de consommer salt/nonce, sinon une erreur partielle laisse des
        # ciphertexts orphelins non retournés.
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError(
                f"encrypt_bulk_ctr: l'élément à l'index {i} doit être "
                f"bytes ou bytearray, reçu {type(msg).__name__}"
            )
        if own_params:
            # Mode autonome : sel frais → k_master unique par message
            msg_salt = os.urandom(SALT_SIZE)
            msg_params = CagouleParams.derive(password, salt=msg_salt,
                                               fast_mode=fast_mode)
        else:
            # Mode partagé : params.salt dans le header (invariant CGL1)
            msg_salt = bytes(params.salt)
            msg_params = params

        try:
            nonce  = os.urandom(NONCE_SIZE)
            ct_alg = _ctr_encrypt(bytes(msg), msg_params, nonce)
            aad    = _build_cgl1_v2(msg_salt)
            # CORRECTIF v3.1.0 (Finding 5) : instancier ChaCha20Poly1305 une
            # seule fois par message en mode own_params, ou idéalement en dehors
            # de la boucle pour le mode partagé. Voir chacha_shared ci-dessus.
            chacha = chacha_shared if (chacha_shared is not None) else ChaCha20Poly1305(msg_params.k_stream)
            ct_aead = chacha.encrypt(nonce, ct_alg, aad)
            # CORRECTIF (audit round 2, consolidation)
            results.append(_cgl1_format.serialize_from_aead(
                msg_salt, nonce, ct_aead, version=_cgl1_format.VERSION_CTR))
        finally:
            if own_params:
                msg_params.zeroize()

    return results