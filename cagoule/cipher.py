"""
cipher.py — Chiffrement CAGOULE v3.1.0

Changements v2.4.0 :
  - Intégration AVX2 complète : S-box Feistel, round-key add/sub,
    CBC XOR via addmod64x4/submod64x4 dans le backend C
  - Dispatch S-box AVX2 hissé (une détection par message)
  - _cbc_decrypt_py : lève ValueError si octet hors [0,256) (cohérence C)
  - Docstring et commentaires mis à jour

Changements v2.1.0 :
  - decrypt() et decrypt_with_params() déplacés dans decipher.py
  - _build_aad / _parse_cgl1 / _cbc_decrypt exportés pour decipher.py
  - API 100% compatible v2.0.x

Optimisations actives (inchangées depuis v2.0) :
  - _cbc_encrypt() : un seul appel ctypes pour tout le message
  - _cbc_decrypt() : idem, ratio decrypt/encrypt ≈ 0.56 (Feistel symétrique)
"""

from __future__ import annotations

import ctypes
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .params import CagouleParams, BLOCK_SIZE_N
from .omega import apply_round_key, remove_round_key

from ._buffer_pool import (
    _get_padded_buf, _get_out_buf, _get_rk_arr, _get_input_buf,
    _acquire_out_buf, _release_out_buf,
    _zeroize_buf,
)
from ._binding import (
    CAGOULE_C_AVAILABLE, _lib,
    list_to_uint64_array, bytes_to_c_uint8, c_uint8_to_bytes,
    cagoule_p_bytes,
    CAGOULE_OK, CAGOULE_ERR_CORRUPT, cagoule_err_strerror,
)
from .logger import get_logger
from . import format as _cgl1_format

_log = get_logger(__name__)

# ── Format CGL1 ───────────────────────────────────────────────────────
MAGIC      = b'CGL1'
VERSION    = b'\x01'
NONCE_SIZE = 12


# ══════════════════════════════════════════════════════════════════════
#  §1. PKCS7
# ══════════════════════════════════════════════════════════════════════

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        raise ValueError("Données vides — padding PKCS7 invalide")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Longueur de padding PKCS7 invalide : {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS7 corrompu")
    return data[:-pad_len]


# ══════════════════════════════════════════════════════════════════════
#  §2. Sérialisation Z/pZ ↔ bytes
# ══════════════════════════════════════════════════════════════════════

def elements_to_bytes(elements: list[int], p_bytes: int) -> bytes:
    return b''.join(e.to_bytes(p_bytes, 'big') for e in elements)


def bytes_to_elements(data: bytes, p_bytes: int) -> list[int]:
    if len(data) % p_bytes != 0:
        raise ValueError(
            f"Taille données ({len(data)}) non multiple de p_bytes ({p_bytes})"
        )
    return [int.from_bytes(data[i:i + p_bytes], 'big')
            for i in range(0, len(data), p_bytes)]


# ══════════════════════════════════════════════════════════════════════
#  §3. Helpers C — récupération des pointeurs
# ══════════════════════════════════════════════════════════════════════

def _get_matrix_ptr(params: CagouleParams):
    diff = params.diffusion
    if diff is None:
        return None
    if hasattr(diff, 'get_ptr') and callable(diff.get_ptr):
        return diff.get_ptr()
    if hasattr(diff, '_ptr') and diff._ptr:
        return diff._ptr
    return None


def _get_sbox_ptr(params: CagouleParams):
    sbox = params.sbox
    if sbox is None:
        return None
    if hasattr(sbox, 'get_ptr') and callable(sbox.get_ptr):
        return sbox.get_ptr()
    if hasattr(sbox, '_s') and sbox._s:
        return ctypes.byref(sbox._s)
    return None


# ══════════════════════════════════════════════════════════════════════
#  §4. Pipeline CBC-like — chiffrement
# ══════════════════════════════════════════════════════════════════════

def _encrypt_block_py(block_ints, prev_cipher, params, round_key):
    p, N = params.p, BLOCK_SIZE_N
    v = [(block_ints[j] + prev_cipher[j]) % p for j in range(N)]
    w = params.diffusion.apply(v)
    u = params.sbox.forward_block(w)
    return apply_round_key(u, round_key, p)


def _cbc_encrypt_py(padded: bytes, n_blocks: int,
                    params: CagouleParams, p_bytes: int) -> bytes:
    N = BLOCK_SIZE_N
    p = params.p
    round_keys = params.round_keys
    num_rk = len(round_keys)
    prev_cipher = [0] * N
    cipher_elems = []
    for idx, i in enumerate(range(0, len(padded), N)):
        block_ints = [b % p for b in padded[i:i + N]]
        rk = round_keys[idx % num_rk]
        c = _encrypt_block_py(block_ints, prev_cipher, params, rk)
        cipher_elems.extend(c)
        prev_cipher = c
    return elements_to_bytes(cipher_elems, p_bytes)


def _cbc_encrypt(message_bytes: bytes, params: CagouleParams) -> bytes:
    """Chiffrement CBC-like. Backend C si disponible (v2.0+)."""
    N = BLOCK_SIZE_N
    padded   = pkcs7_pad(message_bytes, N)
    n_blocks = len(padded) // N
    p_bytes  = cagoule_p_bytes(params.p)

    # v2.5.1 — z_offset est appliqué en C-layer (pas en Python)
    if CAGOULE_C_AVAILABLE and _lib is not None:
        mat_ptr  = _get_matrix_ptr(params)
        sbox_ptr = _get_sbox_ptr(params)
        if mat_ptr is not None and sbox_ptr is not None:
            ct_size   = n_blocks * N * p_bytes
            # P4: Reuse thread-local buffers instead of allocating new ones
            padded_c  = _get_padded_buf(len(padded))
            ctypes.memmove(padded_c, padded, len(padded))
            # CORRECTIF (audit round 2, M4) : voir cipher_ctr.py pour le
            # détail -- _acquire_out_buf/_release_out_buf existaient mais
            # n'étaient jamais appelés, rendant la garde de re-entrance
            # de _get_out_buf() inerte. try/finally pour couvrir les deux
            # chemins de sortie (succès -> return, échec -> fallthrough
            # vers le fallback Python plus bas).
            ct_buf    = _acquire_out_buf(ct_size)
            try:
                # Copy round keys into reusable buffer
                rk_arr    = _get_rk_arr(len(params.round_keys))
                # v2.5.1: population rk_arr en une seule opération C-level
                _rk_type = (ctypes.c_uint64 * len(params.round_keys))
                ctypes.memmove(rk_arr, _rk_type(*params.round_keys),
                              len(params.round_keys) * 8)
                # v2.5.1: z_offset passé au C-layer (16 uint64 ou NULL)
                if getattr(params, 'z_offset', None) and len(params.z_offset) == 16:
                    _zo_arr = (ctypes.c_uint64 * 16)(*params.z_offset)
                    _zo_ptr = ctypes.cast(_zo_arr, ctypes.POINTER(ctypes.c_uint64))
                    _zo_n   = ctypes.c_size_t(16)
                else:
                    _zo_ptr = ctypes.cast(ctypes.c_void_p(0), ctypes.POINTER(ctypes.c_uint64))
                    _zo_n   = ctypes.c_size_t(0)
                ret = _lib.cagoule_cbc_encrypt(
                    padded_c, ctypes.c_size_t(n_blocks),
                    ct_buf,   ctypes.c_size_t(ct_size),
                    mat_ptr, sbox_ptr,
                    rk_arr, ctypes.c_size_t(len(params.round_keys)),
                    ctypes.c_uint64(params.p),
                    _zo_ptr, _zo_n,
                )
                if ret == CAGOULE_OK:
                    result = bytes(ct_buf[:ct_size])
                    # P4: Zeroize plaintext buffer + round keys (BUG v2.3.0 fix)
                    _zeroize_buf(padded_c, len(padded))
                    _zeroize_buf(rk_arr, len(rk_arr) * 8)  # zeroize full allocated TLS buffer
                    return result
                # P4: Zeroize on error path too
                _zeroize_buf(padded_c, len(padded))
                _zeroize_buf(rk_arr, len(rk_arr) * 8)  # zeroize full allocated TLS buffer
                _log.warning("cagoule_cbc_encrypt retourné %d (%s), fallback Python", ret, cagoule_err_strerror(ret))
            finally:
                _release_out_buf()

    # v2.5.1: Python fallback — appliquer z_offset avant _cbc_encrypt_py
    if getattr(params, 'z_offset', None) and len(params.z_offset) == 16:
        _zo256  = bytes(z % 256 for z in params.z_offset)
        _tile   = _zo256 * n_blocks
        _ba     = bytearray(padded)
        for i in range(len(_ba)):
            _ba[i] = (_ba[i] + _tile[i]) & 0xFF
        padded  = bytes(_ba)
    return _cbc_encrypt_py(padded, n_blocks, params, p_bytes)


# ══════════════════════════════════════════════════════════════════════
#  §5. Pipeline CBC-like — déchiffrement
# ══════════════════════════════════════════════════════════════════════

def _decrypt_block_py(cipher_ints, prev_cipher, params, round_key):
    p, N = params.p, BLOCK_SIZE_N
    u = remove_round_key(cipher_ints, round_key, p)
    w = params.sbox.inverse_block(u)
    v = params.diffusion.apply_inverse(w)
    return [(v[j] - prev_cipher[j]) % p for j in range(N)]


def _cbc_decrypt_py(t_message_bytes: bytes, params: CagouleParams) -> bytes:
    p_bytes  = cagoule_p_bytes(params.p)
    N        = BLOCK_SIZE_N
    p        = params.p
    round_keys = params.round_keys
    num_rk   = len(round_keys)
    n_blocks = len(t_message_bytes) // (N * p_bytes)
    prev_cipher = [0] * N
    plain_elems = []
    for idx in range(n_blocks):
        chunk = t_message_bytes[idx * N * p_bytes:(idx + 1) * N * p_bytes]
        cipher_ints = bytes_to_elements(chunk, p_bytes)
        rk = round_keys[idx % num_rk]
        pt = _decrypt_block_py(cipher_ints, prev_cipher, params, rk)
        for j, val in enumerate(pt):
            if val > 255:
                raise ValueError(
                    f"Octet hors domaine [0, 256) après déchiffrement algébrique "
                    f"(bloc {idx}, position {j}, valeur {val}). "
                    f"Ciphertext corrompu ou paramètres incorrects."
                )
        plain_elems.extend(pt)
        prev_cipher = cipher_ints
    return bytes(plain_elems)

def _cbc_decrypt(t_message_bytes: bytes, params: CagouleParams) -> bytes:
    """Déchiffrement CBC-like. Backend C si disponible (v2.0+)."""
    p_bytes  = cagoule_p_bytes(params.p)
    N        = BLOCK_SIZE_N
    n_blocks = len(t_message_bytes) // (N * p_bytes)

    if CAGOULE_C_AVAILABLE and _lib is not None:
        mat_ptr  = _get_matrix_ptr(params)
        sbox_ptr = _get_sbox_ptr(params)
        if mat_ptr is not None and sbox_ptr is not None:
            # P4: Reuse thread-local buffers instead of allocating new ones
            ct_size  = len(t_message_bytes)
            ct_c     = _get_input_buf(ct_size)
            ctypes.memmove(ct_c, t_message_bytes, ct_size)
            pt_size  = n_blocks * N
            # CORRECTIF (audit round 2, M4) : voir cipher_ctr.py pour le
            # détail. try/finally couvre ici trois sorties : succès
            # (return), erreur de domaine (raise ValueError), et échec
            # inconnu (fallthrough vers le fallback Python) -- finally
            # s'exécute dans les trois cas.
            pt_buf   = _acquire_out_buf(pt_size)
            try:
                # Copy round keys into reusable buffer
                rk_arr   = _get_rk_arr(len(params.round_keys))
                # v2.5.1: population rk_arr en une seule opération C-level
                _rk_type = (ctypes.c_uint64 * len(params.round_keys))
                ctypes.memmove(rk_arr, _rk_type(*params.round_keys),
                              len(params.round_keys) * 8)
                # v2.5.1: z_offset passé au C-layer
                if getattr(params, 'z_offset', None) and len(params.z_offset) == 16:
                    _dzo_arr = (ctypes.c_uint64 * 16)(*params.z_offset)
                    _dzo_ptr = ctypes.cast(_dzo_arr, ctypes.POINTER(ctypes.c_uint64))
                    _dzo_n   = ctypes.c_size_t(16)
                else:
                    _dzo_ptr = ctypes.cast(ctypes.c_void_p(0), ctypes.POINTER(ctypes.c_uint64))
                    _dzo_n   = ctypes.c_size_t(0)
                ret = _lib.cagoule_cbc_decrypt(
                    ct_c,    ctypes.c_size_t(n_blocks),
                    pt_buf,  ctypes.c_size_t(pt_size),
                    mat_ptr, sbox_ptr,
                    rk_arr, ctypes.c_size_t(len(params.round_keys)),
                    ctypes.c_uint64(params.p),
                    _dzo_ptr, _dzo_n,
                )
                if ret == CAGOULE_OK:
                    raw = c_uint8_to_bytes(pt_buf, pt_size)
                    # P4: Zeroize plaintext output + ciphertext + round keys (BUG v2.3.0 fix)
                    _zeroize_buf(pt_buf, pt_size)
                    _zeroize_buf(ct_c, ct_size)
                    _zeroize_buf(rk_arr, len(rk_arr) * 8)  # zeroize full allocated TLS buffer
                    # v2.5.1 — z_offset annulé en C-layer (pas en Python)
                    return raw
                if ret == CAGOULE_ERR_CORRUPT:
                    _zeroize_buf(pt_buf, pt_size)
                    _zeroize_buf(ct_c, ct_size)
                    _zeroize_buf(rk_arr, len(rk_arr) * 8)  # zeroize full allocated TLS buffer
                    raise ValueError(
                        f"b hors domaine [0,256) détecté : {cagoule_err_strerror(ret)} (code {ret})")
                # P4: Zeroize on unknown error too
                _zeroize_buf(ct_c, ct_size)
                _zeroize_buf(rk_arr, len(rk_arr) * 8)  # zeroize full allocated TLS buffer
                _log.warning("cagoule_cbc_decrypt retourné %d (%s), fallback Python", ret, cagoule_err_strerror(ret))
            finally:
                _release_out_buf()

    # Python fallback path
    raw = _cbc_decrypt_py(t_message_bytes, params)
    # v2.5.1 — annuler Z-Domain Shifting — vectorisé
    if getattr(params, 'z_offset', None):
        _zo     = params.z_offset
        _tile_n = len(raw) // 16
        _zo256  = bytes(z % 256 for z in _zo)
        _tile   = _zo256 * _tile_n
        _ba = bytearray(raw)
        _bt = bytearray(_tile)
        for i in range(len(_ba)):
            _ba[i] = (_ba[i] - _bt[i]) & 0xFF
        raw = bytes(_ba)
    return raw


# ══════════════════════════════════════════════════════════════════════
#  §6. Format CGL1
# ══════════════════════════════════════════════════════════════════════

def _build_aad(salt: bytes) -> bytes:
    return MAGIC + VERSION + salt


def _serialize_cgl1(salt: bytes, nonce: bytes, ct_tag: bytes) -> bytes:
    # CORRECTIF (audit round 2, consolidation) : délègue à
    # format.serialize_from_aead() (VERSION_BYTE=0x01 par défaut, CBC)
    # au lieu de la concaténation inline MAGIC+VERSION+salt+nonce+ct_tag.
    # Vérifié équivalent avant ce changement -- voir format.py, construit
    # et testé contre de vrais ciphertexts pendant le correctif M6.
    return _cgl1_format.serialize_from_aead(
        salt, nonce, ct_tag, version=_cgl1_format.VERSION_BYTE)


def _parse_cgl1(data: bytes) -> tuple[bytes, bytes, bytes]:
    min_size = 4 + 1 + 32 + 12 + 16   # 65 octets minimum
    if len(data) < min_size:
        raise ValueError(f"Message trop court : {len(data)} < {min_size}")
    magic, version = data[0:4], data[4:5]
    if magic != MAGIC:
        raise ValueError(f"Magic invalide : {magic!r}")
    if version != VERSION:
        if version == b'\x02':
            # CORRECTIF v3.0.1 : ce parseur est CBC-only (0x01). Si on reçoit un
            # ciphertext CTR (0x02), lever une erreur explicite plutôt que générique.
            raise ValueError(
                "Version 0x02 (CTR) reçue dans le parseur CBC — "
                "utiliser decrypt() ou decrypt_ctr() pour le dispatch automatique."
            )
        raise ValueError(f"Version non supportée : 0x{data[4]:02x}")
    return data[5:37], data[37:49], data[49:]   # salt, nonce, ct+tag


# ══════════════════════════════════════════════════════════════════════
#  §7. API publique
# ══════════════════════════════════════════════════════════════════════

def encrypt(plaintext: bytes | str, password: bytes | str,
            salt: bytes | None = None,
            params: CagouleParams | None = None,
            fast_mode: bool = False) -> bytes:
    """
    Chiffre plaintext avec CAGOULE v2.5.1.

    Args:
        plaintext  : Message à chiffrer (bytes ou str UTF-8).
        password   : Mot de passe (bytes ou str).
        salt       : Sel 32 octets (None = aléatoire).
        params     : Paramètres pré-calculés (None = dérivés depuis password+salt).
        fast_mode  : KDF rapide (tests uniquement).

    Returns:
        Bytes au format CGL1 (MAGIC + VERSION + SALT + NONCE + CT + TAG).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')

    own_params = False
    if params is None:
        params     = CagouleParams.derive(password, salt, fast_mode=fast_mode)
        own_params = True

    salt  = params.salt
    nonce = os.urandom(NONCE_SIZE)

    try:
        t_message        = _cbc_encrypt(plaintext, params)
        aad              = _build_aad(salt)
        aead             = ChaCha20Poly1305(params.k_stream)
        ciphertext_w_tag = aead.encrypt(nonce, t_message, aad)
        return _serialize_cgl1(salt, nonce, ciphertext_w_tag)
    finally:
        if own_params:
            params.zeroize()


def encrypt_with_params(plaintext: bytes | str,
                        params: CagouleParams) -> bytes:
    """
    Chiffre avec des paramètres déjà dérivés.
    Usage : KAT, benchmarks, threads (même processus).

    CORRECTIF v3.0.1 : ne PAS utiliser params avec ProcessPoolExecutor —
    CagouleParams.__reduce__() lève désormais TypeError si on tente de le
    pickler, précisément pour empêcher ce pattern qui exposait k_master en
    clair dans les pipes IPC. Pour le parallélisme multi-processus, passer
    (password, salt) à chaque worker et appeler CagouleParams.derive()
    localement dans chaque worker.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    salt  = params.salt
    nonce = os.urandom(NONCE_SIZE)
    t_message        = _cbc_encrypt(plaintext, params)
    aad              = _build_aad(salt)
    aead             = ChaCha20Poly1305(params.k_stream)
    ciphertext_w_tag = aead.encrypt(nonce, t_message, aad)
    return _serialize_cgl1(salt, nonce, ciphertext_w_tag)


# ══════════════════════════════════════════════════════════════════════
#  §8. API bulk — P2 v2.4.0
#  Une seule dérivation Argon2id pour N messages.
#  Fraction GIL-holding chute de ~46% à ~10%.
# ══════════════════════════════════════════════════════════════════════

def encrypt_bulk(
    messages: list,
    password,
    salt: bytes | None = None,
    fast_mode: bool = False,
) -> list:
    """
    Chiffre N messages avec une seule dérivation Argon2id.

    Args:
        messages   : Liste de bytes ou str à chiffrer.
        password   : Mot de passe commun (bytes ou str).
        salt       : Sel 32 octets (None = aléatoire, partagé pour tous les messages).
        fast_mode  : KDF rapide (tests uniquement).

    Returns:
        Liste de bytes au format CGL1, même ordre que messages.

    Note sécurité :
        Le sel Argon2id est partagé entre les N messages — acceptable pour
        une session unique avec le même mot de passe.
        Pour des sessions distinctes, dériver un CagouleParams par session.
    """
    if not messages:
        return []
    if isinstance(password, str):
        password = password.encode('utf-8')

    params = CagouleParams.derive(password, salt, fast_mode=fast_mode)
    try:
        return [encrypt_with_params(msg, params) for msg in messages]
    finally:
        params.zeroize()


def decrypt_bulk(
    ciphertexts: list,
    password,
    fast_mode: bool = False,
) -> list:
    """
    Déchiffre N messages CGL1 avec une seule dérivation Argon2id par sel unique.

    Groupe les ciphertexts par sel (salt) et effectue une seule dérivation
    par groupe. Si tous les ciphertexts partagent le même sel (produits par
    encrypt_bulk), une seule dérivation est effectuée.

    Args:
        ciphertexts : Liste de bytes CGL1.
        password    : Mot de passe (bytes ou str).
        fast_mode   : KDF rapide (tests uniquement).

    Returns:
        Liste de plaintext bytes, même ordre que ciphertexts. Un élément
        est None si son déchiffrement a échoué (CagouleAuthError ou
        CagouleFormatError) -- les autres éléments du même groupe de sel
        ET les groupes suivants sont quand même traités (même contrat que
        decrypt_bulk_ctr() dans decipher_ctr.py, déjà établi côté CTR).
        Les échecs sont journalisés via _log.warning avec leur index
        d'origine et le message d'erreur.
    """
    from .decipher import (
        decrypt_with_params, _parse_cgl1_salt,
        CagouleAuthError, CagouleFormatError,
    )

    if not ciphertexts:
        return []
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Grouper par sel → une seule dérivation par groupe
    from collections import defaultdict
    groups = defaultdict(list)   # salt → [(original_index, ciphertext)]
    for idx, ct in enumerate(ciphertexts):
        salt = _parse_cgl1_salt(ct)
        groups[salt].append((idx, ct))

    # CORRECTIF (audit round 2) : ne plus avorter sur le premier échec --
    # exactement le correctif déjà appliqué à decrypt_bulk_ctr() (voir
    # decipher_ctr.py, "CORRECTIF v3.1.0 (Finding 2)") mais jamais porté
    # ici pour le chemin CBC. Un ciphertext corrompu/altéré dans un groupe
    # ne doit pas faire perdre les résultats déjà obtenus pour ce groupe
    # NI empêcher le traitement des groupes suivants -- avant ce correctif,
    # une exception au milieu d'un groupe se propageait hors de la fonction
    # entière, abandonnant tout, y compris les groupes pas encore atteints.
    results = [None] * len(ciphertexts)
    errors  = []
    for salt, items in groups.items():
        params = CagouleParams.derive(password, salt, fast_mode=fast_mode)
        try:
            for orig_idx, ct in items:
                try:
                    results[orig_idx] = decrypt_with_params(ct, params)
                except (CagouleAuthError, CagouleFormatError) as e:
                    errors.append((orig_idx, e))
                    # results[orig_idx] reste None -- placeholder pour préserver les indices
        finally:
            params.zeroize()

    if errors:
        _log.warning(
            "decrypt_bulk : %d/%d ciphertexts ont échoué : %s",
            len(errors), len(ciphertexts),
            [(i, str(e)) for i, e in errors]
        )

    return results
