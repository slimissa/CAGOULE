"""
_binding.py — Chargeur ctypes pour libcagoule.so — CAGOULE v3.1.0

Nouveautés v3.0.0 :
  - cagoule_ctr_encrypt / cagoule_ctr_decrypt / cagoule_ctr_encrypt_4x
  - _HAS_CTR_API : détection runtime du backend CTR
  - get_backend_info_v300() : inclut ctr_backend

Nouveautés v2.4.0 :
  - GIL release on heavy C calls (cbc_encrypt/decrypt, matrix_mul, sbox_block)
    → ThreadPoolExecutor scaling improved from 1.7× to 4-6× at 8 workers

Nouveautés v2.3.0 (AVX2 S-box, buffer pool, QShell integration) :
  - cagoule_matrix_backend_is_avx2() : détection runtime AVX2
  - cagoule_matrix_mul_scalar / mul_inv_scalar : chemin scalaire explicite
  - get_backend_info() : dictionnaire des backends actifs

Nouveautés v2.1.0 :
  - Vérification version 2.1.0 via cagoule_version() si présent
  - Les symboles cagoule_omega_* sont détectés dans omega.py (pas ici)
    pour éviter le chargement circulaire au démarrage

Expose :
  - CagouleMatrix + cagoule_matrix_*
  - CagouleSBox64 + cagoule_sbox_*
  - cagoule_cbc_encrypt / cagoule_cbc_decrypt
  - cagoule_ctr_encrypt / cagoule_ctr_decrypt / cagoule_ctr_encrypt_4x (v3.0.0)
  - get_backend_info() (v2.2.0), get_backend_info_v230() (v2.3.0),
    get_backend_info_v300() (v3.0.0)
"""

from __future__ import annotations

import ctypes
import os
import pathlib
import warnings
from typing import Optional, List, Dict

# ── Constantes ────────────────────────────────────────────────────────
CAGOULE_N         = 16
CAGOULE_P32_PRIME = 4294967291   # plus grand premier < 2^32

CAGOULE_OK          =  0
CAGOULE_ERR_NULL    = -1
CAGOULE_ERR_SIZE    = -2
CAGOULE_ERR_CORRUPT = -3

# Messages humainement lisibles pour CAGOULE_OK/CAGOULE_ERR_* (namespace
# des primitives bas-niveau -- cagoule_cbc_encrypt/decrypt,
# cagoule_ctr_encrypt/decrypt -- DISTINCT de CAGOULE_API_ERR_* /
# cagoule_api_strerror() ci-dessus, qui couvre cagoule_api.c, une couche
# différente que le pipeline Python principal (cipher.py/cipher_ctr.py)
# n'appelle pas actuellement. Ajouté pour remplacer les messages
# d'exception qui affichaient uniquement un code numérique brut
# (ex. "code -3") sans explication -- voir cipher.py::decrypt_cbc.
_CAGOULE_ERR_MESSAGES = {
    CAGOULE_OK:          "success",
    CAGOULE_ERR_NULL:    "a required argument was NULL",
    CAGOULE_ERR_SIZE:    "output buffer is too small for this operation",
    CAGOULE_ERR_CORRUPT: "input value out of the expected domain [0, 256) -- ciphertext is likely corrupted or was not produced by this cipher",
}


def cagoule_err_strerror(code: int) -> str:
    """Traduit un code CAGOULE_OK/CAGOULE_ERR_* (primitives bas-niveau) en
    message lisible. Toujours une chaîne, jamais une exception -- un code
    inconnu retourne un message générique plutôt que de lever KeyError."""
    return _CAGOULE_ERR_MESSAGES.get(code, f"unrecognized low-level error code {code}")


# ── Localisation de libcagoule.so ─────────────────────────────────────

def _find_lib() -> Optional[pathlib.Path]:
    """Localise libcagoule.so.

    CORRECTIF v3.1.0 (Finding 2) : ajout d'un fallback via ld.so (LD_LIBRARY_PATH,
    /usr/local/lib, etc.) quand la bibliothèque n'est pas aux emplacements relatifs
    connus. Cela permet à une installation via 'make install' (qui copie
    libcagoule.so dans /usr/local/lib) de fonctionner sans LIBCAGOULE_PATH.

    CORRECTIF (post-audit perf) : cette fonction retournait auparavant le
    PREMIER chemin existant dans `candidates`, sans jamais comparer les
    deux emplacements relatifs entre eux. En pratique, `cagoule/libcagoule.so`
    (copie "installée" à côté du package Python) et
    `cagoule/c/libcagoule.so` (build directory) peuvent diverger si l'un
    des deux est reconstruit sans que l'autre soit rafraîchi -- exactement
    ce qui s'est produit durant l'audit perf : Python chargeait
    silencieusement une copie figée datant d'avant un correctif de
    performance réel (AVX2 lazy reduction), tandis que tous les
    benchmarks C liaient contre la copie à jour. Aucun avertissement
    n'était émis ; le seul symptôme était un écart de débit inexpliqué.

    Comportement actuel : si les deux chemins relatifs existent, on
    compare leur contenu. S'ils sont identiques, aucun problème -- on
    retourne le premier (comportement inchangé dans le cas sain). S'ils
    DIFFÈRENT, on émet un RuntimeWarning explicite (laquelle copie est
    plus récente, lesquels chemins) et on retourne la copie dont l'mtime
    est le plus récent -- un choix délibéré : préférer la copie la plus
    fraîche est presque toujours ce que l'appelant veut, mais le
    warning garantit que la divergence ne reste jamais silencieuse.

    LIBCAGOULE_PATH (variable d'environnement), si définie, reste un
    override explicite non soumis à cette vérification : un utilisateur
    qui la positionne a délibérément choisi un binaire précis.
    """
    env_path = os.environ.get("LIBCAGOULE_PATH")
    if env_path:
        p = pathlib.Path(env_path)
        if p.exists():
            return p
        warnings.warn(
            f"cagoule: LIBCAGOULE_PATH={env_path!r} ne pointe vers aucun "
            "fichier existant -- ignoré, poursuite de la recherche normale.",
            RuntimeWarning, stacklevel=2
        )

    relative_candidates = [
        pathlib.Path(__file__).parent / "libcagoule.so",
        pathlib.Path(__file__).parent / "c" / "libcagoule.so",
    ]
    existing = [p for p in relative_candidates if p.exists()]

    if not existing:
        # CORRECTIF : retourner un sentinel pour indiquer "chercher via ld.so"
        # Le chargement ctypes.CDLL("libcagoule.so") sera tenté dans le bloc principal
        return None

    if len(existing) == 1:
        return existing[0]

    # Deux (ou plus) candidats relatifs existent -- vérifier qu'ils sont
    # identiques avant de choisir silencieusement le premier.
    try:
        contents = [p.read_bytes() for p in existing]
    except OSError:
        # Lecture impossible (permissions, etc.) -- retomber sur l'ancien
        # comportement (premier trouvé) plutôt que de faire échouer l'import.
        return existing[0]

    if all(c == contents[0] for c in contents[1:]):
        # Identiques -- pas de divergence réelle, comportement inchangé.
        return existing[0]

    # Les copies DIVERGENT -- avertir explicitement et choisir la plus
    # récente par mtime, plutôt que le premier de la liste par hasard.
    newest = max(existing, key=lambda p: p.stat().st_mtime)
    details = "\n".join(
        f"    {p}  (mtime={p.stat().st_mtime:.0f}, {p.stat().st_size} bytes)"
        for p in existing
    )
    warnings.warn(
        f"cagoule: plusieurs copies de libcagoule.so trouvées avec un "
        f"contenu DIFFÉRENT -- une reconstruction a probablement rafraîchi "
        f"une copie sans l'autre.\n{details}\n"
        f"  -> chargement de la plus récente : {newest}\n"
        f"  Pour éviter cet avertissement, supprimez la copie obsolète ou "
        f"assurez-vous que votre processus de build/installation les "
        f"garde synchronisées.",
        RuntimeWarning, stacklevel=2
    )
    return newest


_LIBCAGOULE_SYSTEM_SEARCH = True  # Tenter la recherche ld.so si _find_lib() → None


_lib_path = _find_lib()
_lib: Optional[ctypes.CDLL] = None
CAGOULE_C_AVAILABLE = False

if _lib_path is not None:
    try:
        _lib = ctypes.CDLL(str(_lib_path))
        CAGOULE_C_AVAILABLE = True
    except OSError as e:
        warnings.warn(
            f"cagoule: impossible de charger {_lib_path}: {e}. "
            "Fallback Python pur (performances v1.x).",
            RuntimeWarning, stacklevel=2
        )
elif _LIBCAGOULE_SYSTEM_SEARCH:
    # CORRECTIF v3.1.0 (Finding 2) : tentative via le linker dynamique système
    try:
        _lib = ctypes.CDLL("libcagoule.so")
        CAGOULE_C_AVAILABLE = True
    except OSError:
        warnings.warn(
            "cagoule: libcagoule.so non trouvé (ni chemins relatifs, ni ld.so). "
            "Compiler : cd cagoule/c && make && make install. "
            "Fallback Python pur actif.",
            RuntimeWarning, stacklevel=2
        )


# ── Structures ctypes ─────────────────────────────────────────────────

class CagouleMatrixC(ctypes.Structure):
    _fields_ = [
        ("fwd",       (ctypes.c_uint64 * CAGOULE_N) * CAGOULE_N),
        ("inv",       (ctypes.c_uint64 * CAGOULE_N) * CAGOULE_N),
        ("p",         ctypes.c_uint64),
        ("kind",      ctypes.c_int),
        # v2.2.1: AVX2 column-major layouts
        ("fwd_avx2",  (ctypes.c_uint64 * (CAGOULE_N * 4)) * 4),
        ("inv_avx2",  (ctypes.c_uint64 * (CAGOULE_N * 4)) * 4),
        # v2.5.0: Mersenne pool constant
        ("k_mersenne", ctypes.c_uint64),
    ]


class CagouleSBox64C(ctypes.Structure):
    _fields_ = [
        ("p",           ctypes.c_uint64),
        ("rk0",         ctypes.c_uint64),
        ("rk1",         ctypes.c_uint64),
        ("d",           ctypes.c_uint64),
        ("d_inv",       ctypes.c_uint64),
        ("use_feistel", ctypes.c_int),
    ]


# ── Vérification de layout struct (chargement du module) ──────────────
#
# Un décalage de champ entre CagouleMatrixC/CagouleSBox64C (ci-dessus) et
# les structs C réelles (cagoule_matrix.h::CagouleMatrix,
# cagoule_sbox.h::CagouleSBox64) ne provoquerait PAS forcément un crash --
# ctypes lirait/écrirait simplement au mauvais offset, produisant des
# clés de round, un k_mersenne, ou un flag use_feistel silencieusement
# corrompus. C'est exactement la classe de bug la plus dangereuse à
# avoir dans une bibliothèque cryptographique : pas de crash, juste un
# mauvais résultat. D'où la vérification au chargement du module, avec
# échec bruyant (RuntimeError), plutôt qu'un test optionnel qu'on
# pourrait oublier de lancer.
#
# Les valeurs attendues ci-dessous ont été obtenues en introspectant
# directement les structs C réelles (offsetof/sizeof, gcc 13.3.0,
# x86-64, -march=native) -- pas recalculées à la main. Elles sont
# spécifiques à ce layout fixe (CAGOULE_N=16, cible x86-64 Linux/GCC
# documentée) ; un changement légitime des structs C (nouveau champ,
# réordonnancement) nécessite de mettre à jour ces constantes ET les
# _fields_ ci-dessus ensemble -- le but de ce garde-fou est de détecter
# les cas où l'un des deux a été modifié sans l'autre.
_EXPECTED_MATRIX_LAYOUT = {
    "_sizeof_": 8216,
    "fwd":         0,
    "inv":         2048,
    "p":           4096,
    "kind":        4104,
    "fwd_avx2":    4112,
    "inv_avx2":    6160,
    "k_mersenne":  8208,
}

_EXPECTED_SBOX_LAYOUT = {
    "_sizeof_": 48,
    "p":           0,
    "rk0":         8,
    "rk1":         16,
    "d":           24,
    "d_inv":       32,
    "use_feistel": 40,
}


def _verify_struct_layout(struct_cls: type, expected: dict) -> list[str]:
    """Compare la taille et les offsets de champ d'une ctypes.Structure
    contre des valeurs attendues. Retourne la liste des erreurs trouvées
    (liste vide = tout correspond). Ne lève jamais -- l'appelant décide
    quoi faire d'une liste non vide (voir l'appel plus bas, qui lève)."""
    errors = []
    actual_size = ctypes.sizeof(struct_cls)
    expected_size = expected["_sizeof_"]
    if actual_size != expected_size:
        errors.append(
            f"{struct_cls.__name__}: sizeof mismatch -- Python computes "
            f"{actual_size} bytes, expected {expected_size} bytes")
    for field_name, expected_offset in expected.items():
        if field_name == "_sizeof_":
            continue
        try:
            actual_offset = getattr(struct_cls, field_name).offset
        except AttributeError:
            errors.append(f"{struct_cls.__name__}: field '{field_name}' not found in _fields_")
            continue
        if actual_offset != expected_offset:
            errors.append(
                f"{struct_cls.__name__}.{field_name}: offset mismatch -- "
                f"Python computes {actual_offset}, expected {expected_offset}")
    return errors


def _check_struct_layouts_or_raise() -> None:
    """Appelé une fois au chargement du module. Lève RuntimeError avec un
    message actionnable si CagouleMatrixC ou CagouleSBox64C ne
    correspond plus au layout C réel -- une continuation silencieuse
    ici serait strictement pire qu'un échec bruyant à l'import."""
    all_errors = (
        _verify_struct_layout(CagouleMatrixC, _EXPECTED_MATRIX_LAYOUT)
        + _verify_struct_layout(CagouleSBox64C, _EXPECTED_SBOX_LAYOUT)
    )
    if all_errors:
        raise RuntimeError(
            "cagoule: ctypes struct layout does not match the expected C "
            "struct layout -- refusing to load, since continuing could "
            "silently corrupt cryptographic parameters (round keys, "
            "k_mersenne, use_feistel) rather than crash visibly.\n"
            + "\n".join(f"  - {e}" for e in all_errors)
            + "\nIf this is a legitimate C struct change, update "
              "_EXPECTED_MATRIX_LAYOUT / _EXPECTED_SBOX_LAYOUT in "
              "_binding.py to match (see the comment above them for how "
              "the expected values were derived)."
        )


_check_struct_layouts_or_raise()


# ── Signatures ctypes ─────────────────────────────────────────────────

# Flags de disponibilité des API
_HAS_AVX2_API    = False
_HAS_SCALAR_API  = False
_HAS_SBOX_AVX2_API = False
_HAS_CTR_API     = False   # v3.0.0

if CAGOULE_C_AVAILABLE and _lib is not None:

    # Matrix
    _lib.cagoule_matrix_build.argtypes = [
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.c_uint64]
    _lib.cagoule_matrix_build.restype = ctypes.POINTER(CagouleMatrixC)

    _lib.cagoule_matrix_free.argtypes = [ctypes.POINTER(CagouleMatrixC)]
    _lib.cagoule_matrix_free.restype  = None

    _lib.cagoule_matrix_mul.argtypes = [
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64)]
    _lib.cagoule_matrix_mul.restype = None

    _lib.cagoule_matrix_mul_inv.argtypes = [
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64)]
    _lib.cagoule_matrix_mul_inv.restype = None

    _lib.cagoule_matrix_verify.argtypes = [ctypes.POINTER(CagouleMatrixC)]
    _lib.cagoule_matrix_verify.restype  = ctypes.c_int

    # ── v2.2.0: AVX2 backend detection ─────────────────────────────
    try:
        _lib.cagoule_matrix_backend_is_avx2.argtypes = []
        _lib.cagoule_matrix_backend_is_avx2.restype = ctypes.c_int
        _HAS_AVX2_API = True
    except AttributeError:
        pass

    # ── v2.2.0: Scalar explicit path (for parity tests) ────────────
    try:
        _lib.cagoule_matrix_mul_scalar.argtypes = [
            ctypes.POINTER(CagouleMatrixC),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64)]
        _lib.cagoule_matrix_mul_scalar.restype = None

        _lib.cagoule_matrix_mul_inv_scalar.argtypes = [
            ctypes.POINTER(CagouleMatrixC),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64)]
        _lib.cagoule_matrix_mul_inv_scalar.restype = None
        _HAS_SCALAR_API = True
    except AttributeError:
        pass

    # S-Box
    _lib.cagoule_sbox_init.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64]
    _lib.cagoule_sbox_init.restype = None

    _lib.cagoule_sbox_forward.argtypes = [
        ctypes.POINTER(CagouleSBox64C), ctypes.c_uint64]
    _lib.cagoule_sbox_forward.restype  = ctypes.c_uint64

    _lib.cagoule_sbox_inverse.argtypes = [
        ctypes.POINTER(CagouleSBox64C), ctypes.c_uint64]
    _lib.cagoule_sbox_inverse.restype  = ctypes.c_uint64

    _lib.cagoule_sbox_block_forward.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_size_t]
    _lib.cagoule_sbox_block_forward.restype = None

    _lib.cagoule_sbox_block_inverse.argtypes = [
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_size_t]
    _lib.cagoule_sbox_block_inverse.restype = None

    # ── v2.3.0: S-box AVX2 backend detection ───────────────────────
    try:
        _lib.cagoule_sbox_backend_is_avx2.argtypes = []
        _lib.cagoule_sbox_backend_is_avx2.restype = ctypes.c_int
        _HAS_SBOX_AVX2_API = True
    except AttributeError:
        pass

    # CBC Pipeline
    _cbc_argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
        ctypes.POINTER(CagouleMatrixC),
        ctypes.POINTER(CagouleSBox64C),
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
        ctypes.c_uint64,
        # v2.5.0 : z_offset[16] uint64 + num_zo
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,
    ]
    _lib.cagoule_cbc_encrypt.argtypes = _cbc_argtypes
    _lib.cagoule_cbc_encrypt.restype  = ctypes.c_int

    _lib.cagoule_cbc_decrypt.argtypes = _cbc_argtypes
    _lib.cagoule_cbc_decrypt.restype  = ctypes.c_int

    # ── v3.0.0: CTR Mode ───────────────────────────────────────────
    try:
        _ctr_argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # pt/ct, len
            ctypes.POINTER(ctypes.c_uint8),                    # iv (8 bytes)
            ctypes.POINTER(CagouleMatrixC),                    # mat
            ctypes.POINTER(CagouleSBox64C),                    # sbox
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,  # rk, nk
            ctypes.c_uint64,                                    # p
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,  # z_offset, num_zo
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,   # out, out_size
        ]
        _lib.cagoule_ctr_encrypt.argtypes = _ctr_argtypes
        _lib.cagoule_ctr_encrypt.restype = ctypes.c_int

        _lib.cagoule_ctr_decrypt.argtypes = _ctr_argtypes
        _lib.cagoule_ctr_decrypt.restype = ctypes.c_int

        _lib.cagoule_ctr_encrypt_4x.argtypes = _ctr_argtypes
        _lib.cagoule_ctr_encrypt_4x.restype = ctypes.c_int

        # cagoule_ctr_keystream
        _lib.cagoule_ctr_keystream.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),                    # iv
            ctypes.c_size_t,                                    # start_bi
            ctypes.POINTER(CagouleMatrixC),                    # mat
            ctypes.POINTER(CagouleSBox64C),                    # sbox
            ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t,  # rk, nk
            ctypes.c_uint64,                                    # p
            ctypes.POINTER(ctypes.c_uint8),                    # out
            ctypes.c_size_t,                                    # n_blocks
        ]
        _lib.cagoule_ctr_keystream.restype = ctypes.c_int

        _HAS_CTR_API = True
    except AttributeError:
        pass

    # cagoule_api_strerror : indépendant de l'API CTR ci-dessus -- son
    # propre try/except pour ne pas dépendre de _HAS_CTR_API, et pour
    # rester résilient si une .so plus ancienne ne l'expose pas encore.
    try:
        _lib.cagoule_api_strerror.argtypes = [ctypes.c_int]
        _lib.cagoule_api_strerror.restype = ctypes.c_char_p
        _HAS_API_STRERROR = True
    except AttributeError:
        _HAS_API_STRERROR = False

    # cagoule_encrypt_v3 / cagoule_decrypt_v3 (cagoule_api.c, API C unifiée
    # mono-message) -- ajoutés uniquement pour le KAT cross-langage
    # (voir test_cross_language_kat.py). Le pipeline Python de production
    # (cipher_ctr.py) N'appelle PAS ces fonctions -- ceci est une
    # infrastructure de TEST, pas un chemin de production. Signature
    # (const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*)
    # -- même convention que _ctr_argtypes ci-dessus (POINTER(c_uint8) +
    # taille explicite pour les buffers d'entrée, pas c_char_p, pour
    # rester cohérent avec le reste de ce fichier).
    try:
        _v3_argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # password, pwd_len
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # pt/ct, pt_len/ct_len
            ctypes.POINTER(ctypes.c_uint8),                    # out
            ctypes.POINTER(ctypes.c_size_t),                   # out_len (in/out)
        ]
        _lib.cagoule_encrypt_v3.argtypes = _v3_argtypes
        _lib.cagoule_encrypt_v3.restype = ctypes.c_int
        _lib.cagoule_decrypt_v3.argtypes = _v3_argtypes
        _lib.cagoule_decrypt_v3.restype = ctypes.c_int
        _HAS_API_V3 = True
    except AttributeError:
        _HAS_API_V3 = False

    # cagoule_stream_* (cagoule_stream.c, API de chiffrement en flux,
    # v3.1.0 Feature 4) -- v3.1.0 release audit, tâche 2. CagouleStreamCtx*
    # est un handle opaque côté C ; ctypes.c_void_p suffit, aucune
    # structure ctypes miroir n'est nécessaire (on ne déréférence jamais
    # ses champs depuis Python).
    try:
        _lib.cagoule_stream_init.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # password, pwd_len
            ctypes.c_size_t,                                   # chunk_size
            ctypes.c_int,                                      # allow_experimental
        ]
        _lib.cagoule_stream_init.restype = ctypes.c_void_p

        _lib.cagoule_stream_init_from_salt.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # password, pwd_len
            ctypes.POINTER(ctypes.c_uint8),                    # session_salt
            ctypes.c_size_t,                                   # chunk_size
            ctypes.c_int,                                      # allow_experimental
        ]
        _lib.cagoule_stream_init_from_salt.restype = ctypes.c_void_p

        _lib.cagoule_stream_update_out_len.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _lib.cagoule_stream_update_out_len.restype = ctypes.c_size_t

        _lib.cagoule_stream_decrypt_out_len.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _lib.cagoule_stream_decrypt_out_len.restype = ctypes.c_size_t

        _lib.cagoule_stream_update.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,   # input, input_len
            ctypes.POINTER(ctypes.c_uint8),                     # out
            ctypes.POINTER(ctypes.c_size_t),                    # out_len (in/out)
        ]
        _lib.cagoule_stream_update.restype = ctypes.c_int

        _lib.cagoule_stream_decrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,   # ct_chunk, ct_chunk_len
            ctypes.POINTER(ctypes.c_uint8),                     # out
            ctypes.POINTER(ctypes.c_size_t),                    # out_len (in/out)
        ]
        _lib.cagoule_stream_decrypt.restype = ctypes.c_int

        _lib.cagoule_stream_free.argtypes = [ctypes.c_void_p]
        _lib.cagoule_stream_free.restype = None

        # const uint8_t* -- CAGOULE_STREAM_SESSION_SALT_SIZE (32) octets,
        # propriété du ctx (pas de free() séparé). restype c_void_p (pas
        # POINTER(c_uint8)) pour pouvoir tester NULL proprement puis
        # relire via ctypes.cast -- un POINTER(c_uint8) NULL lève une
        # ValueError surprenante dès qu'on tente arr[i] dessus.
        _lib.cagoule_stream_session_salt.argtypes = [ctypes.c_void_p]
        _lib.cagoule_stream_session_salt.restype = ctypes.c_void_p

        _HAS_STREAM_API = True
    except AttributeError:
        _HAS_STREAM_API = False

    # Détection NEON -- v3.1.0 release audit, tâche 3.
    # cagoule_matrix_backend_is_neon() : symbole présent UNIQUEMENT dans
    # les builds aarch64 (cagoule_matrix_neon.c n'est ajouté à SRCS que
    # sous `ifeq ($(shell uname -m),aarch64)` -- voir Makefile). Absent
    # (AttributeError) sur x86_64 par construction -- pas une erreur.
    try:
        _lib.cagoule_matrix_backend_is_neon.argtypes = []
        _lib.cagoule_matrix_backend_is_neon.restype = ctypes.c_int
        _HAS_MATRIX_NEON_API = True
    except AttributeError:
        _HAS_MATRIX_NEON_API = False

    # cagoule_sbox_backend_is_neon() : présent sur TOUTES les plateformes
    # (défini sans garde #if dans cagoule_sbox_avx2.c) mais retourne
    # TOUJOURS 0 -- aucune implémentation NEON du S-box n'existe. Ne PAS
    # interpréter un retour futur de 1 comme fiable sans vérifier que
    # cagoule_sbox_avx2.c a réellement été modifié en conséquence.
    try:
        _lib.cagoule_sbox_backend_is_neon.argtypes = []
        _lib.cagoule_sbox_backend_is_neon.restype = ctypes.c_int
        _HAS_SBOX_NEON_API = True
    except AttributeError:
        _HAS_SBOX_NEON_API = False
else:
    _HAS_API_STRERROR = False
    _HAS_API_V3 = False
    _HAS_STREAM_API = False
    _HAS_MATRIX_NEON_API = False
    _HAS_SBOX_NEON_API = False

CAGOULE_STREAM_SESSION_SALT_SIZE = 32  # doit rester en phase avec cagoule_stream.h


# ── Utilitaires ───────────────────────────────────────────────────────

def cagoule_api_strerror(code: int) -> str:
    """
    Traduit un code de retour cagoule_api.h (CAGOULE_API_OK ou l'un des
    CAGOULE_API_ERR_*) en message d'erreur humainement lisible.

    Fonctionne même si le backend C n'est pas disponible (retourne un
    message générique plutôt que de lever une exception) -- cette
    fonction est un utilitaire de confort pour l'affichage, pas un
    chemin critique dont l'échec devrait bloquer autre chose.

    >>> cagoule_api_strerror(0)
    'success'
    >>> cagoule_api_strerror(-3)
    'authentication failed (wrong password, or ciphertext was corrupted or tampered with)'
    """
    if not _HAS_API_STRERROR:
        return f"error code {code} (human-readable messages unavailable: C backend missing cagoule_api_strerror)"
    raw = _lib.cagoule_api_strerror(ctypes.c_int(code))
    if raw is None:
        return f"error code {code} (no message returned)"
    return raw.decode("utf-8", errors="replace")


CAGOULE_API_OVERHEAD_AEAD = 65  # MAGIC(4)+VERSION(1)+SALT(32)+NONCE(12)+TAG(16)
# CORRECTIF : cagoule_api_encrypt_out_len()/decrypt_out_len() (cagoule_api.h)
# sont `static inline` en C -- jamais exportées comme symboles liables,
# donc jamais appelables via ctypes. La formule (juste une addition/
# soustraction) est reproduite ici directement plutôt que de tenter un
# ctypes.CDLL(...).cagoule_api_encrypt_out_len qui échouerait toujours
# avec AttributeError.


def c_encrypt_v3(password: bytes, plaintext: bytes) -> bytes:
    """Appelle cagoule_encrypt_v3 (cagoule_api.c) via ctypes.

    Infrastructure de TEST (KAT cross-langage) -- le pipeline Python de
    production (cipher_ctr.py::encrypt_ctr) n'utilise PAS cette fonction.
    Lève RuntimeError si le backend C ne l'expose pas, ou si l'appel
    échoue (avec le message cagoule_api_strerror() si disponible)."""
    if not _HAS_API_V3:
        raise RuntimeError("cagoule_encrypt_v3 not available in this libcagoule.so build")
    pw_buf = bytes_to_c_uint8(password)
    pt_buf = bytes_to_c_uint8(plaintext)
    out_len_val = len(plaintext) + CAGOULE_API_OVERHEAD_AEAD
    out_buf = (ctypes.c_uint8 * out_len_val)()
    out_len = ctypes.c_size_t(out_len_val)
    ret = _lib.cagoule_encrypt_v3(pw_buf, ctypes.c_size_t(len(password)),
                                   pt_buf, ctypes.c_size_t(len(plaintext)),
                                   out_buf, ctypes.byref(out_len))
    if ret != 0:
        msg = cagoule_api_strerror(ret)
        raise RuntimeError(f"cagoule_encrypt_v3 failed: {msg} (code {ret})")
    return c_uint8_to_bytes(out_buf, out_len.value)


def c_decrypt_v3(password: bytes, ciphertext: bytes) -> bytes:
    """Appelle cagoule_decrypt_v3 (cagoule_api.c) via ctypes.

    Infrastructure de TEST (KAT cross-langage) -- le pipeline Python de
    production (decipher_ctr.py::decrypt_ctr) n'utilise PAS cette fonction.
    Lève RuntimeError si le backend C ne l'expose pas, ou si l'appel
    échoue (mauvais mot de passe, ciphertext corrompu, etc. -- avec le
    message cagoule_api_strerror() si disponible)."""
    if not _HAS_API_V3:
        raise RuntimeError("cagoule_decrypt_v3 not available in this libcagoule.so build")
    pw_buf = bytes_to_c_uint8(password)
    ct_buf = bytes_to_c_uint8(ciphertext)
    out_len_val = max(len(ciphertext) - CAGOULE_API_OVERHEAD_AEAD, 0)
    out_buf = (ctypes.c_uint8 * max(out_len_val, 1))()
    out_len = ctypes.c_size_t(out_len_val)
    ret = _lib.cagoule_decrypt_v3(pw_buf, ctypes.c_size_t(len(password)),
                                   ct_buf, ctypes.c_size_t(len(ciphertext)),
                                   out_buf, ctypes.byref(out_len))
    if ret != 0:
        msg = cagoule_api_strerror(ret)
        raise RuntimeError(f"cagoule_decrypt_v3 failed: {msg} (code {ret})")
    return c_uint8_to_bytes(out_buf, out_len.value)


# ── Wrappers Python-friendly (v3.1.0 release audit, tâche 1) ───────────
#
# c_encrypt_v3()/c_decrypt_v3() ci-dessus retournent déjà bytes et lèvent
# déjà RuntimeError avec cagoule_api_strerror() -- ces wrappers existent
# uniquement pour satisfaire la forme d'API demandée (tuple (ciphertext,
# bytes_written), noms sans préfixe "c_" pour l'usage Python courant).
# Ils délèguent entièrement à c_encrypt_v3/c_decrypt_v3 -- pas de logique
# dupliquée, pas de second appel ctypes.
#
# Rappel (voir docstring de c_encrypt_v3 ci-dessus) : infrastructure de
# TEST/KAT cross-langage. Le pipeline Python de production
# (cipher_ctr.py::encrypt_ctr) n'utilise PAS ces fonctions.

def encrypt_v3(password: bytes, plaintext: bytes) -> tuple[bytes, int]:
    """
    Wrapper Python-friendly autour de cagoule_encrypt_v3 (cagoule_api.c).

    Args:
        password:  mot de passe, bytes
        plaintext: message en clair, bytes

    Returns:
        (ciphertext, bytes_written) -- bytes_written == len(ciphertext),
        conservé séparément car c'est la valeur out_len effectivement
        rapportée par le C (utile pour vérifier la cohérence du buffer
        sans recalculer CAGOULE_API_OVERHEAD_AEAD côté appelant).

    Raises:
        RuntimeError: si le backend C n'expose pas cagoule_encrypt_v3,
                      ou si l'appel échoue (message via cagoule_api_strerror).
    """
    ciphertext = c_encrypt_v3(password, plaintext)
    return ciphertext, len(ciphertext)


def decrypt_v3(password: bytes, ciphertext: bytes) -> tuple[bytes, int]:
    """
    Wrapper Python-friendly autour de cagoule_decrypt_v3 (cagoule_api.c).

    Args:
        password:   mot de passe, bytes
        ciphertext: ciphertext produit par encrypt_v3 (ou cagoule_encrypt_v3
                    C, ou encrypt_ctr() Python -- format v0x02 identique)

    Returns:
        (plaintext, bytes_written)

    Raises:
        RuntimeError: si le backend C n'expose pas cagoule_decrypt_v3,
                      ou si l'authentification échoue (mauvais mot de
                      passe, ciphertext corrompu/altéré), ou si le format
                      est invalide -- message via cagoule_api_strerror.
    """
    plaintext = c_decrypt_v3(password, ciphertext)
    return plaintext, len(plaintext)


def list_to_uint64_array(lst: List[int]) -> ctypes.Array:
    return (ctypes.c_uint64 * len(lst))(*lst)


def uint64_array_to_list(arr: ctypes.Array, n: int) -> List[int]:
    return [int(arr[i]) for i in range(n)]


def bytes_to_c_uint8(data: bytes) -> ctypes.Array:
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def c_uint8_to_bytes(arr: ctypes.Array, n: int) -> bytes:
    return bytes(arr[:n])


def cagoule_p_bytes(p: int) -> int:
    """Nombre d'octets pour un élément de Z/pZ."""
    return 8 if p > 0xFFFFFFFF else 4


def free_matrix(matrix_ptr) -> None:
    if CAGOULE_C_AVAILABLE and _lib and matrix_ptr:
        _lib.cagoule_matrix_free(matrix_ptr)


# ── Backend Info ──────────────────────────────────────────────────────

def get_backend_info() -> Dict[str, str]:
    """Retourne les informations sur les backends actifs (v2.2.0, conservé pour compatibilité).

    Returns:
        dict avec les clés :
        - 'matrix_backend' : 'avx2', 'scalar', ou 'python'
        - 'omega_backend'  : 'C' ou 'python' (rempli par omega.py)
    """
    info = {
        "matrix_backend": "python",
        "omega_backend": "unknown",
    }

    if CAGOULE_C_AVAILABLE and _lib is not None:
        # Détection AVX2 pour la matrice
        try:
            if _HAS_AVX2_API and _lib.cagoule_matrix_backend_is_avx2():
                info["matrix_backend"] = "avx2"
            else:
                info["matrix_backend"] = "scalar"
        except Exception:
            info["matrix_backend"] = "scalar"

        # Backend omega (C par défaut si libcagoule.so est chargé)
        info["omega_backend"] = "C"
    else:
        info["omega_backend"] = "python"

    return info


def get_backend_info_v230() -> Dict[str, str]:
    """Retourne les informations complètes sur les backends actifs (v2.3.0).

    Returns:
        dict avec les clés :
        - 'matrix_backend' : 'avx2', 'scalar', ou 'python'
        - 'sbox_backend'   : 'avx2', 'scalar', ou 'python'   ← nouveau v2.3.0
        - 'omega_backend'  : 'C' ou 'python'
    """
    info = get_backend_info()   # hérite v2.2.0 (matrix_backend, omega_backend)

    if CAGOULE_C_AVAILABLE and _lib is not None:
        try:
            if _HAS_SBOX_AVX2_API and _lib.cagoule_sbox_backend_is_avx2():
                info["sbox_backend"] = "avx2"
            else:
                info["sbox_backend"] = "scalar"
        except Exception:
            info["sbox_backend"] = "scalar"
    else:
        info["sbox_backend"] = "python"

    return info


def get_backend_info_v300() -> Dict[str, str]:
    """Retourne les informations complètes sur les backends actifs (v3.0.0).

    Returns:
        dict avec les clés :
        - 'matrix_backend' : 'avx2', 'scalar', ou 'python'
        - 'sbox_backend'   : 'avx2', 'scalar', ou 'python'
        - 'omega_backend'  : 'C' ou 'python'
        - 'ctr_backend'    : 'C' ou 'python'                 ← nouveau v3.0.0
        - 'ctr_4x_available' : True/False                    ← nouveau v3.0.0
    """
    info = get_backend_info_v230()  # hérite v2.3.0

    if CAGOULE_C_AVAILABLE and _lib is not None:
        info["ctr_backend"] = "C" if _HAS_CTR_API else "scalar"
        info["ctr_4x_available"] = _HAS_CTR_API
    else:
        info["ctr_backend"] = "python"
        info["ctr_4x_available"] = False

    return info


def get_backend_info_v310() -> Dict[str, object]:
    """Retourne les informations complètes sur les backends actifs (v3.1.0).

    Returns:
        dict avec les clés :
        - 'matrix_backend' : 'neon', 'avx2', 'scalar', ou 'python'  ← 'neon' nouveau v3.1.0
        - 'sbox_backend'   : 'avx2', 'scalar', ou 'python'
                             NE retournera JAMAIS 'neon' -- aucune implémentation
                             NEON du S-box n'existe dans cette base de code
                             (voir cagoule_sbox_avx2.c::cagoule_sbox_backend_is_neon).
        - 'omega_backend'  : 'C' ou 'python'
        - 'ctr_backend'    : 'C' ou 'python'
        - 'ctr_4x_available' : True/False
        - 'neon_backend'   : True/False                      ← nouveau v3.1.0
                             reflète UNIQUEMENT le backend matrice (le seul
                             backend NEON réel). Redondant avec
                             matrix_backend == 'neon', exposé séparément
                             car c'est le champ que demande le binding
                             attendu par cagoule-bench (avx2_suite.py).

    Priorité matrix_backend : neon > avx2 > scalar > python. Sur x86_64,
    cagoule_matrix_backend_is_neon n'existe même pas dans le .so (voir
    Makefile) -- _HAS_MATRIX_NEON_API est False et ce chemin est ignoré
    sans jamais tenter l'appel (qui lèverait AttributeError sinon).
    """
    info = get_backend_info_v300()  # hérite v3.0.0 (ctr_backend, ctr_4x_available, etc.)

    is_neon = False
    if CAGOULE_C_AVAILABLE and _lib is not None:
        try:
            if _HAS_MATRIX_NEON_API and _lib.cagoule_matrix_backend_is_neon():
                is_neon = True
        except Exception:
            is_neon = False

    if is_neon:
        info["matrix_backend"] = "neon"
    # sinon : conserver la valeur avx2/scalar/python déjà posée par
    # get_backend_info() -- ne jamais écraser avec 'scalar' ici, ça
    # effacerait un 'avx2' correct sur x86_64.

    info["neon_backend"] = is_neon

    return info