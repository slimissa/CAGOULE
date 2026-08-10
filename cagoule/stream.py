"""
cagoule/stream.py — Wrapper Python pour l'API de chiffrement en flux
CAGOULE v3.1.0 (cagoule_stream.c, Feature 4).

v3.1.0 release audit, tâche 2 : avant ce fichier, l'API C de streaming
n'avait AUCUN binding Python -- seul test_stream.c (C) l'exerçait.
cagoule-bench's streaming_suite.py simulait le "streaming" en découpant
le plaintext côté Python et en appelant encrypt_ctr()/encrypt() par
chunk -- ça n'exerçait jamais le vrai chemin C ci-dessous (MAC
indépendant par chunk, AAD lié à la session). Ce fichier ferme cet
écart.

⚠️  C-API only pour v3.1.0 (roadmap §4) : il n'y a PAS de VERSION byte
CGL1 dédié pour le format streaming. Le wire format par chunk est
documenté dans cagoule_stream.h -- l'appelant (Python ou autre) est
responsable du framing/persistance entre chunks (writer les chunks
ciphertext dans l'ordre, un par un, côté disque/réseau).

Usage :
    from cagoule import CagouleStreamCtx

    with CagouleStreamCtx(b"password") as enc:
        ct1 = enc.update(b"first chunk of plaintext")
        ct2 = enc.update(b"second chunk")
        salt = enc.session_salt   # à transmettre au déchiffreur hors bande

    with CagouleStreamCtx.from_salt(b"password", salt) as dec:
        pt1 = dec.decrypt(ct1)
        pt2 = dec.decrypt(ct2)

Mode expérimental (0x03, Poly1305 seul) : passer allow_experimental=True
ET définir CAGOULE_EXPERIMENTAL_NO_AEAD=1 dans l'environnement -- comme
cipher_ctr_raw.py. DIFFÉRENCE IMPORTANTE avec cipher_ctr_raw.py : le C
(cagoule_stream.c) ne lève PAS d'erreur si allow_experimental=True sans
la variable d'environnement -- il retombe SILENCIEUSEMENT en mode sûr
AEAD 0x02 à la place (choix délibéré, voir cagoule_api.h/cagoule_stream.h
pour le détail de l'audit qui a validé ce comportement). Ce wrapper ne
réplique PAS le hard-fail Python de cipher_ctr_raw.py::_check_experimental_gate
-- ajouter une politique de sécurité qui n'existe pas côté C serait sortir
du périmètre "bindings et détection uniquement" de cette tâche. Si un
hard-fail Python est souhaité pour le streaming, c'est un changement de
comportement à traiter (et auditer) séparément, pas un simple binding.
"""

from __future__ import annotations

import ctypes
from typing import Optional

from ._binding import (
    _lib,
    CAGOULE_C_AVAILABLE,
    cagoule_api_strerror,
    bytes_to_c_uint8,
)

# Import paresseux du flag de disponibilité -- _binding.py le définit
# uniquement dans la branche `if CAGOULE_C_AVAILABLE:` ; absent (pas
# juste False) si le backend C n'est pas chargé du tout.
try:
    from ._binding import _HAS_STREAM_API
except ImportError:
    _HAS_STREAM_API = False

try:
    from ._binding import CAGOULE_STREAM_SESSION_SALT_SIZE
except ImportError:
    CAGOULE_STREAM_SESSION_SALT_SIZE = 32


def cagoule_stream_strerror(code: int) -> str:
    """
    Traduit un code CAGOULE_STREAM_ERR_* en message lisible.

    Il n'existe pas de cagoule_stream_strerror() côté C -- cagoule_stream.h
    ne définit que les macros d'erreur, sans fonction de traduction dédiée.
    Vérifié : CAGOULE_STREAM_ERR_* (cagoule_stream.h) et CAGOULE_API_ERR_*
    (cagoule_api.h) partagent EXACTEMENT les mêmes valeurs numériques pour
    NULL(-1)/SIZE(-2)/AUTH(-3)/FORMAT(-4)/KDF(-5)/CRYPTO(-6)/ALLOC(-7).
    Seul CAGOULE_API_ERR_EXPERIMENTAL_DISABLED(-8) n'a pas d'équivalent
    stream (le code -8 stream, CAGOULE_STREAM_ERR_GATE, a été retiré et
    n'est plus jamais retourné -- voir cagoule_stream.h). Réutiliser
    cagoule_api_strerror() est donc correct pour tout code que
    cagoule_stream_* peut réellement renvoyer.
    """
    return cagoule_api_strerror(code)


class CagouleStreamCtx:
    """
    Contexte de chiffrement/déchiffrement en flux CAGOULE (cagoule_stream.c).

    Un même objet ne fait QUE chiffrer OU QUE déchiffrer -- déterminé à la
    construction (CagouleStreamCtx() chiffre, CagouleStreamCtx.from_salt()
    déchiffre), comme le C sous-jacent (le compteur de chunk interne avance
    dans un seul sens par contexte). Utiliser deux instances séparées pour
    un round-trip, exactement comme test_stream.c.

    Support context manager (with ... as ctx) : libère le contexte C
    automatiquement (cagoule_stream_free) à la sortie du bloc, y compris
    en cas d'exception.
    """

    __slots__ = ("_ctx", "_closed")

    def __init__(self, password: bytes, chunk_size: int = 0,
                 allow_experimental: bool = False):
        """
        Initialise un contexte de CHIFFREMENT (cagoule_stream_init).

        Args:
            password:           mot de passe, bytes
            chunk_size:          taille de chunk en octets (0 -> défaut
                                  64KB, CAGOULE_STREAM_DEFAULT_CHUNK_SIZE)
            allow_experimental:  voir docstring du module -- ne garantit
                                  PAS le mode 0x03 seul (double gate C).

        Raises:
            RuntimeError: backend C indisponible, ou cagoule_stream_init
                          a retourné NULL (mot de passe/paramètres invalides,
                          ou échec Argon2id).
        """
        self._closed = True  # pour que __del__ soit sûr même si __init__ échoue avant la fin
        if not (CAGOULE_C_AVAILABLE and _HAS_STREAM_API):
            raise RuntimeError(
                "cagoule_stream_* not available in this libcagoule.so build "
                "(streaming is a C-API-only v3.1.0 feature -- see cagoule/stream.py)"
            )
        # bytes_to_c_uint8(b"") produit un tableau de taille 0 -> pointeur
        # non-NULL valide (cohérent avec c_encrypt_v3/c_decrypt_v3
        # ci-dessus dans _binding.py) -- PAS de conditionnel "if password
        # else None" ici : ça transformerait un mot de passe vide valide
        # en un vrai pointeur NULL, que cagoule_stream_init rejette avec
        # CAGOULE_STREAM_ERR_NULL (voir test_init_free : NULL+0 → NULL).
        pw_buf = bytes_to_c_uint8(password)
        ctx = _lib.cagoule_stream_init(
            pw_buf, ctypes.c_size_t(len(password)),
            ctypes.c_size_t(chunk_size),
            ctypes.c_int(1 if allow_experimental else 0),
        )
        if not ctx:
            raise RuntimeError(
                "cagoule_stream_init failed (NULL password/context, or KDF failure)"
            )
        self._ctx = ctx
        self._closed = False

    @classmethod
    def from_salt(cls, password: bytes, session_salt: bytes, chunk_size: int = 0,
                  allow_experimental: bool = False) -> "CagouleStreamCtx":
        """
        Initialise un contexte de DÉCHIFFREMENT (cagoule_stream_init_from_salt).

        Args:
            session_salt: exactement CAGOULE_STREAM_SESSION_SALT_SIZE (32)
                          octets, reçus hors bande (typiquement via
                          ctx_encrypt.session_salt transmis au préalable).
            allow_experimental: DOIT correspondre au mode utilisé lors du
                          chiffrement (voir cagoule_stream.h).

        Raises:
            ValueError: session_salt n'a pas la bonne taille.
            RuntimeError: backend C indisponible, ou init a échoué.
        """
        if not (CAGOULE_C_AVAILABLE and _HAS_STREAM_API):
            raise RuntimeError(
                "cagoule_stream_* not available in this libcagoule.so build"
            )
        if len(session_salt) != CAGOULE_STREAM_SESSION_SALT_SIZE:
            raise ValueError(
                f"session_salt must be exactly {CAGOULE_STREAM_SESSION_SALT_SIZE} "
                f"bytes, got {len(session_salt)}"
            )
        self = cls.__new__(cls)
        self._closed = True
        pw_buf = bytes_to_c_uint8(password)
        salt_buf = bytes_to_c_uint8(session_salt)
        ctx = _lib.cagoule_stream_init_from_salt(
            pw_buf, ctypes.c_size_t(len(password)),
            salt_buf,
            ctypes.c_size_t(chunk_size),
            ctypes.c_int(1 if allow_experimental else 0),
        )
        if not ctx:
            raise RuntimeError(
                "cagoule_stream_init_from_salt failed (NULL password/salt, or KDF failure)"
            )
        self._ctx = ctx
        self._closed = False
        return self

    # ── Context manager ─────────────────────────────────────────────

    def __enter__(self) -> "CagouleStreamCtx":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self):
        # Filet de sécurité si close()/__exit__ n'a jamais été appelé --
        # ne doit jamais lever (appelé pendant le GC, potentiellement
        # tard/dans un ordre imprévisible).
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        """Libère le contexte C (cagoule_stream_free) -- idempotent."""
        if not self._closed and getattr(self, "_ctx", None):
            _lib.cagoule_stream_free(self._ctx)
            self._ctx = None
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("CagouleStreamCtx is closed (already freed)")

    # ── Chiffrement ──────────────────────────────────────────────────

    def update(self, plaintext: bytes) -> bytes:
        """
        Chiffre un chunk (cagoule_stream_update). Incrémente le compteur
        de chunk interne -- appeler N fois pour N chunks consécutifs, dans
        l'ordre.

        Le buffer de sortie est dimensionné automatiquement via
        cagoule_stream_update_out_len(ctx, len(plaintext)) -- l'appelant
        n'a jamais à calculer l'overhead lui-même.

        Raises:
            RuntimeError: contexte fermé, ou échec C (message via
                          cagoule_stream_strerror).
        """
        self._check_open()
        # Idem : pas de "if plaintext else None" -- un chunk vide (len 0)
        # doit rester un pointeur valide vers 0 octet, pas NULL.
        pt_buf = bytes_to_c_uint8(plaintext)
        out_cap = _lib.cagoule_stream_update_out_len(self._ctx, ctypes.c_size_t(len(plaintext)))
        out_buf = (ctypes.c_uint8 * max(out_cap, 1))()
        out_len = ctypes.c_size_t(out_cap)
        ret = _lib.cagoule_stream_update(
            self._ctx, pt_buf, ctypes.c_size_t(len(plaintext)),
            out_buf, ctypes.byref(out_len),
        )
        if ret != 0:
            raise RuntimeError(f"cagoule_stream_update failed: {cagoule_stream_strerror(ret)} (code {ret})")
        return bytes(out_buf[:out_len.value])

    # ── Déchiffrement ────────────────────────────────────────────────

    def decrypt(self, ciphertext_chunk: bytes) -> bytes:
        """
        Déchiffre un chunk (cagoule_stream_decrypt). Le TAG est vérifié
        AVANT toute écriture dans le buffer de sortie -- en cas d'échec
        d'authentification, aucun plaintext non vérifié n'est jamais
        exposé (garantie C, voir cagoule_stream.h).

        Raises:
            RuntimeError: contexte fermé, TAG invalide (mauvais mot de
                          passe, chunk altéré ou rejoué/réordonné), ou
                          autre échec C (message via cagoule_stream_strerror).
        """
        self._check_open()
        ct_buf = bytes_to_c_uint8(ciphertext_chunk)
        out_cap = _lib.cagoule_stream_decrypt_out_len(
            self._ctx, ctypes.c_size_t(len(ciphertext_chunk))
        )
        out_buf = (ctypes.c_uint8 * max(out_cap, 1))()
        out_len = ctypes.c_size_t(out_cap)
        ret = _lib.cagoule_stream_decrypt(
            self._ctx, ct_buf, ctypes.c_size_t(len(ciphertext_chunk)),
            out_buf, ctypes.byref(out_len),
        )
        if ret != 0:
            raise RuntimeError(f"cagoule_stream_decrypt failed: {cagoule_stream_strerror(ret)} (code {ret})")
        return bytes(out_buf[:out_len.value])

    # ── Métadonnées ──────────────────────────────────────────────────

    @property
    def session_salt(self) -> bytes:
        """
        Le session_salt (32 octets) de ce contexte -- à transmettre hors
        bande au déchiffreur pour CagouleStreamCtx.from_salt(). Propriété
        du contexte C (pas de free() séparé requis).
        """
        self._check_open()
        raw_ptr = _lib.cagoule_stream_session_salt(self._ctx)
        if not raw_ptr:
            raise RuntimeError("cagoule_stream_session_salt returned NULL")
        buf = (ctypes.c_uint8 * CAGOULE_STREAM_SESSION_SALT_SIZE).from_address(raw_ptr)
        return bytes(buf)
