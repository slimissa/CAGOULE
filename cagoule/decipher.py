"""
decipher.py — Déchiffrement CAGOULE v2.1.0

Corrections v2.1.0 :
  ┌──────────────────────────────────────────────────────────────────┐
  │  FIX test_mauvais_mdp                                            │
  │                                                                  │
  │  Symptôme v2.0 :                                                 │
  │    decrypt(ct, b"wrong_password", params=fast_params)            │
  │    → ne lève PAS CagouleAuthError car params.k_stream est       │
  │      utilisé directement, ignorant le mauvais mot de passe.     │
  │                                                                  │
  │  Cause :                                                         │
  │    Quand params= est fourni ET password est non-vide, v2.0      │
  │    bypasse la re-dérivation → k_stream "correct" → tag OK.      │
  │                                                                  │
  │  Fix v2.1.0 :                                                    │
  │    Si password non-vide, TOUJOURS re-dériver depuis             │
  │    (password, salt_du_ciphertext) avec params.fast_mode.         │
  │    Mauvais mdp → k_master différent → k_stream différent        │
  │    → ChaCha20-Poly1305 InvalidTag → CagouleAuthError ✅          │
  │                                                                  │
  │  Aucun breaking change pour l'API publique :                     │
  │    decrypt(ct, password)              → inchangé                 │
  │    decrypt(ct, password, params=P)   → re-dérive (fix)          │
  │    decrypt_with_params(ct, params)   → password=b'' → intact    │
  └──────────────────────────────────────────────────────────────────┘

  Enrichissement CagouleAuthError / CagouleFormatError :
    .reason, .hint, .ct_size, .backend pour diagnostic facilité.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .params import CagouleParams, BLOCK_SIZE_N
from .cipher import (
    MAGIC, VERSION, NONCE_SIZE,
    pkcs7_unpad,
    _build_aad, _parse_cgl1,
    _cbc_decrypt,
)
from ._binding import CAGOULE_C_AVAILABLE
from .logger import get_logger

_log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════
#  §1. Exceptions enrichies (v2.1.0)
# ══════════════════════════════════════════════════════════════════════════

class CagouleError(Exception):
    """Erreur de base CAGOULE. Toutes les exceptions héritent de cette classe."""


class CagouleAuthError(CagouleError):
    """
    Authentification ChaCha20-Poly1305 échouée.

    Causes possibles (par probabilité décroissante) :
      1. Mot de passe incorrect
      2. Ciphertext altéré ou tronqué (corruption réseau / disque)
      3. Message chiffré avec une version incompatible
      4. params= fournis issus d'un autre message

    Attributs v2.1.0 :
      .reason   : raison probable (str)
      .ct_size  : taille du ciphertext reçu (int, octets)
      .backend  : backend actif au moment de l'échec (str)
      .hint     : conseil de diagnostic (str)
    """
    def __init__(self, message: str, *,
                 reason: str  = "mot de passe incorrect ou ciphertext altéré",
                 ct_size: int = 0,
                 backend: str = "",
                 hint: str    = ""):
        super().__init__(message)
        self.reason  = reason
        self.ct_size = ct_size
        self.backend = backend or _backend_str()
        self.hint    = hint

    def __str__(self) -> str:
        lines = [super().__str__()]
        lines.append(f"  Raison probable   : {self.reason}")
        lines.append(f"  Taille ciphertext : {self.ct_size} octets")
        lines.append(f"  Backend           : {self.backend}")
        if self.hint:
            lines.append(f"  Conseil           : {self.hint}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (f"CagouleAuthError(reason={self.reason!r}, "
                f"ct_size={self.ct_size}, backend={self.backend!r})")


class CagouleFormatError(CagouleError):
    """
    Format CGL1 invalide.

    Attributs v2.1.0 :
      .field      : champ invalide ('magic', 'version', 'salt', 'nonce', 'tag')
      .data_size  : taille des données reçues
      .min_size   : taille minimale attendue
    """
    def __init__(self, message: str, *,
                 field: str     = "",
                 data_size: int = 0,
                 min_size: int  = 0):
        super().__init__(message)
        self.field     = field
        self.data_size = data_size
        self.min_size  = min_size

    def __str__(self) -> str:
        lines = [super().__str__()]
        if self.field:
            lines.append(f"  Champ invalide    : {self.field}")
        if self.data_size:
            lines.append(f"  Taille reçue      : {self.data_size} octets")
        if self.min_size:
            lines.append(f"  Taille minimale   : {self.min_size} octets")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
#  §2. Utilitaires internes
# ══════════════════════════════════════════════════════════════════════════

def _backend_str() -> str:
    return "C (libcagoule.so v2.1)" if CAGOULE_C_AVAILABLE else "Python pur (fallback)"


def _auth_error(ct_size: int, reason: str = "", hint: str = "") -> CagouleAuthError:
    """Construit un CagouleAuthError avec contexte diagnostique automatique."""
    if not reason:
        if ct_size < 65:
            reason = "ciphertext trop court — probablement tronqué"
            hint   = "Vérifiez que le ciphertext complet a bien été transmis."
        else:
            reason = "mot de passe incorrect ou ciphertext altéré"
            hint   = (
                "Si le mot de passe est correct, vérifiez l'intégrité du "
                "fichier (SHA-256). Ciphertext altéré même d'un seul octet "
                "invalide le tag Poly1305."
            )
    return CagouleAuthError(
        "Authentification ChaCha20-Poly1305 échouée — tag Poly1305 invalide.",
        reason=reason,
        ct_size=ct_size,
        hint=hint,
    )


def _detect_bad_field(data: bytes) -> str:
    """Identifie quel champ CGL1 est invalide."""
    if len(data) < 4:
        return f"magic (données de {len(data)} octets, minimum 4)"
    if data[0:4] != MAGIC:
        return f"magic (reçu {data[0:4]!r}, attendu b'CGL1')"
    if len(data) < 5:
        return "version (trop court)"
    if data[4:5] != VERSION:
        return f"version (reçu 0x{data[4]:02x}, attendu 0x01)"
    if len(data) < 37:
        return f"salt (reçu {len(data)-5} octets, attendu 32)"
    if len(data) < 49:
        return f"nonce (reçu {len(data)-37} octets, attendu 12)"
    if len(data) < 65:
        return f"tag (reçu {len(data)-49} octets, minimum 16)"
    return "inconnu"


# ══════════════════════════════════════════════════════════════════════════
#  §3. decrypt() — point d'entrée public avec fix test_mauvais_mdp
# ══════════════════════════════════════════════════════════════════════════

def decrypt(ciphertext: bytes, password: bytes | str,
            fast_mode: bool = False,
            params: CagouleParams | None = None) -> bytes:
    """
    Déchiffre un message CAGOULE v2.1.0 au format CGL1.

    Règle de dérivation des paramètres (v2.1.0) :
    ┌──────────────────────┬───────────────────────────────────────────┐
    │ password             │ params           │ Comportement           │
    ├──────────────────────┼──────────────────┼────────────────────────┤
    │ non-vide             │ None             │ Dérive depuis password │
    │ non-vide             │ fournis          │ RE-dérive (fix !)      │
    │ vide (b'')           │ fournis          │ Utilise params tel quel│
    │ vide (b'')           │ None             │ CagouleError           │
    └──────────────────────┴──────────────────┴────────────────────────┘

    Note : decrypt_with_params() passe password=b'' pour usage interne.

    Args:
        ciphertext : Message au format CGL1.
        password   : Mot de passe (bytes ou str).
        fast_mode  : KDF rapide (tests uniquement, ignoré si params= fourni).
        params     : Paramètres pré-dérivés. Voir tableau ci-dessus.

    Returns:
        Plaintext déchiffré (bytes).

    Raises:
        CagouleFormatError : Header CGL1 invalide.
        CagouleAuthError   : Tag Poly1305 invalide (mauvais mdp ou corruption).
        CagouleError       : Erreur interne.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    _log.info("Déchiffrement — CGL1 %d octets", len(ciphertext))

    # ── 1. Parse CGL1 → salt, nonce, ct+tag ──────────────────────────
    try:
        salt, nonce, ct_tag = _parse_cgl1(ciphertext)
    except ValueError as exc:
        raise CagouleFormatError(
            str(exc),
            field=_detect_bad_field(ciphertext),
            data_size=len(ciphertext),
            min_size=65,
        ) from exc

    # ── 2. Dérivation / validation des paramètres ─────────────────────
    #
    # FIX v2.1.0 — test_mauvais_mdp :
    #
    # En v2.0, `params=fast_params` + mauvais mdp → le k_stream correct
    # de fast_params est utilisé → tag valide → pas d'erreur. FAUX.
    #
    # Fix : si password est non-vide, re-dériver TOUJOURS avec le bon mode
    # KDF (préservé dans params.fast_mode ou fourni par l'appelant).
    # → Mauvais mdp → k_master erroné → k_stream erroné → InvalidTag ✅
    # → Bon mdp avec même salt → résultat identique à avant ✅
    #
    own_params = False

    if password:
        # Déterminer le mode KDF : depuis params existant, sinon argument
        _fast = params.fast_mode if params is not None else fast_mode
        try:
            params    = CagouleParams.derive(password, salt, fast_mode=_fast)
            own_params = True
        except Exception as exc:
            raise CagouleError(
                f"Dérivation des paramètres échouée : {exc}\n"
                "  Vérifiez que argon2-cffi est installé (pip install argon2-cffi)."
            ) from exc
    elif params is None:
        raise CagouleError(
            "decrypt() : password vide et params=None. "
            "Fournissez un mot de passe ou des paramètres pré-dérivés."
        )
    else:
        # password vide + params fournis : usage interne (decrypt_with_params)
        if params.salt != salt:
            raise _auth_error(
                len(ciphertext),
                reason="params fournis ne correspondent pas à ce message (sel différent)",
                hint="Utilisez decrypt(ct, password) sans params= pour ce message.",
            )

    # ── 3. Déchiffrement AEAD (ChaCha20-Poly1305) ────────────────────
    try:
        aad  = _build_aad(salt)
        aead = ChaCha20Poly1305(params.k_stream)
        try:
            t_message = aead.decrypt(nonce, ct_tag, aad)
        except InvalidTag:
            raise _auth_error(len(ciphertext))

        # ── 4. Couche algébrique inverse (C si dispo) ─────────────────
        try:
            padded = _cbc_decrypt(t_message, params)
        except Exception as exc:
            raise CagouleError(
                f"Erreur couche algébrique : {exc}\n"
                "  Le tag Poly1305 était valide — ciphertext interne corrompu."
            ) from exc

        # ── 5. PKCS7 unpad ────────────────────────────────────────────
        try:
            return pkcs7_unpad(padded, BLOCK_SIZE_N)
        except ValueError as exc:
            raise CagouleError(
                f"Padding PKCS7 invalide après déchiffrement réussi : {exc}\n"
                "  Cela ne devrait pas arriver si le tag Poly1305 était valide."
            ) from exc

    finally:
        if own_params:
            params.zeroize()


# ══════════════════════════════════════════════════════════════════════════
#  §4. decrypt_with_params — usage interne (KAT, benchmark, encrypt)
# ══════════════════════════════════════════════════════════════════════════

def decrypt_with_params(ciphertext: bytes, params: CagouleParams) -> bytes:
    """
    Déchiffre avec des paramètres déjà dérivés.
    Passe password=b'' pour court-circuiter la re-dérivation.
    Usage : KAT, benchmarks, encrypt_with_params → decrypt_with_params.
    """
    return decrypt(ciphertext, b'', params=params)