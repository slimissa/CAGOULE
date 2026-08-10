"""
cipher_ctr_raw.py — Pipeline CTR expérimental sans ChaCha20 (CAGOULE v3.1.0)

================================================================================
⚠️  EXPÉRIMENTAL — VERSION CGL1 0x03 — RECHERCHE / BENCHMARK UNIQUEMENT  ⚠️
================================================================================
Ce module retire ChaCha20-Poly1305 du pipeline et n'authentifie le ciphertext
qu'avec Poly1305 seul, appliqué directement sur la sortie du pipeline
algébrique CTR de CAGOULE (Vandermonde + S-box Feistel + ζ(2n) round keys).

La confidentialité de ce mode dépend ENTIÈREMENT de la résistance IND-CPA de
la couche algébrique CAGOULE — qui n'a PAS de preuve de sécurité publiée
(cf. roadmap v3.1.0 §2, SECURITY.md §6.6 : S-box Feistel 2 rounds, degré
algébrique limité, faiblesse connue identifiable par un reviewer IACR).

Critères de promotion vers défaut de production (roadmap §2.3, NON remplis
à ce jour) :
  1. Analyse de sécurité formelle/semi-formelle IND-CPA de la couche CAGOULE
  2. Revue externe (IACR ePrint + 1 cycle de relecture, ou audit indépendant)
  3. Aucune régression dudect sur le pipeline 0x03

Pour tout usage applicatif, utiliser cagoule.encrypt() / encrypt_ctr()
(VERSION 0x02, défaut, IND-CCA2 prouvé via ChaCha20-Poly1305 standard).

Format wire CGL1 v0x03 :
  MAGIC(4) | VERSION=b'\\x03'(1) | SALT(32) | CT(n) | TAG(16)
  Overhead total : 53 octets — corrigé depuis l'erreur arithmétique "49"
  de la proposition initiale du roadmap (§6.1 : 65 − NONCE(12) = 53, pas 49).

Différences vs v0x02 :
  - Pas de chiffrement ChaCha20 de ct_alg — ct_alg est livré tel quel
    (mais reste chiffré par le pipeline CAGOULE CTR algébrique)
  - Pas de champ NONCE dans le header (aucun usage : pas de ChaCha20)
  - TAG = Poly1305(poly_key, AAD ‖ ct_alg)
    poly_key = HKDF(k_master, b'CAGOULE_POLY_V31' + salt, 32)
    AAD      = MAGIC ‖ VERSION ‖ SALT

  CORRECTIF (audit round 2, C2) : poly_key est désormais lié au salt du
  message (32 octets, frais par appel). L'ancienne formule ne dépendait
  que de k_master, ce qui réutilisait la même clé Poly1305 pour tous les
  messages sous params partagés — Poly1305 n'est sûr que pour un seul
  message par clé, donc c'était une forgerie universelle après 2 messages.

  Note de conception — déviation volontaire vs roadmap §2.2 : le roadmap
  écrit "MAC = Poly1305(poly_key, ct_alg)", sans AAD. Cette implémentation
  lie le MAC à (MAGIC ‖ VERSION ‖ SALT) en plus de ct_alg, par symétrie
  avec le pipeline 0x02 (ChaCha20Poly1305 authentifie déjà cet AAD) et pour
  empêcher la falsification silencieuse du byte VERSION ou du SALT — un
  attaquant qui altère SALT sans casser le MAC forcerait une dérivation de
  clé différente côté destinataire, mais rien n'oblige aujourd'hui ce cas à
  échouer de façon authentifiée plutôt que d'échouer "par hasard" sur un
  mauvais déchiffrement. Lier l'AAD ferme ce flou pour un coût nul. À noter
  explicitement dans le draft IACR (roadmap §7, semaine 8) si ce choix est
  conservé. [Confirmed — ceci est un changement par rapport au texte du
  roadmap, fait délibérément ; à valider par LASS avant de figer le KAT 0x03.]

Activation — double gate explicite (MVP Python, avant cagoule_api.c) :
  1. allow_experimental=True passé explicitement à l'appel
  2. variable d'environnement CAGOULE_EXPERIMENTAL_NO_AEAD=1

  [Guess — le roadmap v3.1.0 décrit CAGOULE_EXPERIMENTAL_NO_AEAD comme un
  flag de COMPILATION C pour cagoule_api.c (Feature 2, livré après ce
  module dans l'ordre d'exécution §7). Comme ce module Python est construit
  AVANT cagoule_api.c, il n'existe aucun mécanisme de compilation à gater.
  Ce double gate runtime est un choix d'implémentation pour ce sprint —
  il devra être remplacé/renforcé par le vrai flag de compilation C quand
  cagoule_api.c sera livré, qui pourra retirer purement et simplement le
  symbole 0x03 d'un binaire de production.]
"""
from __future__ import annotations

import os
import warnings
from typing import Optional

from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.exceptions import InvalidSignature

from .params import CagouleParams, hkdf_derive
from .cipher import MAGIC
from .cipher_ctr import SALT_SIZE, _ctr_encrypt, _ctr_decrypt
from .decipher import CagouleAuthError, CagouleFormatError
from .logger import get_logger
from . import format as _cgl1_format

_log = get_logger(__name__)

# ── Constantes format CGL1 v0x03 ────────────────────────────────────────
VERSION_CTR_RAW = b'\x03'
TAG_SIZE        = 16
POLY_KEY_SIZE   = 32

# MAGIC(4) + VERSION(1) + SALT(32) = 37
HEADER_SIZE      = len(MAGIC) + 1 + SALT_SIZE
CGL1_V3_MIN_SIZE = HEADER_SIZE + TAG_SIZE          # 53
OVERHEAD         = HEADER_SIZE + TAG_SIZE          # 53 — cf. roadmap §6.1

ENV_GATE_VAR = "CAGOULE_EXPERIMENTAL_NO_AEAD"


class ExperimentalModeError(RuntimeError):
    """Levée quand VERSION 0x03 est utilisé sans l'opt-in explicite requis."""


def _check_experimental_gate(allow_experimental: bool) -> None:
    env_flag = os.environ.get(ENV_GATE_VAR) == "1"
    if not (allow_experimental and env_flag):
        raise ExperimentalModeError(
            "VERSION 0x03 (Poly1305 seul, sans ChaCha20) est un mode de "
            "recherche expérimental — la confidentialité dépend d'une preuve "
            "IND-CPA NON ENCORE publiée pour la couche algébrique CAGOULE "
            "(roadmap v3.1.0 §2, SECURITY.md §6.6). "
            f"Requiert allow_experimental=True ET la variable d'environnement "
            f"{ENV_GATE_VAR}=1. "
            "Pour tout usage applicatif, utiliser cagoule.encrypt() / "
            "encrypt_ctr() (VERSION 0x02, défaut, IND-CCA2 prouvé)."
        )
    warnings.warn(
        "CAGOULE VERSION 0x03 : confidentialité dépendante d'une preuve "
        "IND-CPA NON ENCORE établie pour la couche algébrique CAGOULE. "
        "Usage recherche/benchmark uniquement — ne pas utiliser pour des "
        "données réelles.",
        UserWarning,
        stacklevel=3,
    )


def _derive_poly_key(params: CagouleParams, salt: bytes) -> bytes:
    """
    poly_key = HKDF(k_master, b'CAGOULE_POLY_V31' + salt, 32)

    CORRECTIF (audit round 2, C2) : la version précédente dérivait poly_key
    depuis k_master seul. Sous params partagés (usage bulk documenté —
    encrypt_ctr_raw(msg, pwd, params=shared_params)), tous les messages
    recevaient la MÊME clé Poly1305 → réutilisation de clé MAC à message
    unique (Poly1305 n'est sûr que pour UN seul message par clé) → forgerie
    universelle possible après 2 messages authentifiés sous la même clé.

    Fix : lier poly_key au salt du message (32 octets, frais par appel —
    voir encrypt_ctr_raw, salt = os.urandom(SALT_SIZE) inconditionnel).
    Même pattern que _derive_ctr_iv() qui lie déjà l'IV CTR au nonce/salt
    par message pour la même raison (two-time-pad, fix v3.0.1 Bug 2).
    """
    return hkdf_derive(params.k_master, b'CAGOULE_POLY_V31' + bytes(salt), POLY_KEY_SIZE)


def _build_aad_v3(salt: bytes) -> bytes:
    return MAGIC + VERSION_CTR_RAW + salt


def encrypt_ctr_raw(message: bytes, password: bytes,
                     params: Optional[CagouleParams] = None,
                     fast_mode: bool = False,
                     allow_experimental: bool = False) -> bytes:
    """
    Chiffrement CTR CAGOULE — VERSION 0x03, EXPÉRIMENTAL (sans ChaCha20).

    Voir l'avertissement de sécurité en tête de module. Requiert
    allow_experimental=True ET CAGOULE_EXPERIMENTAL_NO_AEAD=1 dans
    l'environnement.

    Retourne un ciphertext CGL1 v0x03 :
      MAGIC(4) | VERSION=0x03(1) | SALT(32) | CT(n) | TAG(16)

    |CT| == |message| exactement (identique à v0x02).
    """
    _check_experimental_gate(allow_experimental)

    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message doit être bytes, reçu {type(message).__name__}")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError(f"password doit être bytes, reçu {type(password).__name__}")

    salt = os.urandom(SALT_SIZE)
    own_params = params is None
    if own_params:
        params = CagouleParams.derive(password, salt=salt, fast_mode=fast_mode)

    try:
        # 1. Chiffrement CTR algébrique (identique au pipeline 0x02)
        ct_alg = _ctr_encrypt(bytes(message), params, salt)

        # 2. MAC Poly1305 seul — pas de ChaCha20
        poly_key = _derive_poly_key(params, salt)
        aad = _build_aad_v3(salt)
        tag = Poly1305.generate_tag(poly_key, aad + ct_alg)

        # 3. Assemblage CGL1 v0x03 — pas de NONCE
        # CORRECTIF (audit round 2, consolidation) : délègue à
        # format.serialize_raw() au lieu de la concaténation inline.
        return _cgl1_format.serialize_raw(
            salt, ct_alg, tag, version=_cgl1_format.VERSION_RAW)

    finally:
        if own_params:
            params.zeroize()


def decrypt_ctr_raw(ciphertext: bytes, password: bytes,
                     params: Optional[CagouleParams] = None,
                     fast_mode: bool = False,
                     allow_experimental: bool = False) -> bytes:
    """
    Déchiffrement CTR CAGOULE — VERSION 0x03, EXPÉRIMENTAL (sans ChaCha20).

    Vérifie le tag Poly1305 AVANT tout déchiffrement — même garantie
    d'ordre que v0x02 (pas de plaintext relâché avant authentification,
    cf. roadmap §3.1 sur cagoule_decrypt_v3()).
    """
    _check_experimental_gate(allow_experimental)

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError(f"ciphertext doit être bytes, reçu {type(ciphertext).__name__}")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError(f"password doit être bytes, reçu {type(password).__name__}")

    ciphertext = bytes(ciphertext)
    if len(ciphertext) < CGL1_V3_MIN_SIZE:
        raise CagouleFormatError(
            f"Ciphertext CGL1 v0x03 trop court : {len(ciphertext)} < {CGL1_V3_MIN_SIZE}",
            field="taille",
            data_size=len(ciphertext),
            min_size=CGL1_V3_MIN_SIZE,
        )
    magic   = ciphertext[:4]
    version = ciphertext[4:5]
    if magic != MAGIC:
        raise CagouleFormatError(
            f"Magic invalide : {magic!r} != {MAGIC!r}",
            field="magic",
            data_size=len(ciphertext),
            min_size=CGL1_V3_MIN_SIZE,
        )
    if version != VERSION_CTR_RAW:
        raise CagouleFormatError(
            f"Version inattendue : {version!r} (attendu {VERSION_CTR_RAW!r} "
            "pour CTR raw 0x03). Utiliser decrypt() pour le dispatch "
            "automatique 0x01/0x02.",
            field="version",
            data_size=len(ciphertext),
            min_size=CGL1_V3_MIN_SIZE,
        )

    salt   = ciphertext[5:5 + SALT_SIZE]
    ct_alg = ciphertext[5 + SALT_SIZE:-TAG_SIZE]
    tag    = ciphertext[-TAG_SIZE:]

    own_params = params is None
    if own_params:
        params = CagouleParams.derive(password, salt=salt, fast_mode=fast_mode)
    else:
        if bytes(params.salt) != bytes(salt):
            _log.warning(
                "decrypt_ctr_raw : params.salt (%s...) ne correspond pas au "
                "salt du header CGL1 (%s...). Le déchiffrement peut produire "
                "du garbage sans erreur d'authentification.",
                bytes(params.salt).hex()[:16], salt.hex()[:16]
            )
    # Si params est fourni (bulk ou bench), on l'utilise tel quel — même
    # convention que decrypt_ctr() v0x02 : le salt du ciphertext doit
    # correspondre au salt utilisé pour dériver params.

    try:
        poly_key = _derive_poly_key(params, salt)
        aad = _build_aad_v3(salt)
        try:
            Poly1305.verify_tag(poly_key, aad + ct_alg, tag)
        except InvalidSignature as exc:
            raise CagouleAuthError(
                "Authentification Poly1305 échouée (VERSION 0x03) — "
                "mot de passe incorrect ou ciphertext altéré.",
                reason="mauvais mot de passe ou ciphertext corrompu (CTR v0x03 expérimental)",
                ct_size=len(ciphertext),
                backend="CTR-raw(0x03 expérimental)",
                hint="Vérifier le mot de passe. Rappel : 0x03 n'a pas de "
                     "preuve IND-CPA publiée — usage recherche uniquement.",
            ) from exc

        return _ctr_decrypt(ct_alg, params, salt)

    finally:
        if own_params:
            params.zeroize()
