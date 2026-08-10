"""
decipher_ctr.py — Déchiffrement CTR CAGOULE v3.1.0

Dispatch automatique par VERSION dans le header CGL1 :
  VERSION 0x01 → pipeline CBC (decipher.py)
  VERSION 0x02 → pipeline CTR (ce module)

Utilisé par decrypt() dans __init__.py via _dispatch_decrypt().
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .params      import CagouleParams
from .cipher      import MAGIC
from .cipher_ctr  import (
    VERSION_CTR, VERSION_CBC,
    CGL1_V2_MIN_SIZE,
    _build_cgl1_v2, _parse_cgl1_v2,
    _ctr_decrypt,
)
from .decipher    import CagouleAuthError, CagouleFormatError
from ._binding    import CAGOULE_C_AVAILABLE
from .logger      import get_logger

_log = get_logger(__name__)


def decrypt_ctr(ciphertext: bytes, password: bytes,
                params: CagouleParams = None,
                fast_mode: bool = False) -> bytes:
    """
    Déchiffrement CTR CAGOULE v3.0.0.

    Accepte uniquement les ciphertexts CGL1 v0x02 (CTR).
    Pour les ciphertexts v0x01 (CBC), utiliser decrypt_cbc() ou decrypt()
    qui dispatch automatiquement.

    Args:
        ciphertext: Bytes CGL1 v0x02
        password:   Mot de passe bytes
        params:     CagouleParams pré-dérivés (optionnel)
        fast_mode:  KDF rapide pour les tests

    Returns:
        Plaintext bytes (longueur identique au plaintext original)

    Raises:
        CagouleAuthError:   Tag Poly1305 invalide (mauvais mot de passe ou corruption)
        CagouleFormatError: Format CGL1 invalide
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError(f"ciphertext doit être bytes, reçu {type(ciphertext).__name__}")
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError(f"password doit être bytes, reçu {type(password).__name__}")

    # 1. Parser le header CGL1 v0x02
    try:
        salt, nonce, ct_aead = _parse_cgl1_v2(bytes(ciphertext))
    except ValueError as exc:
        raise CagouleFormatError(
            str(exc),
            field="VERSION/MAGIC",
            data_size=len(ciphertext),
            min_size=CGL1_V2_MIN_SIZE,
        ) from exc

    # 2. Dériver les paramètres depuis (password, salt)
    own_params = params is None
    if own_params:
        params = CagouleParams.derive(password, salt=salt, fast_mode=fast_mode)
    else:
        # CORRECTIF v3.1.0 (Finding 4) : vérifier que params.salt correspond au
        # salt du ciphertext. Une discordance produit un déchiffrement silencieusement
        # erroné (garbage plaintext sans CagouleAuthError) car k_stream est
        # cohérent avec lui-même mais pas avec le ciphertext.
        #
        # Exception : en mode bulk avec cagoule_encrypt_with_handle (C API),
        # chaque ciphertext a un msg_salt distinct même si le handle est partagé.
        # Dans ce cas params.salt (salt original du handle) != msg_salt du header.
        # On log un avertissement mais on ne bloque pas pour préserver la compat C bulk.
        if bytes(params.salt) != bytes(salt):
            _log.warning(
                "decrypt_ctr : params.salt (%s...) ne correspond pas au salt "
                "du header CGL1 (%s...). Si ce ciphertext provient de "
                "cagoule_encrypt_with_handle (C bulk), c'est normal. Sinon, "
                "le déchiffrement peut produire du garbage sans erreur d'auth.",
                bytes(params.salt).hex()[:16], salt.hex()[:16]
            )

    try:
        # 3. Vérification AEAD ChaCha20-Poly1305
        aad    = _build_cgl1_v2(salt)
        chacha = ChaCha20Poly1305(params.k_stream)
        try:
            ct_alg = chacha.decrypt(nonce, ct_aead, aad)
        except InvalidTag as exc:
            raise CagouleAuthError(
                "Authentification ChaCha20-Poly1305 échouée — "
                "mot de passe incorrect ou ciphertext CTR altéré.",
                reason="mauvais mot de passe ou ciphertext corrompu (CTR v0x02)",
                ct_size=len(ciphertext),
                backend=f"CTR{'(C)' if CAGOULE_C_AVAILABLE else '(Python fallback)'}",
                hint="Vérifier le mot de passe ou utiliser decrypt_cbc() pour les "
                     "ciphertexts v0x01.",
            ) from exc

        # 4. Déchiffrement CTR algébrique
        # CORRECTIF v3.0.1 (3e itération) : passer le nonce (lu depuis le header)
        # pour dériver le même IV que lors du chiffrement.
        # L'IV = HKDF(k_master, b'CAGOULE_CTR_V31' + nonce) — symétrique avec encrypt.
        plaintext = _ctr_decrypt(ct_alg, params, nonce)
        return plaintext

    finally:
        if own_params:
            params.zeroize()


def decrypt_bulk_ctr(ciphertexts: list, password: bytes,
                     fast_mode: bool = False) -> list:
    """
    Déchiffrement CTR bulk.

    Déchiffre une liste de ciphertexts CGL1 v0x02.
    Chaque ciphertext est déchiffré indépendamment (salt distinct → k_master
    distinct → dérivation Argon2id par message dans le cas général).

    Pour les ciphertexts produits par encrypt_bulk_ctr(), le salt distinct
    par message entraîne une dérivation Argon2id par message ici.

    Usage : préférer decrypt_ctr() individuel si les performances importent
    plus que la simplicité d'API.
    """
    # CORRECTIF v3.1.0 (Finding 2) : ne plus avorter sur le premier échec.
    # Un ciphertext corrompu dans un lot ne doit pas empêcher le déchiffrement
    # des autres. On retourne (index, résultat_ou_exception) pour chaque élément.
    # L'appelant peut distinguer les succès des échecs sans perdre les succès.
    results = []
    errors  = []
    for i, ct in enumerate(ciphertexts):
        try:
            results.append(decrypt_ctr(ct, password, fast_mode=fast_mode))
        except (CagouleAuthError, CagouleFormatError) as e:
            errors.append((i, e))
            results.append(None)  # placeholder pour préserver les indices

    if errors:
        # Logguer les erreurs mais retourner les succès
        _log.warning(
            "decrypt_bulk_ctr : %d/%d ciphertexts ont échoué : %s",
            len(errors), len(ciphertexts),
            [(i, str(e)) for i, e in errors]
        )
    return results


def _dispatch_decrypt(ciphertext: bytes, password: bytes,
                      params: CagouleParams = None,
                      fast_mode: bool = False) -> bytes:
    """
    Dispatch automatique basé sur VERSION dans le header CGL1.

    VERSION 0x01 → CBC (decipher.decrypt)
    VERSION 0x02 → CTR (decrypt_ctr)
    Autre         → CagouleFormatError
    """
    if len(ciphertext) < 5:
        raise CagouleFormatError(
            f"Ciphertext trop court pour déterminer la version : {len(ciphertext)} octets",
            field="VERSION",
            data_size=len(ciphertext),
            min_size=5,
        )

    magic   = ciphertext[:4]
    version = ciphertext[4:5]

    if magic != MAGIC:
        raise CagouleFormatError(
            f"Magic invalide : {magic.hex()}",
            field="MAGIC",
            data_size=len(ciphertext),
            min_size=5,
        )

    if version == VERSION_CTR:
        return decrypt_ctr(ciphertext, password,
                           params=params, fast_mode=fast_mode)

    if version == VERSION_CBC:
        from .decipher import decrypt as _decrypt_cbc
        return _decrypt_cbc(ciphertext, password,
                           params=params, fast_mode=fast_mode)

    raise CagouleFormatError(
        f"Version CGL1 inconnue : 0x{version.hex()}. "
        "Versions supportées : 0x01 (CBC), 0x02 (CTR).",
        field="VERSION",
        data_size=len(ciphertext),
        min_size=5,
    )