"""
decipher.py — Déchiffrement CAGOULE v1.1

Pipeline (inverse de cipher.py) :
    Ciphertext CGL1
        │
        ▼  Parse : Magic | Version | Salt | Nonce | CT+Tag
        ▼
    ┌─────────────────────────────────────┐
    │  DÉCHIFFREMENT AEAD                 │
    │  ChaCha20-Poly1305 (RFC 8439)       │
    │  Vérifie le tag Poly1305 → T(msg)  │
    └─────────────────────────────────────┘
        │  T(message) = éléments de Z/pZ
        ▼
    ┌─────────────────────────────────────┐
    │  DÉCHIFFREMENT INTERNE (CBC-like)   │
    │  pour chaque bloc c_i :             │
    │    1. u = c - round_key mod p       │  ← retirer clé de ronde
    │    2. w = S-box⁻¹(u)              │  ← inversion S-box
    │    3. v = P⁻¹ × w mod p           │  ← diffusion inverse
    │    4. m = v - prev_cipher mod p    │  ← CBC unmixing
    └─────────────────────────────────────┘
        │  octets plaintexte + padding PKCS7
        ▼  pkcs7_unpad
    Plaintext (bytes)

Requis par : cli.py
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from params import CagouleParams
from params import BLOCK_SIZE_N
from cipher import (
    MAGIC, VERSION, NONCE_SIZE, HEADER_SIZE,
    pkcs7_unpad, bytes_to_elements, elements_to_bytes,
    _build_aad,
)
from omega import remove_round_key


# ------------------------------------------------------------------ #
#  Exceptions typées                                                   #
# ------------------------------------------------------------------ #

class CagouleError(Exception):
    """Erreur de base CAGOULE."""


class CagouleAuthError(CagouleError):
    """
    Tag d'authentification invalide.
    Déclenché si le ciphertext est altéré ou si le mot de passe est incorrect.
    """


class CagouleFormatError(CagouleError):
    """Format CGL1 invalide (magic, version, ou longueur incorrecte)."""


# ------------------------------------------------------------------ #
#  Parsing du format CGL1                                              #
# ------------------------------------------------------------------ #

def _parse_cgl1(data: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Parse un message au format CGL1.

    Retourne (salt, nonce, ciphertext_with_tag).
    Lève CagouleFormatError si le format est invalide.
    """
    min_size = 4 + 1 + 32 + 12 + 16    # Magic + Version + Salt + Nonce + Tag min
    if len(data) < min_size:
        raise CagouleFormatError(
            f"Message trop court : {len(data)} octets < {min_size} minimum"
        )

    magic   = data[0:4]
    version = data[4:5]
    salt    = data[5:37]
    nonce   = data[37:49]
    ct_tag  = data[49:]

    if magic != MAGIC:
        raise CagouleFormatError(
            f"Magic invalide : attendu {MAGIC!r}, reçu {magic!r}"
        )
    if version != VERSION:
        raise CagouleFormatError(
            f"Version non supportée : {version.hex()} (supporté: {VERSION.hex()})"
        )

    return salt, nonce, ct_tag


# ------------------------------------------------------------------ #
#  Déchiffrement interne (CBC-like inverse)                           #
# ------------------------------------------------------------------ #

def _decrypt_block(cipher_block: list[int], prev_cipher: list[int],
                   params: CagouleParams, round_key: int) -> list[int]:
    """
    Déchiffre un bloc de N entiers dans Z/pZ.

    Inverse strict de cipher._encrypt_block :
    1. u = cipher_block - round_key mod p   (retirer clé de ronde)
    2. w = S-box⁻¹(u)                      (inversion S-box)
    3. v = P⁻¹ × w mod p                   (diffusion inverse)
    4. m = v - prev_cipher mod p            (CBC unmixing)
    """
    p = params.p
    N = BLOCK_SIZE_N

    # Étape 1 : retirer la round key
    u = remove_round_key(cipher_block, round_key, p)

    # Étape 2 : S-box inverse
    w = params.sbox.inverse_block(u)

    # Étape 3 : diffusion inverse
    v = params.diffusion.apply_inverse(w)

    # Étape 4 : CBC unmixing
    m = [(v[j] - prev_cipher[j]) % p for j in range(N)]

    return m


def _cbc_decrypt(t_message_bytes: bytes, params: CagouleParams) -> bytes:
    """
    Déchiffre T(message) (sortie du CBC interne) en octets plaintexte.
    Inverse de cipher._cbc_encrypt.
    """
    N = BLOCK_SIZE_N           # taille de bloc fixe = 16
    p = params.p
    p_bytes = params.p_bytes
    round_keys = params.round_keys
    num_round_keys = len(round_keys)

    all_elements = bytes_to_elements(t_message_bytes, p_bytes)

    if len(all_elements) % N != 0:
        raise CagouleFormatError(
            f"Nombre d'éléments ({len(all_elements)}) non multiple de N ({N})"
        )

    cipher_blocks = [all_elements[i:i + N] for i in range(0, len(all_elements), N)]
    prev_cipher = [0] * N

    plaintext_bytes = []
    for block_idx, cipher_block in enumerate(cipher_blocks):
        rk = round_keys[block_idx % num_round_keys]
        m = _decrypt_block(cipher_block, prev_cipher, params, rk)
        for val in m:
            plaintext_bytes.append(val % 256)
        prev_cipher = cipher_block

    return bytes(plaintext_bytes)


# ------------------------------------------------------------------ #
#  Point d'entrée public                                               #
# ------------------------------------------------------------------ #

def decrypt(ciphertext: bytes, password: bytes | str,
            fast_mode: bool = False) -> bytes:
    """
    Déchiffre un message CAGOULE v1.1 au format CGL1.

    ciphertext : octets au format CGL1
    password   : mot de passe (bytes ou str)
    fast_mode  : True = paramètres KDF réduits (tests uniquement)

    Lève :
        CagouleFormatError  — format CGL1 invalide
        CagouleAuthError    — tag invalide (ciphertext altéré ou mauvais mdp)
        CagouleError        — autre erreur interne
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    # ── Parsing CGL1 ──────────────────────────────────────────────── #
    salt, nonce, ct_tag = _parse_cgl1(ciphertext)

    # ── Dérivation des paramètres (même sel = même clés) ─────────── #
    try:
        params = CagouleParams.derive(password, salt, fast_mode=fast_mode)
    except Exception as e:
        raise CagouleError(f"Erreur de dérivation des paramètres : {e}") from e

    # ── Déchiffrement AEAD ChaCha20-Poly1305 ─────────────────────── #
    aad  = _build_aad(salt)
    aead = ChaCha20Poly1305(params.k_stream)

    try:
        t_message = aead.decrypt(nonce, ct_tag, aad)
    except InvalidTag:
        # Exception générique sans détail d'erreur (roadmap §11)
        raise CagouleAuthError(
            "Authentification échouée — ciphertext altéré ou mot de passe incorrect"
        )

    # ── Déchiffrement interne CBC-like ────────────────────────────── #
    try:
        padded_plaintext = _cbc_decrypt(t_message, params)
    except Exception as e:
        raise CagouleError(f"Erreur de déchiffrement interne : {e}") from e

    # ── Retirer le padding PKCS7 ──────────────────────────────────── #
    try:
        plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE_N)
    except ValueError as e:
        raise CagouleError(f"Padding PKCS7 invalide : {e}") from e

    return plaintext


def decrypt_with_params(ciphertext: bytes, params: CagouleParams) -> bytes:
    """
    Déchiffre avec des paramètres déjà dérivés.
    Utile pour les tests déterministes (KAT).
    """
    salt, nonce, ct_tag = _parse_cgl1(ciphertext)

    aad  = _build_aad(salt)
    aead = ChaCha20Poly1305(params.k_stream)

    try:
        t_message = aead.decrypt(nonce, ct_tag, aad)
    except InvalidTag:
        raise CagouleAuthError("Authentification échouée")

    padded_plaintext = _cbc_decrypt(t_message, params)
    return pkcs7_unpad(padded_plaintext, BLOCK_SIZE_N)