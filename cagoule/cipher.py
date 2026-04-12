"""
cipher.py — Chiffrement CAGOULE v1.1

Pipeline :
    Plaintext (bytes)
        │
        ▼  PKCS7 pad → blocs de N octets → vecteurs dans Z/pZ
        ▼
    ┌─────────────────────────────────────┐
    │  CHIFFREMENT INTERNE (CBC-like)     │
    │  pour chaque bloc m_i :             │
    │    1. v = m_i + prev_cipher mod p   │  ← CBC mixing (addition mod p)
    │    2. w = P × v mod p              │  ← diffusion Vandermonde
    │    3. u = S-box(w)                 │  ← confusion cubique
    │    4. c = u + round_key mod p      │  ← clé de ronde Ω
    └─────────────────────────────────────┘
        │  T(message) sérialisé en octets (p_bytes par élément)
        ▼
    ┌─────────────────────────────────────┐
    │  ENVELOPPE AEAD                     │
    │  ChaCha20-Poly1305 (RFC 8439)       │
    │  K_stream + nonce + AAD             │
    └─────────────────────────────────────┘
        │
    Format CGL1 : Magic(4) | Version(1) | Salt(32) | Nonce(12) | CT | Tag(16)

Requis par : cli.py
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .params import CagouleParams, BLOCK_SIZE_N
from .omega import apply_round_key


# ------------------------------------------------------------------ #
#  Format binaire CGL1                                                 #
# ------------------------------------------------------------------ #

MAGIC   = b'CGL1'          # 4 octets
VERSION = b'\x01'          # 1 octet
NONCE_SIZE = 12            # octets — 96 bits pour ChaCha20-Poly1305
HEADER_SIZE = 4 + 1 + 32 + 12  # = 49 octets (avant ciphertext)


# ------------------------------------------------------------------ #
#  PKCS7 padding                                                       #
# ------------------------------------------------------------------ #

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Applique le padding PKCS7 pour aligner sur block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Retire le padding PKCS7."""
    if not data:
        raise ValueError("Données vides — padding PKCS7 invalide")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Longueur de padding PKCS7 invalide : {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS7 corrompu")
    return data[:-pad_len]


# ------------------------------------------------------------------ #
#  Sérialisation Z/pZ ↔ bytes                                         #
# ------------------------------------------------------------------ #

def elements_to_bytes(elements: list[int], p_bytes: int) -> bytes:
    """
    Sérialise une liste d'éléments de Z/pZ en octets.
    Chaque élément utilise p_bytes octets (big-endian).
    """
    parts = []
    for e in elements:
        parts.append(e.to_bytes(p_bytes, 'big'))
    return b''.join(parts)


def bytes_to_elements(data: bytes, p_bytes: int) -> list[int]:
    """
    Désérialise des octets en éléments de Z/pZ.
    Chaque élément occupe p_bytes octets (big-endian).
    """
    if len(data) % p_bytes != 0:
        raise ValueError(
            f"Taille des données ({len(data)}) non multiple de p_bytes ({p_bytes})"
        )
    elements = []
    for i in range(0, len(data), p_bytes):
        elements.append(int.from_bytes(data[i:i + p_bytes], 'big'))
    return elements


# ------------------------------------------------------------------ #
#  Chiffrement interne (CBC-like)                                      #
# ------------------------------------------------------------------ #

def _encrypt_block(block_ints: list[int], prev_cipher: list[int],
                   params: CagouleParams, round_key: int) -> list[int]:
    """
    Chiffre un bloc de N entiers dans Z/pZ.

    1. v = block_ints + prev_cipher mod p  (CBC mixing)
    2. w = P × v mod p                     (diffusion Vandermonde)
    3. u = S-box(w) pour chaque élément    (confusion)
    4. c = u + round_key mod p             (clé de ronde)
    """
    p = params.p
    N = BLOCK_SIZE_N

    # Étape 1 : CBC mixing (addition mod p)
    v = [(block_ints[j] + prev_cipher[j]) % p for j in range(N)]

    # Étape 2 : diffusion matricielle
    w = params.diffusion.apply(v)

    # Étape 3 : S-box
    u = params.sbox.forward_block(w)

    # Étape 4 : ajout de la round key
    c = apply_round_key(u, round_key, p)

    return c


def _cbc_encrypt(message_bytes: bytes, params: CagouleParams) -> bytes:
    """
    Applique le chiffrement interne CBC-like sur les octets du message.

    Taille de bloc fixe : BLOCK_SIZE_N = 16 (Phase 1).
    params.n est le paramètre Zêta pour les round keys (distinct).

    Retourne T(message) : octets sérialisés des éléments chiffrés de Z/pZ.
    """
    N = BLOCK_SIZE_N           # taille de bloc fixe = 16
    p = params.p
    p_bytes = params.p_bytes
    round_keys = params.round_keys
    num_round_keys = len(round_keys)

    # PKCS7 padding pour aligner sur N octets
    padded = pkcs7_pad(message_bytes, N)

    # Découpage en blocs de N octets
    blocks = [list(padded[i:i + N]) for i in range(0, len(padded), N)]

    # Vecteur IV initial (tout à zéro)
    prev_cipher = [0] * N

    # Chiffrement bloc par bloc
    cipher_elements = []
    for block_idx, block in enumerate(blocks):
        # Convertir les octets en éléments de Z/pZ (b ∈ [0,255] < p)
        block_ints = [b % p for b in block]

        # Round key courante (cycling sur num_round_keys)
        rk = round_keys[block_idx % num_round_keys]

        # Chiffrer le bloc
        c = _encrypt_block(block_ints, prev_cipher, params, rk)

        cipher_elements.extend(c)
        prev_cipher = c

    return elements_to_bytes(cipher_elements, p_bytes)


# ------------------------------------------------------------------ #
#  Construction du format CGL1                                         #
# ------------------------------------------------------------------ #

def _build_aad(salt: bytes) -> bytes:
    """
    AAD = Magic || Version || Salt.
    Ces champs sont authentifiés par Poly1305 mais transmis en clair.
    """
    return MAGIC + VERSION + salt


def _serialize_cgl1(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Sérialise le message chiffré au format CGL1.

    Structure : Magic(4) | Version(1) | Salt(32) | Nonce(12) | CT+Tag
    (le tag Poly1305 de 16 octets est inclus dans ciphertext par ChaCha20Poly1305)
    """
    return MAGIC + VERSION + salt + nonce + ciphertext


# ------------------------------------------------------------------ #
#  Point d'entrée public                                               #
# ------------------------------------------------------------------ #

def encrypt(plaintext: bytes | str, password: bytes | str,
            salt: bytes | None = None,
            params: CagouleParams | None = None) -> bytes:
    """
    Chiffre plaintext avec CAGOULE v1.1.

    plaintext : message à chiffrer (bytes ou str UTF-8)
    password  : mot de passe (bytes ou str)
    salt      : sel 32 octets (None = aléatoire)
    params    : paramètres pré-calculés (None = dérivés depuis password+salt)

    Retourne les octets au format CGL1.
    """
    # Normalisation des entrées
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(password, str):
        password = password.encode('utf-8')

    # Dérivation des paramètres
    if params is None:
        params = CagouleParams.derive(password, salt)
    salt = params.salt

    # ── Chiffrement interne CBC-like ───────────────────────────────── #
    t_message = _cbc_encrypt(plaintext, params)

    # ── Enveloppe AEAD ChaCha20-Poly1305 ─────────────────────────── #
    nonce = os.urandom(NONCE_SIZE)
    aad   = _build_aad(salt)
    aead  = ChaCha20Poly1305(params.k_stream)
    ciphertext_with_tag = aead.encrypt(nonce, t_message, aad)

    # ── Format CGL1 ──────────────────────────────────────────────── #
    return _serialize_cgl1(salt, nonce, ciphertext_with_tag)


def encrypt_with_params(plaintext: bytes | str,
                        params: CagouleParams) -> bytes:
    """
    Chiffre avec des paramètres déjà dérivés.
    Utile pour les tests déterministes (KAT).
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return encrypt(plaintext, b'', params=params)