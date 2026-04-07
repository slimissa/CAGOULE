"""
format.py — Sérialisation / désérialisation du format binaire CGL1

Structure d'un message chiffré CAGOULE v1.1 :

  Offset  Taille  Champ
  ──────  ──────  ──────────────────────────────────────────────
   0..3      4    Magic : 0x43474C31 = "CGL1"
      4      1    Version : 0x01
   5..36    32    Salt (inclus dans AAD)
  37..48    12    Nonce ChaCha20-Poly1305 (96 bits)
  49..N   variable  Ciphertext T(message) chiffré par ChaCha20
  N..N+16   16    Tag Poly1305

AAD = Magic || Version || Salt (authentifié mais transmis en clair).
Overhead fixe : 4 + 1 + 32 + 12 + 16 = 65 octets.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple, Optional

# ------------------------------------------------------------------ #
#  Constantes de format                                              #
# ------------------------------------------------------------------ #

MAGIC: bytes = b'CGL1'
MAGIC_HEX: int = 0x43474C31
VERSION_BYTE: int = 0x01
VERSION: bytes = bytes([VERSION_BYTE])

MAGIC_SIZE: int = 4
VERSION_SIZE: int = 1
SALT_SIZE: int = 32
NONCE_SIZE: int = 12
TAG_SIZE: int = 16

HEADER_SIZE: int = MAGIC_SIZE + VERSION_SIZE + SALT_SIZE + NONCE_SIZE  # 49
OVERHEAD: int = HEADER_SIZE + TAG_SIZE                                  # 65

SUPPORTED_VERSIONS: set = {0x01}


# ------------------------------------------------------------------ #
#  Exceptions                                                         #
# ------------------------------------------------------------------ #

class CGL1FormatError(Exception):
    """Erreur de format CGL1 (magic, version, ou longueur incorrecte)."""
    pass


# ------------------------------------------------------------------ #
#  Structure parsée                                                   #
# ------------------------------------------------------------------ #

@dataclass
class CGL1Packet:
    """
    Représente un paquet CGL1 parsé.

    Attributs :
        version    : numéro de version (int)
        salt       : sel Argon2id/Scrypt (32 octets)
        nonce      : nonce ChaCha20 (12 octets)
        ciphertext : ciphertext brut (sans tag)
        tag        : tag Poly1305 (16 octets)

    Propriétés calculées :
        aad        : données authentifiées (Magic || Version || Salt)
        ct_with_tag: ciphertext || tag (format attendu par decrypt)
    """
    version: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        """Validation des types après initialisation."""
        if not isinstance(self.version, int):
            raise TypeError(f"version doit être int, got {type(self.version)}")
        if len(self.salt) != SALT_SIZE:
            raise ValueError(f"salt doit faire {SALT_SIZE} octets, got {len(self.salt)}")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(f"nonce doit faire {NONCE_SIZE} octets, got {len(self.nonce)}")
        if len(self.tag) != TAG_SIZE:
            raise ValueError(f"tag doit faire {TAG_SIZE} octets, got {len(self.tag)}")

    @property
    def aad(self) -> bytes:
        """Données authentifiées = Magic || Version || Salt."""
        return MAGIC + bytes([self.version]) + self.salt

    @property
    def ciphertext_with_tag(self) -> bytes:
        """Ciphertext + tag (format pour ChaCha20Poly1305.decrypt)."""
        return self.ciphertext + self.tag

    def to_bytes(self) -> bytes:
        """Sérialise le paquet en format CGL1 binaire."""
        return (
            MAGIC
            + bytes([self.version])
            + self.salt
            + self.nonce
            + self.ciphertext
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CGL1Packet:
        """Alias de parse() — construction à partir de bytes."""
        return parse(data)

    def __repr__(self) -> str:
        return (
            f"CGL1Packet(version=0x{self.version:02x}, "
            f"salt={self.salt[:4].hex()}..., "
            f"nonce={self.nonce.hex()[:8]}..., "
            f"ct_len={len(self.ciphertext)}, "
            f"tag={self.tag.hex()[:8]}...)"
        )


# ------------------------------------------------------------------ #
#  Parsing                                                           #
# ------------------------------------------------------------------ #

def parse(data: bytes) -> CGL1Packet:
    """
    Parse un message au format CGL1.

    Lève CGL1FormatError si le format est invalide.
    Retourne un CGL1Packet avec les champs extraits.
    """
    min_size = HEADER_SIZE + TAG_SIZE   # 65 octets minimum (CT vide)
    if len(data) < min_size:
        raise CGL1FormatError(
            f"Paquet trop court : {len(data)} octets "
            f"(minimum {min_size} = header {HEADER_SIZE} + tag {TAG_SIZE})"
        )

    # Magic
    magic = data[0:MAGIC_SIZE]
    if magic != MAGIC:
        raise CGL1FormatError(
            f"Magic invalide : attendu {MAGIC!r} (0x{MAGIC_HEX:08x}), "
            f"reçu {magic!r} (0x{int.from_bytes(magic, 'big'):08x})"
        )

    # Version
    version = data[MAGIC_SIZE]
    if version not in SUPPORTED_VERSIONS:
        raise CGL1FormatError(
            f"Version non supportée : 0x{version:02x} "
            f"(supportées : {[hex(v) for v in sorted(SUPPORTED_VERSIONS)]})"
        )

    # Salt
    offset = MAGIC_SIZE + VERSION_SIZE
    salt = data[offset:offset + SALT_SIZE]
    if len(salt) != SALT_SIZE:
        raise CGL1FormatError(f"Salt tronqué : {len(salt)} < {SALT_SIZE}")

    # Nonce
    offset += SALT_SIZE
    nonce = data[offset:offset + NONCE_SIZE]
    if len(nonce) != NONCE_SIZE:
        raise CGL1FormatError(f"Nonce tronqué : {len(nonce)} < {NONCE_SIZE}")

    # Ciphertext + Tag
    offset += NONCE_SIZE
    ct_and_tag = data[offset:]
    if len(ct_and_tag) < TAG_SIZE:
        raise CGL1FormatError(
            f"Zone CT+Tag trop courte : {len(ct_and_tag)} < {TAG_SIZE}"
        )

    ciphertext = ct_and_tag[:-TAG_SIZE]
    tag = ct_and_tag[-TAG_SIZE:]

    return CGL1Packet(
        version=version,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
    )


# ------------------------------------------------------------------ #
#  Sérialisation                                                     #
# ------------------------------------------------------------------ #

def serialize(
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    version: int = VERSION_BYTE
) -> bytes:
    """
    Sérialise les composants en format CGL1.

    Args:
        salt       : 32 octets
        nonce      : 12 octets
        ciphertext : ciphertext brut (sans tag)
        tag        : tag Poly1305 (16 octets)
        version    : numéro de version (défaut : 1)

    Returns:
        bytes: Paquet CGL1 complet

    Raises:
        CGL1FormatError: si les composants sont invalides
    """
    if len(salt) != SALT_SIZE:
        raise CGL1FormatError(
            f"Salt invalide : {len(salt)} octets (attendu {SALT_SIZE})"
        )
    if len(nonce) != NONCE_SIZE:
        raise CGL1FormatError(
            f"Nonce invalide : {len(nonce)} octets (attendu {NONCE_SIZE})"
        )
    if len(tag) != TAG_SIZE:
        raise CGL1FormatError(
            f"Tag invalide : {len(tag)} octets (attendu {TAG_SIZE})"
        )
    if version not in SUPPORTED_VERSIONS:
        raise CGL1FormatError(f"Version non supportée : 0x{version:02x}")

    return MAGIC + bytes([version]) + salt + nonce + ciphertext + tag


def serialize_from_aead(
    salt: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    version: int = VERSION_BYTE
) -> bytes:
    """
    Sérialise à partir de la sortie directe de ChaCha20Poly1305.encrypt().

    Cette fonction est un wrapper pour ceux qui préfèrent l'API originale.

    Args:
        salt                : 32 octets
        nonce               : 12 octets
        ciphertext_with_tag : ciphertext + tag concaténés (sortie AEAD)
        version             : numéro de version (défaut : 1)
    """
    if len(ciphertext_with_tag) < TAG_SIZE:
        raise CGL1FormatError(
            f"CT+Tag trop court : {len(ciphertext_with_tag)} < {TAG_SIZE}"
        )
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag = ciphertext_with_tag[-TAG_SIZE:]
    return serialize(salt, nonce, ciphertext, tag, version)


# ------------------------------------------------------------------ #
#  Inspection                                                        #
# ------------------------------------------------------------------ #

def inspect(data: bytes) -> dict:
    """
    Inspecte un paquet CGL1 sans le déchiffrer.

    Retourne un dictionnaire avec les métadonnées du paquet.
    Lève CGL1FormatError si le format est invalide.
    """
    packet = parse(data)
    return {
        "magic":           MAGIC.decode('ascii'),
        "magic_hex":       f"0x{MAGIC_HEX:08x}",
        "version":         f"0x{packet.version:02x}",
        "salt_hex":        packet.salt.hex(),
        "salt_len":        len(packet.salt),
        "nonce_hex":       packet.nonce.hex(),
        "nonce_len":       len(packet.nonce),
        "ciphertext_len":  len(packet.ciphertext),
        "tag_hex":         packet.tag.hex(),
        "tag_len":         len(packet.tag),
        "total_size":      len(data),
        "overhead":        OVERHEAD,
        "aad_hex":         packet.aad.hex(),
        "aad_size":        len(packet.aad),
    }


def overhead() -> int:
    """Retourne l'overhead fixe en octets (65 = header + tag)."""
    return OVERHEAD


def is_cgl1(data: bytes) -> bool:
    """Vérifie rapidement si des bytes semblent être un paquet CGL1 valide."""
    try:
        parse(data)
        return True
    except CGL1FormatError:
        return False


# ------------------------------------------------------------------ #
#  Test rapide (si exécuté directement)                              #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    # Test de base
    salt = bytes([i for i in range(SALT_SIZE)])
    nonce = bytes([i for i in range(NONCE_SIZE)])
    ciphertext = b"Hello, World!"
    tag = bytes([i for i in range(TAG_SIZE)])

    # Test serialize
    packet = serialize(salt, nonce, ciphertext, tag)
    print(f"Paquet sérialisé : {len(packet)} octets")
    print(f"  Magic : {packet[:4]!r}")
    print(f"  Version : {packet[4]:02x}")
    print(f"  Salt : {packet[5:37].hex()[:16]}...")
    print(f"  Nonce : {packet[37:49].hex()}")
    print(f"  Ciphertext : {packet[49:-16]!r}")
    print(f"  Tag : {packet[-16:].hex()}")

    # Test parse
    parsed = parse(packet)
    print(f"\nParsé : {parsed}")
    print(f"  AAD : {parsed.aad.hex()[:32]}...")

    # Test inspect
    info = inspect(packet)
    print(f"\nInspect :")
    for k, v in info.items():
        if isinstance(v, str) and len(v) > 40:
            print(f"  {k}: {v[:40]}...")
        else:
            print(f"  {k}: {v}")

    # Test roundtrip
    assert parsed.to_bytes() == packet
    assert is_cgl1(packet)
    print("\n✅ Tous les tests passent !")