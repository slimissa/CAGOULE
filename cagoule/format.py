"""
format.py — Sérialisation / désérialisation CGL1 — CAGOULE v3.1.0
CTR v0x02 support added.

CORRECTIF (audit round 2, M6) : v0x03 (RAW, cipher_ctr_raw.py) ajouté à
SUPPORTED_VERSIONS.

CORRECTIF (ce passage d'audit) : le commentaire précédent affirmait que
"les pipelines de production (cipher_ctr_raw.py, cagoule_api.c) font
leur propre découpage d'octets et ne passent PAS par ce module" -- cette
affirmation est FAUSSE et l'était déjà au moment où le commentaire a été
écrit. Vérifié directement (grep) : cipher.py, cipher_ctr.py, ET
cipher_ctr_raw.py appellent tous les trois `_cgl1_format.serialize_from_aead`
ou `_cgl1_format.serialize_raw` pour assembler leur ciphertext final --
ce module EST sur le chemin critique de production pour les trois
pipelines Python (v0x01, v0x02, v0x03). Seul `cagoule_api.c` (couche C)
fait effectivement son propre assemblage indépendant, sans passer par ce
fichier Python.

Ce que ça implique concrètement : ce module n'est pas un simple
"module de RÉFÉRENCE DE SPEC" à faible enjeu -- un bug de sérialisation
ici corromprait silencieusement le ciphertext produit par tous les
appels Python de production (encrypt(), encrypt_ctr(), encrypt_ctr_raw()),
pas seulement les tests. Traiter ce fichier avec la même rigueur que les
pipelines qu'il sert, pas comme une référence annexe.

La spec elle-même reste correcte et inchangée : le format v0x03 n'a PAS
de champ nonce (Poly1305 seul, pas de ChaCha20) -- layout
MAGIC(4)|VERSION(1)|SALT(32)|CT(n)|TAG(16), overhead 53, contre
MAGIC(4)|VERSION(1)|SALT(32)|NONCE(12)|CT(n)|TAG(16), overhead 65 pour
v0x01/v0x02. Ajouter 0x03 à SUPPORTED_VERSIONS SANS rendre parse() aware
de cette différence de layout aurait fait mal-parser tout ciphertext
v0x03 réel silencieusement (12 octets de nonce inexistants pris dans le
ciphertext, 12 octets de CT+TAG réels perdus) -- pire que l'ancien
comportement (rejet explicite "Version non supportée").
"""
from __future__ import annotations
from dataclasses import dataclass

MAGIC           = b'CGL1'
MAGIC_HEX       = 0x43474C31
VERSION_BYTE    = 0x01
VERSION_CTR     = 0x02
VERSION_RAW     = 0x03
VERSION         = bytes([VERSION_BYTE])
MAGIC_SIZE      = 4
VERSION_SIZE    = 1
SALT_SIZE       = 32
NONCE_SIZE      = 12
TAG_SIZE        = 16
HEADER_SIZE     = MAGIC_SIZE + VERSION_SIZE + SALT_SIZE + NONCE_SIZE   # 49 (v0x01/v0x02, avec nonce)
OVERHEAD        = HEADER_SIZE + TAG_SIZE                                # 65 (v0x01/v0x02)
HEADER_SIZE_RAW = MAGIC_SIZE + VERSION_SIZE + SALT_SIZE                 # 37 (v0x03, PAS de nonce)
OVERHEAD_RAW    = HEADER_SIZE_RAW + TAG_SIZE                            # 53 (v0x03)

SUPPORTED_VERSIONS = {0x01, 0x02, 0x03}
# Versions dont le layout n'a PAS de champ nonce (Poly1305 seul, pas d'AEAD).
NONCELESS_VERSIONS = {0x03}


class CGL1FormatError(Exception):
    pass


@dataclass
class CGL1Packet:
    version: int
    salt: bytes
    ciphertext: bytes
    tag: bytes
    # None pour les versions NONCELESS_VERSIONS (v0x03) -- pas de champ
    # nonce dans ce layout. Champ déplacé en dernier avec défaut pour
    # rester compatible avec tout appelant existant utilisant des
    # kwargs (vérifié : seul parse() construit CGL1Packet, toujours en
    # kwargs, donc cet ordre de champs n'a pas d'effet sur l'existant).
    nonce: bytes | None = None

    def __post_init__(self):
        if len(self.salt) != SALT_SIZE:
            raise ValueError(f"salt={len(self.salt)}")
        if self.version in NONCELESS_VERSIONS:
            if self.nonce is not None:
                raise ValueError(
                    f"version 0x{self.version:02x} ne doit pas avoir de nonce "
                    f"(reçu {len(self.nonce)} octets)")
        else:
            if self.nonce is None or len(self.nonce) != NONCE_SIZE:
                got = "None" if self.nonce is None else len(self.nonce)
                raise ValueError(f"nonce={got}")
        if len(self.tag) != TAG_SIZE:
            raise ValueError(f"tag={len(self.tag)}")

    @property
    def aad(self):
        return MAGIC + bytes([self.version]) + self.salt

    @property
    def ciphertext_with_tag(self):
        return self.ciphertext + self.tag

    def to_bytes(self):
        if self.version in NONCELESS_VERSIONS:
            return MAGIC + bytes([self.version]) + self.salt + self.ciphertext + self.tag
        return MAGIC + bytes([self.version]) + self.salt + self.nonce + self.ciphertext + self.tag

    @classmethod
    def from_bytes(cls, data):
        return parse(data)

    def __repr__(self):
        return f"CGL1Packet(v=0x{self.version:02x}, ct_len={len(self.ciphertext)})"


def parse(data):
    if len(data) < MAGIC_SIZE + VERSION_SIZE:
        raise CGL1FormatError(f"Trop court pour lire la version: {len(data)}")
    if data[0:4] != MAGIC:
        raise CGL1FormatError(f"Magic invalide: {data[0:4]!r}")
    version = data[4]
    if version not in SUPPORTED_VERSIONS:
        raise CGL1FormatError(f"Version non supportée: {version}")

    if version in NONCELESS_VERSIONS:
        min_size = HEADER_SIZE_RAW + TAG_SIZE
        if len(data) < min_size:
            raise CGL1FormatError(f"Trop court: {len(data)}<{min_size}")
        salt = data[5:5 + SALT_SIZE]
        ct_tag = data[5 + SALT_SIZE:]
        if len(ct_tag) < TAG_SIZE:
            raise CGL1FormatError("CT+Tag trop court")
        return CGL1Packet(version=version, salt=salt, nonce=None,
                          ciphertext=ct_tag[:-TAG_SIZE], tag=ct_tag[-TAG_SIZE:])

    min_size = HEADER_SIZE + TAG_SIZE
    if len(data) < min_size:
        raise CGL1FormatError(f"Trop court: {len(data)}<{min_size}")
    salt = data[5:37]; nonce = data[37:49]; ct_tag = data[49:]
    if len(ct_tag) < TAG_SIZE:
        raise CGL1FormatError("CT+Tag trop court")
    return CGL1Packet(version=version, salt=salt, nonce=nonce,
                      ciphertext=ct_tag[:-TAG_SIZE], tag=ct_tag[-TAG_SIZE:])


def serialize(salt, nonce, ciphertext, tag, version=VERSION_BYTE):
    if version in NONCELESS_VERSIONS:
        raise CGL1FormatError(
            f"serialize() attend un nonce -- version 0x{version:02x} n'en a "
            f"pas dans son layout, utiliser serialize_raw()")
    if len(salt) != SALT_SIZE:   raise CGL1FormatError(f"Salt invalide: {len(salt)}")
    if len(nonce) != NONCE_SIZE: raise CGL1FormatError(f"Nonce invalide: {len(nonce)}")
    if len(tag) != TAG_SIZE:     raise CGL1FormatError(f"Tag invalide: {len(tag)}")
    return MAGIC + bytes([version]) + salt + nonce + ciphertext + tag


def serialize_raw(salt, ciphertext, tag, version=VERSION_RAW):
    """Sérialisation v0x03 (RAW, cipher_ctr_raw.py) -- pas de champ nonce."""
    if version not in NONCELESS_VERSIONS:
        raise CGL1FormatError(
            f"serialize_raw() est pour les versions sans nonce, pas 0x{version:02x}")
    if len(salt) != SALT_SIZE: raise CGL1FormatError(f"Salt invalide: {len(salt)}")
    if len(tag) != TAG_SIZE:   raise CGL1FormatError(f"Tag invalide: {len(tag)}")
    return MAGIC + bytes([version]) + salt + ciphertext + tag


def serialize_from_aead(salt, nonce, ciphertext_with_tag, version=VERSION_BYTE):
    if len(ciphertext_with_tag) < TAG_SIZE:
        raise CGL1FormatError("CT+Tag trop court")
    return serialize(salt, nonce, ciphertext_with_tag[:-TAG_SIZE],
                     ciphertext_with_tag[-TAG_SIZE:], version)


def inspect(data):
    pkt = parse(data)
    d = {"magic": MAGIC.decode('ascii'), "magic_hex": f"0x{MAGIC_HEX:08x}",
         "version": f"0x{pkt.version:02x}", "salt_hex": pkt.salt.hex(),
         "salt_len": len(pkt.salt),
         "ciphertext_len": len(pkt.ciphertext),
         "tag_hex": pkt.tag.hex(), "tag_len": len(pkt.tag),
         "total_size": len(data),
         "overhead": OVERHEAD_RAW if pkt.version in NONCELESS_VERSIONS else OVERHEAD,
         "aad_hex": pkt.aad.hex(), "aad_size": len(pkt.aad)}
    if pkt.nonce is not None:
        d["nonce_hex"] = pkt.nonce.hex()
        d["nonce_len"] = len(pkt.nonce)
    else:
        d["nonce_hex"] = None
        d["nonce_len"] = 0
    return d


def overhead(version=VERSION_BYTE):
    return OVERHEAD_RAW if version in NONCELESS_VERSIONS else OVERHEAD


def is_cgl1(data):
    try:
        parse(data)
        return True
    except CGL1FormatError:
        return False
