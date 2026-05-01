"""
format.py — Sérialisation / désérialisation CGL1 — CAGOULE v2.0.0
Identique à v1.x.
"""
from __future__ import annotations
from dataclasses import dataclass

MAGIC           = b'CGL1'
MAGIC_HEX       = 0x43474C31
VERSION_BYTE    = 0x01
VERSION         = bytes([VERSION_BYTE])
MAGIC_SIZE      = 4
VERSION_SIZE    = 1
SALT_SIZE       = 32
NONCE_SIZE      = 12
TAG_SIZE        = 16
HEADER_SIZE     = MAGIC_SIZE + VERSION_SIZE + SALT_SIZE + NONCE_SIZE   # 49
OVERHEAD        = HEADER_SIZE + TAG_SIZE                                # 65
SUPPORTED_VERSIONS = {0x01}

class CGL1FormatError(Exception):
    pass

@dataclass
class CGL1Packet:
    version: int; salt: bytes; nonce: bytes; ciphertext: bytes; tag: bytes
    def __post_init__(self):
        if len(self.salt)!=SALT_SIZE:   raise ValueError(f"salt={len(self.salt)}")
        if len(self.nonce)!=NONCE_SIZE: raise ValueError(f"nonce={len(self.nonce)}")
        if len(self.tag)!=TAG_SIZE:     raise ValueError(f"tag={len(self.tag)}")
    @property
    def aad(self): return MAGIC+bytes([self.version])+self.salt
    @property
    def ciphertext_with_tag(self): return self.ciphertext+self.tag
    def to_bytes(self): return MAGIC+bytes([self.version])+self.salt+self.nonce+self.ciphertext+self.tag
    @classmethod
    def from_bytes(cls, data): return parse(data)
    def __repr__(self): return f"CGL1Packet(v=0x{self.version:02x}, ct_len={len(self.ciphertext)})"

def parse(data):
    min_size = HEADER_SIZE+TAG_SIZE
    if len(data)<min_size: raise CGL1FormatError(f"Trop court: {len(data)}<{min_size}")
    if data[0:4]!=MAGIC: raise CGL1FormatError(f"Magic invalide: {data[0:4]!r}")
    version=data[4]
    if version not in SUPPORTED_VERSIONS: raise CGL1FormatError(f"Version non supportée: {version}")
    salt=data[5:37]; nonce=data[37:49]; ct_tag=data[49:]
    if len(ct_tag)<TAG_SIZE: raise CGL1FormatError("CT+Tag trop court")
    return CGL1Packet(version=version, salt=salt, nonce=nonce,
                      ciphertext=ct_tag[:-TAG_SIZE], tag=ct_tag[-TAG_SIZE:])

def serialize(salt, nonce, ciphertext, tag, version=VERSION_BYTE):
    if len(salt)!=SALT_SIZE:   raise CGL1FormatError(f"Salt invalide: {len(salt)}")
    if len(nonce)!=NONCE_SIZE: raise CGL1FormatError(f"Nonce invalide: {len(nonce)}")
    if len(tag)!=TAG_SIZE:     raise CGL1FormatError(f"Tag invalide: {len(tag)}")
    return MAGIC+bytes([version])+salt+nonce+ciphertext+tag

def serialize_from_aead(salt, nonce, ciphertext_with_tag, version=VERSION_BYTE):
    if len(ciphertext_with_tag)<TAG_SIZE: raise CGL1FormatError("CT+Tag trop court")
    return serialize(salt, nonce, ciphertext_with_tag[:-TAG_SIZE], ciphertext_with_tag[-TAG_SIZE:], version)

def inspect(data):
    pkt=parse(data)
    return {"magic": MAGIC.decode('ascii'), "magic_hex": f"0x{MAGIC_HEX:08x}",
            "version": f"0x{pkt.version:02x}", "salt_hex": pkt.salt.hex(),
            "salt_len": len(pkt.salt), "nonce_hex": pkt.nonce.hex(),
            "nonce_len": len(pkt.nonce), "ciphertext_len": len(pkt.ciphertext),
            "tag_hex": pkt.tag.hex(), "tag_len": len(pkt.tag),
            "total_size": len(data), "overhead": OVERHEAD,
            "aad_hex": pkt.aad.hex(), "aad_size": len(pkt.aad)}

def overhead(): return OVERHEAD

def is_cgl1(data):
    try: parse(data); return True
    except CGL1FormatError: return False
