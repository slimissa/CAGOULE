"""test_format.py — Tests parsing/sérialisation CGL1 — CAGOULE v2.0.0"""

import os
import pytest
import warnings

from cagoule.format import (
    parse, serialize, serialize_from_aead, inspect, is_cgl1,
    OVERHEAD, MAGIC, SALT_SIZE, NONCE_SIZE, TAG_SIZE, HEADER_SIZE,
    CGL1FormatError, CGL1Packet,
)


# ============================================================
# Helpers
# ============================================================

def make_packet(ct=b"hello"):
    """Génère un paquet CGL1 valide avec des valeurs déterministes."""
    salt = bytes(range(SALT_SIZE))
    nonce = bytes(range(NONCE_SIZE))
    tag = bytes(range(TAG_SIZE))
    raw = serialize(salt, nonce, ct, tag)
    return raw, salt, nonce, ct, tag


# Paquet de référence pour les tests
_RAW = make_packet(b"data" * 5)[0]


# ============================================================
# Tests de sérialisation
# ============================================================

class TestSerialize:
    def test_magic(self):
        """Le magic doit être 'CGL1'."""
        assert make_packet()[0][:4] == MAGIC

    def test_version(self):
        """La version doit être 0x01."""
        assert make_packet()[0][4:5] == b"\x01"

    def test_taille(self):
        """La taille totale doit être OVERHEAD + len(ciphertext)."""
        ct = b"X" * 42
        assert len(make_packet(ct)[0]) == OVERHEAD + 42

    def test_salt_invalide(self):
        """Un salt de mauvaise taille doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            serialize(b"trop_court", bytes(NONCE_SIZE), b"ct", bytes(TAG_SIZE))

    def test_nonce_invalide(self):
        """Un nonce de mauvaise taille doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            serialize(bytes(SALT_SIZE), b"bad", b"ct", bytes(TAG_SIZE))

    def test_tag_invalide(self):
        """Un tag de mauvaise taille doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            serialize(bytes(SALT_SIZE), bytes(NONCE_SIZE), b"ct", b"short")


# ============================================================
# Tests de parsing
# ============================================================

class TestParse:
    def test_roundtrip(self):
        """Sérialisation → parsing doit restituer les données originales."""
        ct = b"payload data"
        raw, salt, nonce, _, tag = make_packet(ct)
        pkt = parse(raw)
        assert pkt.salt == salt
        assert pkt.nonce == nonce
        assert pkt.ciphertext == ct
        assert pkt.tag == tag

    def test_magic_invalide(self):
        """Un magic incorrect doit lever une exception."""
        raw = make_packet()[0]
        with pytest.raises(CGL1FormatError):
            parse(b"XXXX" + raw[4:])

    def test_version_non_supportee(self):
        """Une version non supportée doit lever une exception."""
        raw = make_packet()[0]
        # Modifier l'octet de version (position 4)
        raw = raw[:4] + b'\xff' + raw[5:]
        with pytest.raises(CGL1FormatError):
            parse(raw)

    def test_trop_court(self):
        """Un paquet trop court doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            parse(b"CGL1\x01" + b"\x00" * 10)

    def test_to_bytes_roundtrip(self):
        """to_bytes() doit reconstruire le paquet original."""
        raw = make_packet(b"round trip test")[0]
        assert parse(raw).to_bytes() == raw

    def test_from_bytes_alias(self):
        """from_bytes() doit être un alias de parse()."""
        raw = make_packet()[0]
        assert CGL1Packet.from_bytes(raw).version == 1

    def test_aad_magic(self):
        """L'AAD doit commencer par le magic."""
        assert parse(_RAW).aad[:4] == MAGIC


# ============================================================
# Tests d'inspection
# ============================================================

class TestInspect:
    def test_champs_presents(self):
        """inspect() doit retourner tous les champs attendus."""
        raw = make_packet(b"test payload")[0]
        info = inspect(raw)
        assert info["magic"] == "CGL1"
        assert info["overhead"] == OVERHEAD
        assert info["ciphertext_len"] == 12  # "test payload" fait 12 octets
        assert "salt_hex" in info
        assert "tag_hex" in info
        assert "nonce_hex" in info
        assert "version" in info
        assert "total_size" in info

    def test_inspect_invalide(self):
        """inspect() sur un paquet invalide doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            inspect(b"not a valid packet")

    def test_is_cgl1_vrai(self):
        """is_cgl1() doit retourner True pour un paquet valide."""
        assert is_cgl1(make_packet()[0])

    def test_is_cgl1_faux(self):
        """is_cgl1() doit retourner False pour un paquet invalide."""
        assert not is_cgl1(b"not a CGL1 packet")

    def test_is_cgl1_vide(self):
        """is_cgl1() doit retourner False pour un paquet vide."""
        assert not is_cgl1(b"")


# ============================================================
# Tests de CGL1Packet
# ============================================================

class TestCGL1Packet:
    def test_repr(self):
        """Le repr() doit contenir des informations utiles."""
        raw = make_packet()[0]
        pkt = parse(raw)
        repr_str = repr(pkt)
        assert "CGL1Packet" in repr_str
        assert "ct_len" in repr_str

    def test_properties(self):
        """Les propriétés aad et ciphertext_with_tag doivent être correctes."""
        raw, salt, nonce, ct, tag = make_packet(b"secret")
        pkt = parse(raw)
        assert pkt.aad == MAGIC + bytes([1]) + salt
        assert pkt.ciphertext_with_tag == ct + tag


# ============================================================
# Tests de serialize_from_aead
# ============================================================

class TestSerializeFromAEAD:
    def test_equivalent(self):
        """serialize_from_aead doit être équivalent à serialize."""
        ct = b"ciphertext"
        tag = bytes(TAG_SIZE)
        r1 = serialize(bytes(SALT_SIZE), bytes(NONCE_SIZE), ct, tag)
        r2 = serialize_from_aead(bytes(SALT_SIZE), bytes(NONCE_SIZE), ct + tag)
        assert r1 == r2

    def test_ct_tag_trop_court(self):
        """CT+Tag trop court doit lever une exception."""
        with pytest.raises(CGL1FormatError):
            serialize_from_aead(bytes(SALT_SIZE), bytes(NONCE_SIZE), b"short")


# ============================================================
# Tests des constantes
# ============================================================

class TestConstantes:
    def test_taille_coherentes(self):
        """Vérifie la cohérence des tailles."""
        assert HEADER_SIZE == 4 + 1 + 32 + 12  # MAGIC + VERSION + SALT + NONCE
        assert OVERHEAD == HEADER_SIZE + 16   # + TAG_SIZE
        assert SALT_SIZE == 32
        assert NONCE_SIZE == 12
        assert TAG_SIZE == 16