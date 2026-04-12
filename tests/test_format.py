"""
test_format.py — Tests pour format.py (parsing/sérialisation CGL1)
"""
import pytest
from cagoule.format import (
    parse, serialize, serialize_from_aead, inspect, is_cgl1,
    OVERHEAD, MAGIC, SALT_SIZE, NONCE_SIZE, TAG_SIZE, CGL1FormatError,
)


def make_packet(ct=b"hello"):
    salt  = bytes(range(SALT_SIZE))
    nonce = bytes(range(NONCE_SIZE))
    tag   = bytes(range(TAG_SIZE))
    return serialize(salt, nonce, ct, tag), salt, nonce, ct, tag


class TestSerialize:

    def test_magic_present(self):
        raw, *_ = make_packet()
        assert raw[:4] == MAGIC

    def test_version_present(self):
        raw, *_ = make_packet()
        assert raw[4:5] == b"\x01"

    def test_taille_totale(self):
        ct = b"X" * 42
        raw, *_ = make_packet(ct)
        assert len(raw) == OVERHEAD + len(ct)

    def test_salt_invalide(self):
        with pytest.raises(CGL1FormatError):
            serialize(b"too_short", bytes(NONCE_SIZE), b"ct", bytes(TAG_SIZE))

    def test_nonce_invalide(self):
        with pytest.raises(CGL1FormatError):
            serialize(bytes(SALT_SIZE), b"bad", b"ct", bytes(TAG_SIZE))

    def test_tag_invalide(self):
        with pytest.raises(CGL1FormatError):
            serialize(bytes(SALT_SIZE), bytes(NONCE_SIZE), b"ct", b"short")


class TestParse:

    def test_roundtrip(self):
        ct = b"payload data"
        raw, salt, nonce, _, tag = make_packet(ct)
        pkt = parse(raw)
        assert pkt.salt == salt
        assert pkt.nonce == nonce
        assert pkt.ciphertext == ct
        assert pkt.tag == tag

    def test_magic_invalide(self):
        raw, *_ = make_packet()
        bad = b"XXXX" + raw[4:]
        with pytest.raises(CGL1FormatError):
            parse(bad)

    def test_trop_court(self):
        with pytest.raises(CGL1FormatError):
            parse(b"CGL1\x01" + b"\x00" * 10)

    def test_to_bytes_roundtrip(self):
        raw, *_ = make_packet(b"round trip test")
        pkt = parse(raw)
        assert pkt.to_bytes() == raw

    def test_from_bytes_alias(self):
        raw, *_ = make_packet()
        from cagoule.format import CGL1Packet
        pkt = CGL1Packet.from_bytes(raw)
        assert pkt.version == 1


class TestInspect:

    def test_champs_presents(self):
        raw, *_ = make_packet(b"test payload")
        info = inspect(raw)
        assert info["magic"] == "CGL1"
        assert info["overhead"] == OVERHEAD
        assert info["ciphertext_len"] == 12  # len("test payload")
        assert "salt_hex" in info
        assert "tag_hex" in info

    def test_is_cgl1_vrai(self):
        raw, *_ = make_packet()
        assert is_cgl1(raw)

    def test_is_cgl1_faux(self):
        assert not is_cgl1(b"not a CGL1 packet")
        assert not is_cgl1(b"")


class TestSerializeFromAEAD:

    def test_equivalent_serialize(self):
        ct = b"ciphertext"
        tag = bytes(TAG_SIZE)
        ct_with_tag = ct + tag
        raw1 = serialize(bytes(SALT_SIZE), bytes(NONCE_SIZE), ct, tag)
        raw2 = serialize_from_aead(bytes(SALT_SIZE), bytes(NONCE_SIZE), ct_with_tag)
        assert raw1 == raw2
