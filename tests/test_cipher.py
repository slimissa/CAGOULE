"""
test_cipher.py — Tests pour cipher.py et decipher.py

Couvre :
- Round-trip encrypt/decrypt
- PKCS7 padding/unpadding
- Authentification (mauvais mot de passe)
- Format CGL1 (magic, version, tailles)
- Cas limites (message vide, message long, binaire)
"""
import os
import pytest

# Mot de passe fixe pour tous les tests
TEST_PASSWORD = b"test_password_cagoule"


# ─── Tests PKCS7 ─────────────────────────────────────────────────────────────

class TestPKCS7:

    @pytest.mark.parametrize("length,block", [(0, 16), (1, 16), (15, 16), (16, 16), (17, 16)])
    def test_pad_aligne(self, length, block):
        from cagoule.cipher import pkcs7_pad
        data = b"A" * length
        padded = pkcs7_pad(data, block)
        assert len(padded) % block == 0
        assert len(padded) >= len(data)

    @pytest.mark.parametrize("length,block", [(0, 16), (1, 16), (15, 16), (16, 16), (31, 16)])
    def test_roundtrip_pad_unpad(self, length, block):
        from cagoule.cipher import pkcs7_pad, pkcs7_unpad
        data = os.urandom(length)
        assert pkcs7_unpad(pkcs7_pad(data, block), block) == data

    def test_unpad_invalide_leve_exception(self):
        from cagoule.cipher import pkcs7_unpad
        with pytest.raises(ValueError):
            pkcs7_unpad(b"\x00" * 16, 16)


# ─── Tests Round-trip ─────────────────────────────────────────────────────────

class TestEncryptDecrypt:

    def test_roundtrip_simple(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        # Utiliser le même mot de passe que fast_params
        ct = encrypt(b"Hello, World!", TEST_PASSWORD, params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD)
        assert pt == b"Hello, World!"

    def test_roundtrip_str_input(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        ct = encrypt("Bonjour monde", TEST_PASSWORD.decode(), params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD.decode())
        assert pt == b"Bonjour monde"

    def test_roundtrip_message_vide(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        ct = encrypt(b"", TEST_PASSWORD, params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD)
        assert pt == b""

    def test_roundtrip_message_long(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        msg = os.urandom(1024)
        ct = encrypt(msg, TEST_PASSWORD, params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD)
        assert pt == msg

    def test_roundtrip_binaire(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        msg = bytes(range(256))
        ct = encrypt(msg, TEST_PASSWORD, params=fast_params)
        assert decrypt(ct, TEST_PASSWORD) == msg

    def test_roundtrip_utf8(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        msg = "مرحبا بالعالم 🔐".encode("utf-8")
        ct = encrypt(msg, TEST_PASSWORD, params=fast_params)
        assert decrypt(ct, TEST_PASSWORD) == msg

    def test_mauvais_mot_de_passe(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt, CagouleAuthError
        ct = encrypt(b"secret", TEST_PASSWORD, params=fast_params)
        with pytest.raises(CagouleAuthError):
            decrypt(ct, b"wrong_password")

    def test_ciphertext_altere(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt, CagouleAuthError
        ct = bytearray(encrypt(b"secret", TEST_PASSWORD, params=fast_params))
        if len(ct) > 60:
            ct[60] ^= 0xFF
        with pytest.raises(CagouleAuthError):
            decrypt(bytes(ct), TEST_PASSWORD)

    def test_deux_chiffrements_differents(self, fast_params):
        from cagoule.cipher import encrypt
        msg = b"same message"
        ct1 = encrypt(msg, TEST_PASSWORD, params=fast_params)
        ct2 = encrypt(msg, TEST_PASSWORD, params=fast_params)
        assert ct1 != ct2

    @pytest.mark.parametrize("size", [1, 15, 16, 17, 63, 64, 65, 255, 256, 1024])
    def test_sizes(self, fast_params, size):
        from cagoule.cipher import encrypt
        from cagoule.decipher import decrypt
        msg = os.urandom(size)
        ct = encrypt(msg, TEST_PASSWORD, params=fast_params)
        assert decrypt(ct, TEST_PASSWORD) == msg


# ─── Tests du format CGL1 ─────────────────────────────────────────────────────

class TestCGL1Format:

    def test_magic(self, fast_params):
        from cagoule.cipher import encrypt
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        assert ct[:4] == b"CGL1"

    def test_version(self, fast_params):
        from cagoule.cipher import encrypt
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        assert ct[4:5] == b"\x01"

    def test_taille_minimale(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.format import OVERHEAD
        ct = encrypt(b"", TEST_PASSWORD, params=fast_params)
        assert len(ct) >= OVERHEAD

    def test_format_parse(self, fast_params):
        from cagoule.cipher import encrypt
        from cagoule.format import parse, is_cgl1
        ct = encrypt(b"hello", TEST_PASSWORD, params=fast_params)
        assert is_cgl1(ct)
        pkt = parse(ct)
        assert len(pkt.salt) == 32
        assert len(pkt.nonce) == 12
        assert len(pkt.tag) == 16

    def test_format_invalide_leve_exception(self):
        from cagoule.decipher import decrypt, CagouleFormatError
        with pytest.raises(CagouleFormatError):
            decrypt(b"not a valid CGL1 packet at all", TEST_PASSWORD)