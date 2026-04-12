"""
test_kat.py — Known Answer Tests (KAT) pour CAGOULE v1.1

Vérifie que l'implémentation produit exactement les vecteurs de référence
enregistrés dans kat_vectors.json.
Ces tests doivent PASSER sans modification entre versions mineures.
"""
import hashlib
import pytest


class TestKATParameters:
    """Vérifie que les paramètres dérivés correspondent aux valeurs KAT."""

    def test_kat_version(self, kat):
        assert kat["version"] == "1.5"

    def test_kat_n_zeta(self, kat):
        """n_zeta dérivé = 63237."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.n == kat["derived"]["n_zeta"]

    def test_kat_prime_p(self, kat):
        """p dérivé = 13226797537736071951."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.p == kat["derived"]["p"]

    def test_kat_mu_strategy(self, kat):
        """µ trouvé dans Z/pZ (stratégie A)."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.mu.strategy == kat["derived"]["mu_strategy"]

    def test_kat_mu_value(self, kat):
        """Valeur exacte de µ."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        expected_mu = int(kat["derived"]["mu_hex"], 16)
        assert params.mu.as_int() == expected_mu

    def test_kat_k_stream(self, kat):
        """K_stream (clé ChaCha20) correspond au vecteur."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.k_stream.hex() == kat["derived"]["k_stream_hex"]

    def test_kat_round_key_0(self, kat):
        """Première round key."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.round_keys[0] == kat["derived"]["round_key_0"]

    def test_kat_round_key_63(self, kat):
        """Dernière round key (index 63)."""
        from cagoule.params import CagouleParams
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        params = CagouleParams.derive(password, salt, fast_mode=False)
        assert params.round_keys[63] == kat["derived"]["round_key_63"]


class TestKATCipher:
    """Vérifie que le chiffrement produit exactement le vecteur de sortie."""

    def test_kat_t_message(self, kat):
        """T(message) — sortie du CBC interne — correspond au vecteur."""
        from cagoule.params import CagouleParams
        from cagoule.cipher import _cbc_encrypt
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        params = CagouleParams.derive(password, salt, fast_mode=False)
        t_msg = _cbc_encrypt(plaintext, params)
        assert t_msg.hex() == kat["output"]["t_message_hex"]
        assert len(t_msg) == kat["output"]["t_message_len"]

    def test_kat_full_cgl1_sha256(self, kat):
        """
        Chiffrement déterministe avec nonce fixe → SHA-256 du CGL1 doit correspondre.
        On utilise encrypt_with_params + un nonce fixe via monkeypatching de os.urandom.
        """
        import unittest.mock as mock
        from cagoule.params import CagouleParams
        from cagoule.cipher import encrypt

        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        nonce = bytes.fromhex(kat["parameters"]["nonce_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])

        params = CagouleParams.derive(password, salt, fast_mode=False)

        # Fixer le nonce aléatoire
        with mock.patch("cagoule.cipher.os.urandom", return_value=nonce):
            cgl1 = encrypt(plaintext, password, salt=salt, params=params)

        sha = hashlib.sha256(cgl1).hexdigest()
        assert sha == kat["output"]["sha256_cgl1"]
        assert len(cgl1) == kat["output"]["cgl1_len"]

    def test_kat_cgl1_hex(self, kat):
        """Vérifie le contenu hexadécimal complet du CGL1."""
        import unittest.mock as mock
        from cagoule.params import CagouleParams
        from cagoule.cipher import encrypt

        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        nonce = bytes.fromhex(kat["parameters"]["nonce_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        params = CagouleParams.derive(password, salt, fast_mode=False)

        with mock.patch("cagoule.cipher.os.urandom", return_value=nonce):
            cgl1 = encrypt(plaintext, password, salt=salt, params=params)

        assert cgl1.hex() == kat["output"]["cgl1_hex"]


class TestKATRoundTrip:
    """Vérifie que déchiffrer le CGL1 KAT redonne le plaintext original."""

    def test_decrypt_kat_cgl1(self, kat):
        from cagoule import decrypt
        cgl1 = bytes.fromhex(kat["output"]["cgl1_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = decrypt(cgl1, password)
        expected = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        assert plaintext == expected
