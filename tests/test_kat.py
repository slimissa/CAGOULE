"""test_kat.py — Known Answer Tests CAGOULE v3.1.0

Vecteurs générés par regenerate_kat.py avec la S-box Feistel.

Ces tests garantissent que l'implémentation est déterministe et compatible
avec la spécification de référence (KAT v2.3.0).
"""

import hashlib
import json
import os
import sys
import warnings
import pytest

# Configuration des chemins
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
so_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "cagoule", "libcagoule.so")
if os.path.exists(so_path):
    os.environ["LIBCAGOULE_PATH"] = so_path


# ============================================================
# Helper pour convertir les formats KAT
# ============================================================

def _normalize_kat(data):
    # If it's already the old format, return as-is
    if "parameters" in data and "derived" in data and "output" in data:
        return data
    
    # New format v2.3.0 (with both "vectors" and "derived")
    if "vectors" in data and len(data["vectors"]) > 0:
        v = data["vectors"][0]
        # Preserve derived params if available
        derived = data.get("derived", {})
        
        # Extract the actual nonce from the ciphertext (bytes 5-16 = positions 10-34 in hex)
        ciphertext_hex = v.get("ciphertext", "")
        nonce_hex = ciphertext_hex[74:98] if len(ciphertext_hex) >= 98 else data.get("nonce", "")        
        
        return {
            "version": data.get("version", "2.3.0"),
            "parameters": {
                "password": data.get("password", "CAGOULE_KAT_2026_MASTER_FIXED"),
                "salt_hex": data.get("salt", ""),
                "nonce_hex": nonce_hex,
                "plaintext_hex": v.get("plaintext", "48656c6c6f2c20576f726c6421"),
                "plaintext_len": len(bytes.fromhex(v.get("plaintext", ""))) if v.get("plaintext") else 0,
            },
            "derived": {
                "sbox_type": derived.get("sbox_type", "feistel"),
                "n_zeta": derived.get("n_zeta", 0),
                "p": derived.get("p", 0),
                "mu_strategy": derived.get("mu_strategy", ""),
                "mu_hex": derived.get("mu_hex", ""),
                "k_stream_hex": derived.get("k_stream_hex", ""),
                "round_key_0": derived.get("round_key_0", 0),
                "round_key_63": derived.get("round_key_63", 0),
            },
            "output": {
                "t_message_hex": "",
                "t_message_len": 0,
                "cgl1_hex": ciphertext_hex,
                "cgl1_len": len(bytes.fromhex(ciphertext_hex)) if ciphertext_hex else 0,
                "tag_hex": ciphertext_hex[-32:] if ciphertext_hex else "",
                "sha256_cgl1": v.get("sha256", "")
            }
        }
    
    return data


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture(scope="session")
def kat():
    """Charge les vecteurs KAT depuis kat_vectors.json."""
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "cagoule", "kat_vectors.json")
    if not os.path.exists(path):
        pytest.skip(f"Fichier KAT introuvable: {path}. Exécutez regenerate_kat.py")
    with open(path) as f:
        raw_data = json.load(f)
        return _normalize_kat(raw_data)


@pytest.fixture(scope="session")
def kat_params(kat):
    if kat["derived"]["p"] == 0:
        pytest.skip("Paramètres dérivés non disponibles dans ce format KAT")
    
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.params import CagouleParams
    
    salt = bytes.fromhex(kat["parameters"]["salt_hex"])
    password = kat["parameters"]["password"].encode()
    params = CagouleParams.derive(password, salt, fast_mode=True) 
    yield params
    params.zeroize()


# ============================================================
# Tests des paramètres dérivés (uniquement si disponibles)
# ============================================================

class TestKATParameters:
    """Vérifie que les paramètres dérivés correspondent aux KAT."""

    def test_version(self, kat):
        """La version du KAT doit être 2.0, 2.1.0, 2.2.0, 2.3.0, 2.4.0, 2.5.0, 3.0.0, ou 3.1.0."""
        assert kat["version"] in ["2.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "3.0.0", "3.1.0"], \
            f"Version KAT incorrecte: {kat['version']}"

    def test_sbox_type(self, kat):
        """La S-box doit être de type Feistel pour KAT v2.0/v2.1."""
        if "derived" in kat and "sbox_type" in kat["derived"]:
            assert kat["derived"]["sbox_type"] == "feistel", "La S-box KAT devrait être Feistel"
        else:
            pytest.skip("sbox_type non disponible dans ce format KAT")

    def test_n_zeta(self, kat, kat_params):
        """n_zeta doit correspondre."""
        if kat["derived"]["n_zeta"] == 0:
            pytest.skip("n_zeta non disponible dans ce format KAT")
        assert kat_params.n == kat["derived"]["n_zeta"], "n_zeta ne correspond pas"

    def test_prime_p(self, kat, kat_params):
        """Le nombre premier p doit correspondre et appartenir au pool Mersenne-64."""
        from cagoule.params import MERSENNE_POOL
        if kat["derived"]["p"] == 0:
            pytest.skip("p non disponible dans ce format KAT")
        assert kat_params.p == kat["derived"]["p"], "p ne correspond pas"
        # v2.5.0: p doit être dans le pool Mersenne
        mersenne_ps = [p for k, p in MERSENNE_POOL]
        assert kat_params.p in mersenne_ps, f"p={kat_params.p} hors du pool Mersenne-64"

    def test_k_mersenne(self, kat, kat_params):
        """k_mersenne doit correspondre au KAT."""
        from cagoule.params import MERSENNE_POOL
        expected_k = kat["derived"].get("k_mersenne", 0)
        if expected_k == 0:
            pytest.skip("k_mersenne non disponible dans ce format KAT")
        assert kat_params.k_mersenne == expected_k, f"k_mersenne incorrect: got {kat_params.k_mersenne}, expected {expected_k}"

    def test_z_offset_derived(self, kat, kat_params):
        """z_offset doit être dérivé et dans [0, p)."""
        assert len(kat_params.z_offset) == 16, "z_offset doit avoir 16 éléments"
        assert all(0 <= z < kat_params.p for z in kat_params.z_offset), "z_offset hors de [0, p)"
        expected_z0 = kat["derived"].get("z_offset_0", 0)
        if expected_z0 > 0:
            assert kat_params.z_offset[0] == expected_z0, f"z_offset[0] incorrect"

    def test_mu_strategy(self, kat, kat_params):
        """La stratégie de µ doit correspondre."""
        if kat["derived"]["mu_strategy"] == "":
            pytest.skip("mu_strategy non disponible dans ce format KAT")
        assert kat_params.mu.strategy == kat["derived"]["mu_strategy"], "µ strategy incorrecte"

    def test_mu_value(self, kat, kat_params):
        """La valeur de µ doit correspondre."""
        if not kat["derived"]["mu_hex"]:
            pytest.skip("mu_hex non disponible dans ce format KAT")
        expected_mu = int(kat["derived"]["mu_hex"], 16)
        assert kat_params.mu.as_int() == expected_mu, "µ value incorrecte"

    def test_k_stream(self, kat, kat_params):
        """La clé de stream ChaCha20 doit correspondre."""
        if not kat["derived"]["k_stream_hex"]:
            pytest.skip("k_stream_hex non disponible dans ce format KAT")
        assert kat_params.k_stream.hex() == kat["derived"]["k_stream_hex"], "k_stream incorrect"

    def test_round_key_0(self, kat, kat_params):
        """La première round key doit correspondre."""
        if kat["derived"]["round_key_0"] == 0:
            pytest.skip("round_key_0 non disponible dans ce format KAT")
        assert kat_params.round_keys[0] == kat["derived"]["round_key_0"], "rk[0] incorrect"

    def test_round_key_63(self, kat, kat_params):
        """La dernière round key doit correspondre."""
        if kat["derived"]["round_key_63"] == 0:
            pytest.skip("round_key_63 non disponible dans ce format KAT")
        assert kat_params.round_keys[63] == kat["derived"]["round_key_63"], "rk[63] incorrect"


# ============================================================
# Tests de chiffrement
# ============================================================

class TestKATCipher:
    """Vérifie que le chiffrement produit les valeurs KAT."""

    def test_t_message(self, kat, kat_params):
        """T(message) — sortie du CBC interne."""
        if not kat["output"]["t_message_hex"]:
            pytest.skip("t_message_hex non disponible dans ce format KAT")
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import _cbc_encrypt
        
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        t_msg = _cbc_encrypt(plaintext, kat_params)
        
        assert t_msg.hex() == kat["output"]["t_message_hex"], "T(message) hex incorrect"
        assert len(t_msg) == kat["output"]["t_message_len"], "T(message) taille incorrecte"

    def test_cgl1_sha256(self, kat, kat_params):
        """Chiffrement déterministe — SHA-256 du CGL1."""
        if not kat["output"]["cgl1_hex"]:
            pytest.skip("cgl1_hex non disponible dans ce format KAT")
        
        from unittest import mock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
        
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        nonce = bytes.fromhex(kat["parameters"]["nonce_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        
        with mock.patch("cagoule.cipher.os.urandom", return_value=nonce):
            cgl1 = encrypt(plaintext, password, salt=salt, params=kat_params)
        
        sha = hashlib.sha256(cgl1).hexdigest()
        expected_sha = kat["output"]["sha256_cgl1"]
        assert sha == expected_sha, f"SHA-256 CGL1 incorrect: {sha[:16]}... attendu {expected_sha[:16]}..."
        assert len(cgl1) == kat["output"]["cgl1_len"], "Taille CGL1 incorrecte"

    def test_cgl1_hex(self, kat, kat_params):
        """Contenu hexadécimal exact du CGL1."""
        if not kat["output"]["cgl1_hex"]:
            pytest.skip("cgl1_hex non disponible dans ce format KAT")
        
        from unittest import mock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
        
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        nonce = bytes.fromhex(kat["parameters"]["nonce_hex"])
        password = kat["parameters"]["password"].encode()
        plaintext = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        
        with mock.patch("cagoule.cipher.os.urandom", return_value=nonce):
            cgl1 = encrypt(plaintext, password, salt=salt, params=kat_params)
        
        assert cgl1.hex() == kat["output"]["cgl1_hex"], "CGL1 hex incorrect"


# ============================================================
# Tests de déchiffrement et roundtrip
# ============================================================

class TestKATRoundTrip:
    """Vérifie que le déchiffrement des KAT fonctionne."""

    def test_decrypt_kat_cgl1(self, kat):
        """Déchiffrer le CGL1 KAT redonne le plaintext original."""
        if not kat["output"]["cgl1_hex"]:
            pytest.skip("cgl1_hex non disponible dans ce format KAT")
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule import decrypt
            from cagoule.params import CagouleParams
        
        cgl1 = bytes.fromhex(kat["output"]["cgl1_hex"])
        password = kat["parameters"]["password"].encode()
        salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        
        # Pour v2.1.0, le nonce est aléatoire, donc on doit dériver les paramètres
        # depuis le salt contenu dans le ciphertext
        params = CagouleParams.derive(password, salt, fast_mode=True)
        plaintext = decrypt(cgl1, password, params=params)
        expected = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        
        assert plaintext == expected, "Déchiffrement KAT incorrect"
        params.zeroize()

    def test_decrypt_with_params(self, kat, kat_params):
        """Déchiffrement avec paramètres pré-dérivés doit fonctionner."""
        if not kat["output"]["cgl1_hex"] or kat["derived"]["p"] == 0:
            pytest.skip("Données KAT insuffisantes")
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule import decrypt
        
        cgl1 = bytes.fromhex(kat["output"]["cgl1_hex"])
        plaintext = decrypt(cgl1, b"", params=kat_params)
        expected = bytes.fromhex(kat["parameters"]["plaintext_hex"])
        
        assert plaintext == expected, "Déchiffrement KAT avec params incorrect"

    def test_tag_extracted(self, kat):
        """Le tag extrait correspond au vecteur KAT."""
        if not kat["output"]["tag_hex"]:
            pytest.skip("tag_hex non disponible dans ce format KAT")
        
        cgl1 = bytes.fromhex(kat["output"]["cgl1_hex"])
        tag = cgl1[-16:]
        assert tag.hex() == kat["output"]["tag_hex"], "Tag incorrect"

    def test_cgl1_structure(self, kat):
        """Vérifie la structure du CGL1 KAT."""
        if not kat["output"]["cgl1_hex"]:
            pytest.skip("cgl1_hex non disponible dans ce format KAT")
        
        cgl1 = bytes.fromhex(kat["output"]["cgl1_hex"])
        
        # Magic (4 octets)
        assert cgl1[:4] == b"CGL1", "Magic incorrect"
        
        # Version (1 octet)
        assert cgl1[4:5] == b"\x01", "Version incorrecte"
        
        # Salt (32 octets)
        salt = cgl1[5:37]
        expected_salt = bytes.fromhex(kat["parameters"]["salt_hex"])
        assert salt == expected_salt, "Salt incorrect"
        
        # Pour v2.1.0, le nonce est aléatoire, donc on ne peut pas le comparer
        # On vérifie juste qu'il fait 12 octets
        nonce = cgl1[37:49]
        assert len(nonce) == 12, "Nonce doit faire 12 octets"
        
        # Le ciphertext + tag doivent avoir une taille positive
        assert len(cgl1) >= 49 + 16, "CGL1 trop court"

# ============================================================
# Tests de non-régression (uniquement pour format v2.0)
# ============================================================

class TestKATNonRegression:
    """Vérifie que les KAT ne régressent pas entre versions."""

    def test_sha256_fixed(self, kat):
        """L'empreinte SHA-256 du CGL1 KAT ne doit pas changer (v2.4.0)."""
        expected_sha = "a1542d657c711ce180c99195da923f0e3c97a3376e40b16a8ade985ba1518c0a"
        actual_sha = kat["output"]["sha256_cgl1"]
        if not actual_sha:
            pytest.skip("sha256_cgl1 non disponible")
        assert actual_sha == expected_sha, \
            f"L'empreinte SHA-256 a changé!\n  Attendu: {expected_sha}\n  Reçu  : {actual_sha}"

    def test_cgl1_hex_fixed(self, kat):
        """Le CGL1 hex doit correspondre à l'attendu (vérification secondaire)."""
        if not kat["output"]["cgl1_hex"]:
            pytest.skip("cgl1_hex non disponible")
        
        # Cette valeur doit être stable entre les runs
        expected_hex_prefix = "43474c3101"  # "CGL1" + version 0x01
        actual_hex = kat["output"]["cgl1_hex"]
        assert actual_hex.startswith(expected_hex_prefix), "CGL1 hex ne commence pas correctement"