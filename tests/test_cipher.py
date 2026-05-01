"""
test_cipher.py — Tests cipher/decipher CAGOULE v2.1.0

Changements v2.1.0 :
  - test_mauvais_mdp : xfail supprimé — le test passe désormais (fix decipher.py)
  - test_mauvais_mdp_sans_params : nouveau — vérifie sans params= aussi
  - test_auth_error_enrichi : vérifie les nouveaux attributs CagouleAuthError
  - test_format_error_enrichi : vérifie les nouveaux attributs CagouleFormatError
  - test_fast_mode_stored : vérifie que CagouleParams.fast_mode est mémorisé
"""

import os
import sys
import warnings
import time

import pytest

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    so_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "cagoule", "libcagoule.so")
    if os.path.exists(so_path):
        os.environ["LIBCAGOULE_PATH"] = so_path

TEST_PASSWORD = b"test_password_cagoule_v2"


@pytest.fixture(scope="session")
def fast_params():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.params import CagouleParams
    params = CagouleParams.derive(TEST_PASSWORD, fast_mode=True)
    yield params
    params.zeroize()


@pytest.fixture(scope="session")
def normal_params():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.params import CagouleParams
    params = CagouleParams.derive(TEST_PASSWORD, fast_mode=False)
    yield params
    params.zeroize()


# ══════════════════════════════════════════════════════════════════════════
#  Tests de base — roundtrip
# ══════════════════════════════════════════════════════════════════════════

class TestRoundtrip:

    def test_roundtrip_simple(self, fast_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        ct = encrypt(b"Hello CAGOULE v2!", TEST_PASSWORD, params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD, params=fast_params)
        assert pt == b"Hello CAGOULE v2!"

    def test_roundtrip_vide(self, fast_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        ct = encrypt(b"", TEST_PASSWORD, params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD, params=fast_params)
        assert pt == b""

    def test_roundtrip_str(self, fast_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        ct = encrypt("Bonjour monde", TEST_PASSWORD.decode(), params=fast_params)
        pt = decrypt(ct, TEST_PASSWORD.decode(), params=fast_params)
        assert pt == b"Bonjour monde"

    def test_roundtrip_normal_params(self, normal_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        ct = encrypt(b"Secret message", TEST_PASSWORD, params=normal_params)
        pt = decrypt(ct, TEST_PASSWORD, params=normal_params)
        assert pt == b"Secret message"


# ══════════════════════════════════════════════════════════════════════════
#  Tests d'erreur — CagouleAuthError
# ══════════════════════════════════════════════════════════════════════════

class TestAuthError:

    def test_mauvais_mdp(self, fast_params):
        """
        FIX v2.1.0 — test_mauvais_mdp.
        Était xfail en v2.0 : decrypt(ct, wrong_password, params=correct_params)
        ne levait pas CagouleAuthError car params.k_stream était utilisé
        directement, ignorant le mauvais mot de passe.

        Fix : quand password est non-vide, on re-dérive toujours depuis
        (password, salt_cgl1) avec fast_mode=params.fast_mode.
        Mauvais mdp → k_master erroné → k_stream erroné → InvalidTag → CagouleAuthError.
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
        ct = encrypt(b"secret", TEST_PASSWORD, params=fast_params)
        with pytest.raises(CagouleAuthError):
            decrypt(ct, b"wrong_password", params=fast_params)

    def test_mauvais_mdp_sans_params(self):
        """Mauvais mot de passe sans params= (cas standard)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
            from cagoule.params import CagouleParams
        params = CagouleParams.derive(TEST_PASSWORD, fast_mode=True)
        ct = encrypt(b"secret", TEST_PASSWORD, params=params)
        params.zeroize()
        with pytest.raises(CagouleAuthError):
            decrypt(ct, b"completely_wrong_password")

    def test_mauvais_mdp_tres_different(self, fast_params):
        """Mot de passe radicalement différent → CagouleAuthError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
        ct = encrypt(b"confidentiel", TEST_PASSWORD, params=fast_params)
        with pytest.raises(CagouleAuthError):
            decrypt(ct, b"X" * 32, params=fast_params)

    def test_auth_error_attributs(self, fast_params):
        """CagouleAuthError v2.1.0 expose .reason, .ct_size, .backend, .hint."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        with pytest.raises(CagouleAuthError) as exc_info:
            decrypt(ct, b"wrong", params=fast_params)
        err = exc_info.value
        assert hasattr(err, 'reason'),  "CagouleAuthError doit avoir .reason"
        assert hasattr(err, 'ct_size'), "CagouleAuthError doit avoir .ct_size"
        assert hasattr(err, 'backend'), "CagouleAuthError doit avoir .backend"
        assert hasattr(err, 'hint'),    "CagouleAuthError doit avoir .hint"
        assert err.ct_size == len(ct),  ".ct_size doit correspondre à len(ct)"
        assert isinstance(err.reason, str) and len(err.reason) > 0
        assert isinstance(err.backend, str) and len(err.backend) > 0

    def test_auth_error_str_lisible(self, fast_params):
        """str(CagouleAuthError) doit être lisible et multi-lignes."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        with pytest.raises(CagouleAuthError) as exc_info:
            decrypt(ct, b"bad", params=fast_params)
        err_str = str(exc_info.value)
        assert "Raison" in err_str or "raison" in err_str.lower()
        assert "ciphertext" in err_str.lower() or "Taille" in err_str

    def test_ciphertext_altere(self, fast_params):
        """Corruption du ciphertext → CagouleAuthError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError
            from cagoule.format import HEADER_SIZE
        ct = encrypt(b"secret message for corruption test", TEST_PASSWORD, params=fast_params)
        ct_bytes = bytearray(ct)
        if len(ct_bytes) > HEADER_SIZE:
            ct_bytes[HEADER_SIZE] ^= 0xFF
        else:
            pytest.skip("Ciphertext trop court pour corruption")
        with pytest.raises(CagouleAuthError):
            decrypt(bytes(ct_bytes), TEST_PASSWORD, params=fast_params)

    def test_ciphertext_tronque(self, fast_params):
        """Ciphertext tronqué → CagouleFormatError ou CagouleAuthError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt, CagouleAuthError, CagouleFormatError
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        with pytest.raises((CagouleFormatError, CagouleAuthError)):
            decrypt(ct[:20], TEST_PASSWORD, params=fast_params)


# ══════════════════════════════════════════════════════════════════════════
#  Tests format CGL1
# ══════════════════════════════════════════════════════════════════════════

class TestFormat:

    def test_format_cgl1(self, fast_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.format import parse, is_cgl1, OVERHEAD, HEADER_SIZE, TAG_SIZE
        ct = encrypt(b"test", TEST_PASSWORD, params=fast_params)
        assert ct[:4] == b"CGL1", "Magic invalide"
        assert ct[4:5] == b"\x01", "Version invalide"
        assert is_cgl1(ct)
        pkt = parse(ct)
        assert len(pkt.salt) == 32
        assert len(pkt.nonce) == 12
        assert len(pkt.tag) == 16
        assert len(ct) >= OVERHEAD

    def test_format_error_attributs(self):
        """CagouleFormatError v2.1.0 expose .field, .data_size, .min_size."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.decipher import decrypt, CagouleFormatError
        with pytest.raises(CagouleFormatError) as exc_info:
            decrypt(b"BADF", b"password")
        err = exc_info.value
        assert hasattr(err, 'field'),     "CagouleFormatError doit avoir .field"
        assert hasattr(err, 'data_size'), "CagouleFormatError doit avoir .data_size"
        assert hasattr(err, 'min_size'),  "CagouleFormatError doit avoir .min_size"
        assert err.data_size == 4
        assert err.field != ""

    def test_format_error_magic_invalide(self):
        """Magic invalide → CagouleFormatError avec field='magic'."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.decipher import decrypt, CagouleFormatError
        bad = b"XXXX" + b"\x01" + b"\x00" * 60
        with pytest.raises(CagouleFormatError) as exc_info:
            decrypt(bad, b"password")
        assert "magic" in exc_info.value.field.lower()

    def test_deux_chiffrements_differents(self, fast_params):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
        msg = b"same message"
        ct1 = encrypt(msg, TEST_PASSWORD, params=fast_params)
        ct2 = encrypt(msg, TEST_PASSWORD, params=fast_params)
        assert ct1 != ct2, "Deux chiffrements doivent être différents (nonce aléatoire)"


# ══════════════════════════════════════════════════════════════════════════
#  Tests parametrés — tailles
# ══════════════════════════════════════════════════════════════════════════

class TestSizes:

    @pytest.mark.parametrize("size", [1, 15, 16, 17, 63, 64, 65, 255, 256, 1024])
    def test_sizes(self, fast_params, size):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        msg = os.urandom(size)
        ct  = encrypt(msg, TEST_PASSWORD, params=fast_params)
        pt  = decrypt(ct, TEST_PASSWORD, params=fast_params)
        assert pt == msg, f"Roundtrip échoué pour size={size}"


# ══════════════════════════════════════════════════════════════════════════
#  Tests params — fast_mode + decrypt_with_params
# ══════════════════════════════════════════════════════════════════════════

class TestParams:

    def test_fast_mode_stored(self):
        """CagouleParams.fast_mode doit être stocké (v2.1.0)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        p_fast = CagouleParams.derive(b"pwd", fast_mode=True)
        p_slow = CagouleParams.derive(b"pwd", fast_mode=False)
        assert p_fast.fast_mode is True,  "fast_mode=True doit être mémorisé"
        assert p_slow.fast_mode is False, "fast_mode=False doit être mémorisé"
        p_fast.zeroize()
        p_slow.zeroize()

    def test_params_sans_password(self, fast_params):
        """encrypt_with_params / decrypt_with_params : password vide OK."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt_with_params
            from cagoule.decipher import decrypt_with_params        
        msg = b"test with params only"
        ct  = encrypt_with_params(msg, fast_params)
        pt  = decrypt_with_params(ct, fast_params)
        assert pt == msg

    def test_params_mauvais_sel(self, fast_params):
        """params avec sel différent du ciphertext → CagouleAuthError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt_with_params
            from cagoule.decipher import decrypt, CagouleAuthError
            from cagoule.params import CagouleParams
        ct      = encrypt_with_params(b"test", fast_params)
        other_p = CagouleParams.derive(TEST_PASSWORD, fast_mode=True)
        with pytest.raises((CagouleAuthError, Exception)):
            decrypt(ct, b"", params=other_p)
        other_p.zeroize()

    def test_password_vide_sans_params(self):
        """password vide + params=None → CagouleError."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.decipher import decrypt, CagouleError
        with pytest.raises(CagouleError):
            decrypt(b"CGL1\x01" + b"\x00" * 60, b"")


# ══════════════════════════════════════════════════════════════════════════
#  Tests de performance (smoke)
# ══════════════════════════════════════════════════════════════════════════

class TestPerformance:

    def test_benchmark_1mb_fast(self, fast_params):
        """Chiffrement/déchiffrement 1 MB avec params pré-dérivés."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt
            from cagoule.decipher import decrypt
        msg = os.urandom(1024 * 1024)
        t0  = time.perf_counter()
        ct  = encrypt(msg, TEST_PASSWORD, params=fast_params)
        t_enc = time.perf_counter() - t0
        t0  = time.perf_counter()
        pt  = decrypt(ct, TEST_PASSWORD, params=fast_params)
        t_dec = time.perf_counter() - t0
        assert pt == msg
        # Sanity : < 10 s même sur machine lente
        assert t_enc < 10.0, f"Chiffrement trop lent : {t_enc:.1f}s"
        assert t_dec < 10.0, f"Déchiffrement trop lent : {t_dec:.1f}s"
