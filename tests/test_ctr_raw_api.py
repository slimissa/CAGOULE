"""
test_ctr_raw_api.py — Tests pytest pour le pipeline CTR expérimental v0x03
(Poly1305 seul, sans ChaCha20) — CAGOULE v3.1.0 Feature 1.

Couvre :
  - Gate expérimental (refus sans allow_experimental=True + env var)
  - encrypt_ctr_raw() / decrypt_ctr_raw() roundtrip
  - Format wire v0x03 : MAGIC|VERSION|SALT|CT|TAG, overhead = 53 octets
  - Mauvais mot de passe / tag corrompu → CagouleAuthError
  - Format invalide → CagouleFormatError
  - Tailles critiques
  - Parité ct_alg : 0x03 doit produire le même ct_alg que 0x02 pour les
    mêmes (password, salt) — seule la couche AEAD diffère
  - Non-régression : 0x02 reste inchangé et toujours le défaut
"""
import os
import pytest

from cagoule.cipher_ctr import VERSION_CTR, encrypt_ctr, _ctr_encrypt
from cagoule.decipher_ctr import decrypt_ctr
from cagoule.cipher_ctr_raw import (
    encrypt_ctr_raw, decrypt_ctr_raw,
    VERSION_CTR_RAW, OVERHEAD, CGL1_V3_MIN_SIZE,
    ExperimentalModeError, ENV_GATE_VAR,
)
from cagoule.cipher import MAGIC
from cagoule.decipher import CagouleAuthError, CagouleFormatError
from cagoule.params import CagouleParams

PASSWORD = b"test_password_v310"
MESSAGE  = b"CAGOULE v3.1.0 raw CTR test message"
FAST_KW  = {"fast_mode": True}


@pytest.fixture(autouse=True)
def _clean_env():
    """S'assure que la variable d'env du gate ne fuite pas entre tests."""
    saved = os.environ.pop(ENV_GATE_VAR, None)
    yield
    if saved is None:
        os.environ.pop(ENV_GATE_VAR, None)
    else:
        os.environ[ENV_GATE_VAR] = saved


# ── Gate expérimental ─────────────────────────────────────────────────────
class TestExperimentalGate:
    def test_refused_without_any_flag(self):
        with pytest.raises(ExperimentalModeError):
            encrypt_ctr_raw(MESSAGE, PASSWORD, **FAST_KW)

    def test_refused_with_only_python_flag(self):
        with pytest.raises(ExperimentalModeError):
            encrypt_ctr_raw(MESSAGE, PASSWORD, allow_experimental=True, **FAST_KW)

    def test_refused_with_only_env_flag(self):
        os.environ[ENV_GATE_VAR] = "1"
        with pytest.raises(ExperimentalModeError):
            encrypt_ctr_raw(MESSAGE, PASSWORD, **FAST_KW)

    def test_allowed_with_both_flags(self):
        os.environ[ENV_GATE_VAR] = "1"
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, allow_experimental=True, **FAST_KW)
        assert ct[4:5] == VERSION_CTR_RAW

    def test_decrypt_also_gated(self):
        os.environ[ENV_GATE_VAR] = "1"
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, allow_experimental=True, **FAST_KW)
        del os.environ[ENV_GATE_VAR]
        with pytest.raises(ExperimentalModeError):
            decrypt_ctr_raw(ct, PASSWORD, allow_experimental=True, **FAST_KW)

    def test_warns_when_allowed(self):
        os.environ[ENV_GATE_VAR] = "1"
        with pytest.warns(UserWarning):
            encrypt_ctr_raw(MESSAGE, PASSWORD, allow_experimental=True, **FAST_KW)

    def test_wrong_env_value_refused(self):
        os.environ[ENV_GATE_VAR] = "true"   # doit être exactement "1"
        with pytest.raises(ExperimentalModeError):
            encrypt_ctr_raw(MESSAGE, PASSWORD, allow_experimental=True, **FAST_KW)


def _opt_in():
    os.environ[ENV_GATE_VAR] = "1"
    return {"allow_experimental": True, **FAST_KW}


# ── Roundtrip de base ──────────────────────────────────────────────────────
class TestRawCTRBasic:
    def test_roundtrip(self):
        kw = _opt_in()
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        pt = decrypt_ctr_raw(ct, PASSWORD, **kw)
        assert pt == MESSAGE

    def test_version_byte(self):
        kw = _opt_in()
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        assert ct[:4] == MAGIC
        assert ct[4:5] == VERSION_CTR_RAW

    def test_overhead_is_53_bytes(self):
        """Roadmap §6.1 : overhead corrigé 53 (pas 49)."""
        kw = _opt_in()
        pt = b"x" * 100
        ct = encrypt_ctr_raw(pt, PASSWORD, **kw)
        assert OVERHEAD == 53
        assert len(ct) == len(pt) + OVERHEAD

    def test_no_nonce_field_shorter_than_v02(self):
        """v0x03 n'a pas de champ NONCE(12) → 12 octets plus court que v0x02."""
        kw = _opt_in()
        pt = b"x" * 100
        ct_raw = encrypt_ctr_raw(pt, PASSWORD, **kw)
        ct_v2  = encrypt_ctr(pt, PASSWORD, fast_mode=True)
        assert len(ct_v2) - len(ct_raw) == 12

    def test_ct_neq_pt(self):
        kw = _opt_in()
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        assert MESSAGE not in ct

    def test_nondeterministic(self):
        kw = _opt_in()
        ct1 = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        ct2 = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        assert ct1 != ct2  # salt aléatoire

    def test_wrong_password(self):
        kw = _opt_in()
        ct = encrypt_ctr_raw(MESSAGE, PASSWORD, **kw)
        with pytest.raises(CagouleAuthError):
            decrypt_ctr_raw(ct, b"wrong_password", **kw)

    def test_corrupted_tag(self):
        kw = _opt_in()
        ct = bytearray(encrypt_ctr_raw(MESSAGE, PASSWORD, **kw))
        ct[-1] ^= 0xFF
        with pytest.raises(CagouleAuthError):
            decrypt_ctr_raw(bytes(ct), PASSWORD, **kw)

    def test_corrupted_ciphertext_body(self):
        """Le MAC doit aussi détecter une altération du corps CT (pas que le tag)."""
        kw = _opt_in()
        ct = bytearray(encrypt_ctr_raw(MESSAGE, PASSWORD, **kw))
        ct[40] ^= 0xFF  # quelque part dans le corps CT
        with pytest.raises(CagouleAuthError):
            decrypt_ctr_raw(bytes(ct), PASSWORD, **kw)

    def test_corrupted_salt_detected_by_aad(self):
        """
        Déviation volontaire vs roadmap §2.2 : l'AAD (MAGIC|VERSION|SALT)
        est lié au MAC. Altérer le salt doit donc faire échouer
        l'authentification de façon déterministe, et pas dépendre d'un
        hasard de dérivation de clé.
        """
        kw = _opt_in()
        ct = bytearray(encrypt_ctr_raw(MESSAGE, PASSWORD, **kw))
        ct[5] ^= 0xFF  # premier octet du salt
        with pytest.raises(CagouleAuthError):
            decrypt_ctr_raw(bytes(ct), PASSWORD, **kw)

    def test_wrong_version_in_raw_decoder(self):
        kw = _opt_in()
        ct_v2 = encrypt_ctr(MESSAGE, PASSWORD, fast_mode=True)
        with pytest.raises(CagouleFormatError):
            decrypt_ctr_raw(ct_v2, PASSWORD, **kw)

    def test_truncated_header(self):
        kw = _opt_in()
        with pytest.raises(CagouleFormatError):
            decrypt_ctr_raw(b"CGL1\x03", PASSWORD, **kw)

    def test_bad_magic(self):
        kw = _opt_in()
        with pytest.raises(CagouleFormatError):
            decrypt_ctr_raw(b"\xDE\xAD\xBE\xEF\x03" + b"\x00" * 60, PASSWORD, **kw)


# ── Tailles critiques ────────────────────────────────────────────────────
@pytest.mark.parametrize("size", [0, 1, 7, 15, 16, 17, 31, 32, 33, 63,
                                   64, 65, 127, 128, 129, 255, 256, 257,
                                   1023, 1024, 1025])
def test_raw_ctr_roundtrip_all_sizes(size):
    kw = _opt_in()
    pt = os.urandom(size)
    ct = encrypt_ctr_raw(pt, PASSWORD, **kw)
    assert len(ct) == len(pt) + OVERHEAD
    assert decrypt_ctr_raw(ct, PASSWORD, **kw) == pt


# ── Parité algébrique avec 0x02 ──────────────────────────────────────────
class TestParityWithV02:
    def test_same_ct_alg_for_same_params(self):
        """
        0x02 et 0x03 partagent le même pipeline CTR algébrique
        (_ctr_encrypt). Pour les mêmes params ET le même header_salt,
        le ct_alg brut doit être identique — seule la couche AEAD diffère.

        CORRECTIF v3.0.1 : _ctr_encrypt requiert désormais header_salt
        explicitement (mélangé dans l'IV pour corriger le two-time-pad
        sur params partagé). On capture le salt réellement utilisé par
        encrypt_ctr_raw et on le repasse à l'appel direct pour comparer
        des chemins équivalents.
        """
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            os.environ[ENV_GATE_VAR] = "1"
            ct_raw = encrypt_ctr_raw(MESSAGE, PASSWORD, params=params,
                                      allow_experimental=True, fast_mode=True)
            used_salt = ct_raw[5:5 + 32]

            ct_alg_direct = _ctr_encrypt(MESSAGE, params, used_salt)

            # body = tout sauf header(37) et tag(16)
            body = ct_raw[37:-16]
            assert body == ct_alg_direct
        finally:
            params.zeroize()


# ── Types invalides ───────────────────────────────────────────────────────
def test_encrypt_raw_bad_type_message():
    kw = _opt_in()
    with pytest.raises(TypeError):
        encrypt_ctr_raw("not bytes", PASSWORD, **kw)


def test_encrypt_raw_bad_type_password():
    kw = _opt_in()
    with pytest.raises(TypeError):
        encrypt_ctr_raw(MESSAGE, "not bytes", **kw)


def test_decrypt_raw_bad_type():
    kw = _opt_in()
    with pytest.raises(TypeError):
        decrypt_ctr_raw("not bytes", PASSWORD, **kw)


# ── 0x02 reste inchangé (non-régression) ──────────────────────────────────
def test_v02_unaffected_by_v03_module_import():
    """L'existence du module 0x03 ne doit rien changer au pipeline 0x02."""
    ct = encrypt_ctr(MESSAGE, PASSWORD, fast_mode=True)
    assert ct[4:5] == VERSION_CTR
    assert decrypt_ctr(ct, PASSWORD, fast_mode=True) == MESSAGE
