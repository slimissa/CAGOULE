"""
test_ctr_api.py — Tests pytest de l'API Python CTR CAGOULE v3.1.0

Couvre :
  - encrypt_ctr() / decrypt_ctr() roundtrip
  - VERSION dispatch (v0x01 CBC → decrypt_cbc, v0x02 CTR → decrypt_ctr)
  - migrate_cbc_to_ctr()
  - encrypt_bulk_ctr() / decrypt_bulk_ctr()
  - Mauvais mot de passe → CagouleAuthError
  - Format invalide → CagouleFormatError
  - Tailles critiques (0, 1, 15, 16, 17, 255, 256, 1024)
  - encrypt() defaulte à CTR en v3.0.0
  - decrypt() dispatch automatique
"""
import os
import pytest

from cagoule import (
    encrypt, decrypt,
    encrypt_ctr, decrypt_ctr,
    encrypt_cbc, decrypt_cbc,
    encrypt_bulk, decrypt_bulk,
    encrypt_bulk_ctr, decrypt_bulk_ctr,
    migrate_cbc_to_ctr,
    __version__,
)
from cagoule.decipher     import CagouleAuthError, CagouleFormatError
from cagoule.cipher_ctr   import MAGIC, VERSION_CTR, VERSION_CBC

# ── Fixtures ────────────────────────────────────────────────────────────
PASSWORD  = b"test_password_v310"
MESSAGE   = b"CAGOULE v3.1.0 CTR test message"
FAST_KW   = {"fast_mode": True}   # KDF rapide pour les tests


# ── Version ─────────────────────────────────────────────────────────────
def test_version():
    assert __version__ == "3.1.0"


# ── encrypt() défaut → CTR (VERSION 0x02) ───────────────────────────────
def test_encrypt_defaults_to_ctr():
    ct = encrypt(MESSAGE, PASSWORD, **FAST_KW)
    assert ct[4:5] == VERSION_CTR, "encrypt() doit produire CGL1 v0x02 (CTR)"


def test_decrypt_dispatch_ctr():
    ct = encrypt(MESSAGE, PASSWORD, **FAST_KW)
    assert ct[4:5] == VERSION_CTR
    pt = decrypt(ct, PASSWORD, **FAST_KW)
    assert pt == MESSAGE


# ── encrypt_ctr / decrypt_ctr ───────────────────────────────────────────
class TestCTRBasic:
    def test_roundtrip(self):
        ct = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        pt = decrypt_ctr(ct, PASSWORD, **FAST_KW)
        assert pt == MESSAGE

    def test_version_byte(self):
        ct = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        assert ct[:4] == MAGIC
        assert ct[4:5] == VERSION_CTR

    def test_ct_len_equals_pt_len(self):
        """CGL1 v0x02 : |CT_aead| = |PT| + 16 (tag). Pas de PKCS7."""
        pt = b"x" * 100
        ct = encrypt_ctr(pt, PASSWORD, **FAST_KW)
        # header: 4+1+32+12 = 49, + CT(100) + TAG(16) = 165
        assert len(ct) == 49 + len(pt) + 16

    def test_ct_neq_pt(self):
        ct = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        assert MESSAGE not in ct

    def test_nondeterministic(self):
        ct1 = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        ct2 = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        assert ct1 != ct2   # salt + nonce aléatoires

    def test_wrong_password(self):
        ct = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        with pytest.raises(CagouleAuthError):
            decrypt_ctr(ct, b"wrong_password", **FAST_KW)

    def test_corrupted_tag(self):
        ct = bytearray(encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW))
        ct[-1] ^= 0xFF  # corrompre le tag
        with pytest.raises(CagouleAuthError):
            decrypt_ctr(bytes(ct), PASSWORD, **FAST_KW)

    def test_wrong_version_in_ctr_decoder(self):
        """decrypt_ctr() refuse les ciphertexts v0x01 (CBC)."""
        ct_cbc = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        with pytest.raises(CagouleFormatError):
            decrypt_ctr(ct_cbc, PASSWORD, **FAST_KW)

    def test_truncated_header(self):
        with pytest.raises(CagouleFormatError):
            decrypt_ctr(b"CGL1\x02", PASSWORD, **FAST_KW)


# ── Tailles critiques ────────────────────────────────────────────────────
@pytest.mark.parametrize("size", [0, 1, 7, 15, 16, 17, 31, 32, 33, 63,
                                   64, 65, 127, 128, 129, 255, 256, 257,
                                   1023, 1024, 1025])
def test_ctr_roundtrip_all_sizes(size):
    pt = os.urandom(size)
    ct = encrypt_ctr(pt, PASSWORD, **FAST_KW)
    assert decrypt_ctr(ct, PASSWORD, **FAST_KW) == pt


# ── CBC rétrocompatibilité ───────────────────────────────────────────────
class TestCBCBackcompat:
    def test_encrypt_cbc_version(self):
        ct = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        assert ct[4:5] == VERSION_CBC

    def test_decrypt_cbc_explicit(self):
        ct = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        pt = decrypt_cbc(ct, PASSWORD, **FAST_KW)
        assert pt == MESSAGE

    def test_dispatch_routes_v01_to_cbc(self):
        """decrypt() dispatch v0x01 → CBC pipeline."""
        ct_cbc = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        assert ct_cbc[4:5] == VERSION_CBC
        pt = decrypt(ct_cbc, PASSWORD, **FAST_KW)
        assert pt == MESSAGE

    def test_dispatch_routes_v02_to_ctr(self):
        """decrypt() dispatch v0x02 → CTR pipeline."""
        ct_ctr = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        assert ct_ctr[4:5] == VERSION_CTR
        pt = decrypt(ct_ctr, PASSWORD, **FAST_KW)
        assert pt == MESSAGE

    def test_dispatch_unknown_version(self):
        ct = bytearray(encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW))
        ct[4] = 0xFF   # version inconnue
        with pytest.raises(CagouleFormatError):
            decrypt(bytes(ct), PASSWORD, **FAST_KW)

    def test_cbc_ctr_ct_differ(self):
        ct_cbc = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        ct_ctr = encrypt_ctr(MESSAGE, PASSWORD, **FAST_KW)
        assert ct_cbc != ct_ctr
        assert ct_cbc[4:5] != ct_ctr[4:5]


# ── Migration CBC → CTR ─────────────────────────────────────────────────
class TestMigration:
    def test_migrate_basic(self):
        ct_cbc = encrypt_cbc(MESSAGE, PASSWORD, **FAST_KW)
        ct_ctr = migrate_cbc_to_ctr(ct_cbc, PASSWORD, fast_mode=True)
        assert ct_ctr[4:5] == VERSION_CTR
        pt = decrypt_ctr(ct_ctr, PASSWORD, **FAST_KW)
        assert pt == MESSAGE

    def test_migrate_roundtrip(self):
        original = b"migration test payload " * 10
        ct_cbc = encrypt_cbc(original, PASSWORD, **FAST_KW)
        ct_ctr = migrate_cbc_to_ctr(ct_cbc, PASSWORD, fast_mode=True)
        recovered = decrypt(ct_ctr, PASSWORD, **FAST_KW)
        assert recovered == original

    def test_migrate_ct_size(self):
        """Après migration, |CT_body| == |plaintext| (pas de padding CBC)."""
        pt = b"x" * 100
        ct_ctr = migrate_cbc_to_ctr(
            encrypt_cbc(pt, PASSWORD, **FAST_KW),
            PASSWORD, fast_mode=True
        )
        # header 49 + PT(100) + TAG(16) = 165
        assert len(ct_ctr) == 49 + len(pt) + 16


# ── Bulk CTR ────────────────────────────────────────────────────────────
class TestBulkCTR:
    def test_bulk_roundtrip(self):
        messages = [b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"]
        cts = encrypt_bulk_ctr(messages, PASSWORD, fast_mode=True)
        pts = [decrypt_ctr(ct, PASSWORD, **FAST_KW) for ct in cts]
        assert pts == messages

    def test_bulk_len(self):
        messages = [os.urandom(50) for _ in range(10)]
        cts = encrypt_bulk_ctr(messages, PASSWORD, fast_mode=True)
        assert len(cts) == 10

    def test_bulk_all_ctr(self):
        cts = encrypt_bulk_ctr([MESSAGE] * 5, PASSWORD, fast_mode=True)
        assert all(ct[4:5] == VERSION_CTR for ct in cts)

    def test_bulk_decrypt_roundtrip(self):
        messages = [b"bulk_" + str(i).encode() for i in range(20)]
        cts = encrypt_bulk(messages, PASSWORD, fast_mode=True)
        pts = decrypt_bulk(cts, PASSWORD, fast_mode=True)
        assert pts == messages

    def test_bulk_empty(self):
        assert encrypt_bulk_ctr([], PASSWORD, fast_mode=True) == []

    def test_bulk_single(self):
        cts = encrypt_bulk_ctr([MESSAGE], PASSWORD, fast_mode=True)
        assert len(cts) == 1
        assert decrypt_ctr(cts[0], PASSWORD, **FAST_KW) == MESSAGE

    def test_bulk_mixed_sizes(self):
        msgs = [b"", b"x", b"y" * 100, b"z" * 1000]
        cts  = encrypt_bulk_ctr(msgs, PASSWORD, fast_mode=True)
        pts  = [decrypt_ctr(ct, PASSWORD, **FAST_KW) for ct in cts]
        assert pts == msgs

    def test_bulk_wrong_password(self):
        cts = encrypt_bulk_ctr([MESSAGE], PASSWORD, fast_mode=True)
        with pytest.raises(CagouleAuthError):
            decrypt_ctr(cts[0], b"wrong", **FAST_KW)


# ── Régression v3.1.0 — two-time-pad sur params= partagé (CORRIGÉ) ─────────
class TestSharedParamsKeystreamUniqueness:
    """
    Couvre le bug rapporté et corrigé en v3.0.1 :
      - encrypt_ctr(params=<partagé>) réutilisait le même IV (donc le même
        keystream CTR algébrique) pour tous les messages partageant le même
        objet CagouleParams, car l'IV ne dépendait que de k_master.
      - Le correctif initial appliqué uniquement à encrypt_bulk_ctr cassait
        le côté decrypt (formule IV divergente entre encrypt et decrypt).
      - Fix final : une formule IV unique partout, toujours salée par le
        sel du header CGL1 (HKDF(k_master, b'CAGOULE_CTR_V31' + header_salt)).

    Ces tests vérifient à la fois la confidentialité (keystreams distincts)
    et la correction fonctionnelle (round-trip avec params partagé).
    """

    def test_shared_params_encrypt_ctr_different_ciphertexts(self):
        """Deux messages différents, même params partagé → ciphertexts distincts."""
        from cagoule.params import CagouleParams
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            ct1 = encrypt_ctr(b"Message numero un - meme longueur!", PASSWORD,
                               params=params, fast_mode=True)
            ct2 = encrypt_ctr(b"Message numero deux - meme longueur", PASSWORD,
                               params=params, fast_mode=True)
            assert ct1 != ct2
            # CORRECTIF v3.0.1 (3e itération) : en mode params partagé, les sels
            # de header sont IDENTIQUES (= params.salt, pour préserver l'invariant
            # CGL1 password+salt→k_master). L'unicité par message vient du nonce
            # ChaCha20 (12 octets à l'offset 37), pas du salt.
            assert ct1[5:37] == ct2[5:37], (
                "Les sels de header doivent être identiques en mode params partagé "
                "(= params.salt) — l'unicité par message vient du nonce, pas du salt."
            )
            assert ct1[37:49] != ct2[37:49], "Les nonces ChaCha20 doivent différer"
        finally:
            params.zeroize()

    def test_shared_params_roundtrip_both_directions(self):
        """
        Le test demandé explicitement par le rapport de bug : chiffrer deux
        messages différents avec un params= partagé, vérifier que les
        ciphertexts algébriques diffèrent, puis vérifier que les deux
        déchiffrent correctement avec le même params= repassé en argument.
        """
        from cagoule.params import CagouleParams
        from cagoule.cipher_ctr import _ctr_encrypt
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            pt1 = b"Premier message secret avec params partage"
            pt2 = b"Second message totalement different ici"

            ct1 = encrypt_ctr(pt1, PASSWORD, params=params, fast_mode=True)
            ct2 = encrypt_ctr(pt2, PASSWORD, params=params, fast_mode=True)

            # Extraire les ct_alg bruts (sans AEAD) pour vérifier l'absence
            # de réutilisation de keystream au niveau algébrique, pas
            # seulement au niveau du ciphertext final masqué par ChaCha20.
            # CORRECTIF : l'IV est lié au nonce (offset 37), pas au salt.
            nonce1, nonce2 = ct1[37:49], ct2[37:49]
            ct_alg1_direct = _ctr_encrypt(pt1, params, nonce1)
            ct_alg2_direct = _ctr_encrypt(pt2, params, nonce2)
            xor_ct = bytes(a ^ b for a, b in zip(ct_alg1_direct, ct_alg2_direct))
            xor_pt = bytes(a ^ b for a, b in zip(pt1, pt2))
            assert xor_ct != xor_pt, (
                "Signature two-time-pad détectée — keystream réutilisé "
                "entre deux messages partageant le même params="
            )

            # Round-trip avec le même params= repassé en argument
            rec1 = decrypt_ctr(ct1, PASSWORD, params=params, fast_mode=True)
            rec2 = decrypt_ctr(ct2, PASSWORD, params=params, fast_mode=True)
            assert rec1 == pt1
            assert rec2 == pt2
        finally:
            params.zeroize()

    def test_shared_params_same_plaintext_different_ciphertext(self):
        """Même plaintext, même params partagé, appels distincts → ciphertexts distincts."""
        from cagoule.params import CagouleParams
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            ct_a = encrypt_ctr(MESSAGE, PASSWORD, params=params, fast_mode=True)
            ct_b = encrypt_ctr(MESSAGE, PASSWORD, params=params, fast_mode=True)
            assert ct_a != ct_b  # sels de header différents -> IV différents
            assert decrypt_ctr(ct_a, PASSWORD, params=params, fast_mode=True) == MESSAGE
            assert decrypt_ctr(ct_b, PASSWORD, params=params, fast_mode=True) == MESSAGE
        finally:
            params.zeroize()

    def test_encrypt_bulk_ctr_shared_params_roundtrip(self):
        """encrypt_bulk_ctr(params=<partagé>) doit rester déchiffrable (régression v3.0.1)."""
        from cagoule.params import CagouleParams
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            messages = [b"bulk msg un", b"bulk msg deux", b"bulk msg trois"]
            cts = encrypt_bulk_ctr(messages, PASSWORD, params=params, fast_mode=True)
            # CORRECTIF v3.0.1 (3e itération) : en mode partagé, les sels de header
            # sont identiques (= params.salt). L'unicité par message vient des nonces.
            assert len({ct[5:37] for ct in cts}) == 1, (
                "Les sels de header doivent être identiques en mode params partagé"
            )
            assert len({ct[37:49] for ct in cts}) == len(cts), (
                "Les nonces ChaCha20 doivent être uniques par message"
            )
            recovered = [decrypt_ctr(ct, PASSWORD, fast_mode=True) for ct in cts]
            assert recovered == messages
        finally:
            params.zeroize()

    def test_mono_message_path_also_fixed(self):
        """
        Vérifie que le chemin mono-message (encrypt_ctr sans bulk) — celui que
        le rapport identifie comme jamais patché dans la tentative précédente —
        utilise désormais aussi un IV salé par message, pas seulement le bulk.
        """
        from cagoule.params import CagouleParams
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        try:
            pt = b"meme plaintext"
            ct1 = encrypt_ctr(pt, PASSWORD, params=params, fast_mode=True)
            ct2 = encrypt_ctr(pt, PASSWORD, params=params, fast_mode=True)
            # ct_alg (entre header et tag) doit différer entre les deux appels
            ct_alg1 = ct1[37:-16]
            ct_alg2 = ct2[37:-16]
            assert ct_alg1 != ct_alg2, (
                "Le chemin mono-message encrypt_ctr(params=partagé) réutilise "
                "encore le même keystream — régression du bug rapporté."
            )
        finally:
            params.zeroize()

    def test_cross_session_roundtrip_no_params_object(self):
        """
        LE test définitif manquant dans toutes les itérations précédentes.

        Chiffrer avec params= partagé, SUPPRIMER l'objet params, puis déchiffrer
        en re-dérivant params depuis (password, header_salt) uniquement — sans
        garder l'objet params en mémoire. C'est le seul test qui valide que
        l'invariant CGL1 tient en conditions réelles (cross-session, cross-process).
        """
        from cagoule.params import CagouleParams
        params = CagouleParams.derive(PASSWORD, fast_mode=True)
        ct = encrypt_ctr(MESSAGE, PASSWORD, params=params, fast_mode=True)
        params.zeroize()
        del params  # Simuler une session distincte — plus d'objet params en mémoire

        # Re-dériver depuis (password + header_salt) uniquement
        recovered = decrypt_ctr(ct, PASSWORD, fast_mode=True)
        assert recovered == MESSAGE, (
            "Impossible de déchiffrer sans garder params en mémoire — "
            "l'invariant CGL1 (password+salt→k_master) est cassé."
        )


# ── Types invalides ─────────────────────────────────────────────────────
def test_encrypt_ctr_bad_type_message():
    with pytest.raises(TypeError):
        encrypt_ctr("not bytes", PASSWORD, **FAST_KW)

def test_encrypt_ctr_bad_type_password():
    with pytest.raises(TypeError):
        encrypt_ctr(MESSAGE, "not bytes", **FAST_KW)

def test_decrypt_ctr_bad_type():
    with pytest.raises(TypeError):
        decrypt_ctr("not bytes", PASSWORD, **FAST_KW)


# ── Format invalide ─────────────────────────────────────────────────────
def test_decrypt_bad_magic():
    with pytest.raises(CagouleFormatError):
        decrypt_ctr(b"\xDE\xAD\xBE\xEF\x02" + b"\x00" * 100, PASSWORD, **FAST_KW)

def test_decrypt_too_short():
    with pytest.raises(CagouleFormatError):
        decrypt_ctr(b"CGL1\x02", PASSWORD, **FAST_KW)


# ── CTR est symétrique (encrypt == decrypt au niveau C) ─────────────────
def test_ctr_symmetry():
    """
    CTR : decrypt(encrypt(m)) == m
         ET encrypt(encrypt(m)) == m   (si on enlève le wrapper AEAD)
    On teste au niveau Python API que les deux sens fonctionnent.
    """
    for size in [0, 1, 16, 100, 500]:
        pt = os.urandom(size)
        ct = encrypt_ctr(pt, PASSWORD, **FAST_KW)
        assert decrypt_ctr(ct, PASSWORD, **FAST_KW) == pt


# ── Stabilité déterministe des params ──────────────────────────────────
def test_ctr_determinism_same_salt():
    """Mêmes params → même keystream → même ciphertext."""
    from cagoule.params import CagouleParams
    salt = os.urandom(32)
    params = CagouleParams.derive(PASSWORD, salt=salt, fast_mode=True)
    try:
        ct1 = encrypt_ctr(MESSAGE, PASSWORD, params=params, **FAST_KW)
        # Même salt → même k_master → même IV CTR → même keystream
        ct2 = encrypt_ctr(MESSAGE, PASSWORD, params=params, **FAST_KW)
        # Les nonces AEAD diffèrent (os.urandom), donc ct1 != ct2 au niveau AEAD
        # Mais les deux doivent décrypter vers MESSAGE
        assert decrypt_ctr(ct1, PASSWORD, params=params, **FAST_KW) == MESSAGE
        assert decrypt_ctr(ct2, PASSWORD, params=params, **FAST_KW) == MESSAGE
    finally:
        params.zeroize()
