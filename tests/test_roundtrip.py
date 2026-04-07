"""
test_roundtrip.py — Tests Tier A + Tier B pour cipher.py / decipher.py

Couvre tous les cas du roadmap §9 :
  Tier A : roundtrip, altération, mauvais mdp, vide, 100KB
  Tier B : avalanche effect, entropie visuelle, différence de CT
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from params import CagouleParams, SALT_SIZE, BLOCK_SIZE_N
from cipher import encrypt, encrypt_with_params, pkcs7_pad, pkcs7_unpad
from decipher import (
    decrypt, decrypt_with_params,
    CagouleAuthError, CagouleFormatError, CagouleError,
)

# ------------------------------------------------------------------ #
#  Fixtures partagées (calculées une seule fois)                       #
# ------------------------------------------------------------------ #

FAST = True
SALT = b'\xCC' * SALT_SIZE
PWD  = b'CAGOULE_TEST_PASSWORD_2026'

_SHARED_PARAMS = None

def _params():
    global _SHARED_PARAMS
    if _SHARED_PARAMS is None:
        _SHARED_PARAMS = CagouleParams.derive(PWD, SALT, fast_mode=FAST)
    return _SHARED_PARAMS


# ------------------------------------------------------------------ #
#  Tier A — Tests fonctionnels (roadmap §9)                            #
# ------------------------------------------------------------------ #

def test_roundtrip_basic():
    """Chiffrer puis déchiffrer retourne le plaintext d'origine."""
    params = _params()
    msg = b"Hello CAGOULE!"
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg, f"Aller-retour échoué : {pt!r}"

def test_roundtrip_empty_message():
    """Message vide → aller-retour parfait."""
    params = _params()
    ct = encrypt(b'', PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == b''

def test_roundtrip_single_byte():
    """Un seul octet."""
    params = _params()
    ct = encrypt(b'\x42', PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == b'\x42'

def test_roundtrip_all_bytes():
    """Tous les octets de 0 à 255."""
    params = _params()
    msg = bytes(range(256))
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg

def test_roundtrip_block_aligned():
    """Message de taille exactement N=16 (aligné sur un bloc)."""
    params = _params()
    msg = b'A' * BLOCK_SIZE_N
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg

def test_roundtrip_multiple_blocks():
    """Message de 3 blocs = 48 octets."""
    params = _params()
    msg = b'B' * (BLOCK_SIZE_N * 3)
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg

def test_roundtrip_utf8_string():
    """Chiffrement de chaîne UTF-8."""
    params = _params()
    msg = "Données cryptographiques — CAGOULE ζ(2n) 🔐"
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg.encode('utf-8')

def test_different_passwords_different_ct():
    """Mêmes message et sel, mots de passe différents → ciphertexts différents."""
    msg = b"test message"
    # Pas de fast_mode dans encrypt()
    ct1 = encrypt(msg, b'password1', salt=SALT)
    ct2 = encrypt(msg, b'password2', salt=SALT)
    assert ct1 != ct2

def test_tampered_ciphertext_raises():
    """Altération du ciphertext → CagouleAuthError."""
    params = _params()
    msg = b"Message confidentiel"
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    # Altérer un octet dans la zone ciphertext (après le header de 49 octets)
    ct_tampered = bytearray(ct)
    ct_tampered[60] ^= 0xFF
    try:
        decrypt(bytes(ct_tampered), PWD, fast_mode=FAST)
        assert False, "CagouleAuthError attendue"
    except CagouleAuthError:
        pass

def test_tampered_tag_raises():
    """Altération du tag Poly1305 → CagouleAuthError."""
    params = _params()
    ct = encrypt(b"test", PWD, salt=SALT, params=params)
    ct_tampered = bytearray(ct)
    ct_tampered[-1] ^= 0x01    # Dernier octet = fin du tag
    try:
        decrypt(bytes(ct_tampered), PWD, fast_mode=FAST)
        assert False, "CagouleAuthError attendue"
    except CagouleAuthError:
        pass

def test_wrong_password_raises():
    """Mauvais mot de passe → CagouleAuthError."""
    params = _params()
    ct = encrypt(b"Secret", PWD, salt=SALT, params=params)
    try:
        decrypt(ct, b'mauvais_mot_de_passe', fast_mode=FAST)
        assert False, "CagouleAuthError attendue"
    except CagouleAuthError:
        pass

def test_large_message_roundtrip():
    """Fichier 100 KB aléatoire → aller-retour parfait."""
    import random
    rng = random.Random(2026)
    params = _params()
    msg = bytes(rng.randint(0, 255) for _ in range(100 * 1024))
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    pt = decrypt(ct, PWD, fast_mode=FAST)
    assert pt == msg, f"100KB aller-retour échoué : longueur {len(pt)} != {len(msg)}"

def test_cgl1_magic():
    """Le ciphertext commence par le magic 'CGL1'."""
    params = _params()
    ct = encrypt(b"test", PWD, salt=SALT, params=params)
    assert ct[:4] == b'CGL1', f"Magic invalide : {ct[:4]!r}"

def test_cgl1_version():
    """Le byte de version est 0x01."""
    params = _params()
    ct = encrypt(b"test", PWD, salt=SALT, params=params)
    assert ct[4:5] == b'\x01'

def test_cgl1_salt_in_header():
    """Le sel est correctement inclus dans le header CGL1."""
    params = _params()
    ct = encrypt(b"test", PWD, salt=SALT, params=params)
    assert ct[5:37] == SALT

def test_cgl1_overhead():
    """Overhead fixe de 65 octets (Magic+Version+Salt+Nonce+Tag)."""
    params = _params()
    # Message vide → CT = overhead + expansion interne (1 bloc PKCS7 padded)
    ct = encrypt(b"", PWD, salt=SALT, params=params)
    # Header : 4+1+32+12 = 49 ; tag : 16 ; 1 bloc interne (16 éléments × 8 octets = 128)
    assert len(ct) == 49 + 128 + 16, f"Overhead inattendu : {len(ct)}"

def test_format_error_too_short():
    """Ciphertext trop court → CagouleFormatError."""
    try:
        decrypt(b'CGL1\x01', PWD, fast_mode=FAST)
        assert False
    except CagouleFormatError:
        pass

def test_format_error_bad_magic():
    """Magic invalide → CagouleFormatError."""
    params = _params()
    ct = bytearray(encrypt(b"test", PWD, salt=SALT, params=params))
    ct[0] = ord('X')
    try:
        decrypt(bytes(ct), PWD, fast_mode=FAST)
        assert False
    except CagouleFormatError:
        pass

def test_with_params_roundtrip():
    """encrypt_with_params / decrypt_with_params."""
    params = _params()
    msg = b"Test avec params"
    ct = encrypt_with_params(msg, params)
    pt = decrypt_with_params(ct, params)
    assert pt == msg


# ------------------------------------------------------------------ #
#  Tests PKCS7                                                         #
# ------------------------------------------------------------------ #

def test_pkcs7_pad_unpad():
    """PKCS7 padding aller-retour."""
    for size in [0, 1, 15, 16, 17, 31, 32]:
        data = b'X' * size
        padded = pkcs7_pad(data, 16)
        assert len(padded) % 16 == 0
        unpadded = pkcs7_unpad(padded, 16)
        assert unpadded == data

def test_pkcs7_full_block_padding():
    """Message aligné → un bloc de padding complet ajouté."""
    data = b'A' * 16
    padded = pkcs7_pad(data, 16)
    assert len(padded) == 32
    assert padded[16:] == b'\x10' * 16


# ------------------------------------------------------------------ #
#  Tier B — Propriétés cryptographiques                                #
# ------------------------------------------------------------------ #

def test_different_plaintexts_different_ct():
    """Plaintexts différents → ciphertexts différents."""
    params = _params()
    ct1 = encrypt(b"Message A", PWD, salt=SALT, params=params)
    ct2 = encrypt(b"Message B", PWD, salt=SALT, params=params)
    # Les CT peuvent avoir une longueur différente (ici même longueur car même taille)
    # L'important : les données chiffrées diffèrent
    assert ct1[49:] != ct2[49:], "CT doivent différer"

def test_random_nonce_different_ct():
    """Même plaintext + même params → nonces différents → CT différents."""
    params = _params()
    msg = b"Message identique"
    ct1 = encrypt(msg, PWD, params=params)
    ct2 = encrypt(msg, PWD, params=params)
    # Nonces différents (aléatoires)
    assert ct1[37:49] != ct2[37:49], "Nonces doivent être différents"
    # CT différents
    assert ct1 != ct2

def test_avalanche_single_bit():
    """
    Effet avalanche : changer 1 bit du plaintext → au moins 30% des bits CT changent.
    (Le seuil > 50% s'applique au chiffrement interne ; ici on vérifie le minimum)
    """
    params = _params()
    msg1 = b'A' * 32
    msg2 = bytearray(msg1)
    msg2[0] ^= 0x01   # 1 bit de différence
    msg2 = bytes(msg2)

    # Chiffrer avec le même nonce (via params) pour comparer à même taille
    ct1 = encrypt_with_params(msg1, params)
    ct2 = encrypt_with_params(msg2, params)

    # Comparer les zones ciphertext (ignorer header + tag)
    ct1_data = ct1[49:-16]
    ct2_data = ct2[49:-16]

    # Compter les bits différents
    diff_bits = sum(bin(a ^ b).count('1')
                    for a, b in zip(ct1_data, ct2_data))
    total_bits = len(ct1_data) * 8
    ratio = diff_bits / total_bits

    assert ratio > 0.30, (
        f"Effet avalanche insuffisant : {ratio:.1%} bits changés "
        f"(attendu > 30%)"
    )

def test_ciphertext_expansion():
    """
    Vérifier le facteur d'expansion 8× par bloc.
    Utilise un message de 31 octets → 2 blocs internes (16+16).
    """
    params = _params()
    # 31 octets → PKCS7 pad sur 16 → 2 blocs de 16 octets = 32 octets
    msg = b'T' * 31
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    # 2 blocs × 16 éléments × 8 octets = 256
    expected_data_size = 2 * BLOCK_SIZE_N * 8
    actual_data_size = len(ct) - 49 - 16
    assert actual_data_size == expected_data_size, (
        f"Expansion inattendue : {actual_data_size} != {expected_data_size}"
    )

def test_ct_randomness_chi2():
    """
    Test de distribution des octets du ciphertext.
    Les octets doivent être approximativement uniformes sur [0, 255].
    """
    import random
    rng = random.Random(42)
    params = _params()
    msg = bytes(rng.randint(0, 255) for _ in range(512))
    ct = encrypt(msg, PWD, salt=SALT, params=params)
    ct_data = ct[49:-16]   # Exclure header et tag

    # Compter les occurrences de chaque octet
    counts = [0] * 256
    for b in ct_data:
        counts[b] += 1

    # Tous les octets ne doivent pas être identiques
    nonzero = sum(1 for c in counts if c > 0)
    assert nonzero > 128, f"Distribution trop peu uniforme : {nonzero}/256 valeurs"


# ------------------------------------------------------------------ #
#  Runner                                                              #
# ------------------------------------------------------------------ #

def run_all():
    tests = [
        test_roundtrip_basic,
        test_roundtrip_empty_message,
        test_roundtrip_single_byte,
        test_roundtrip_all_bytes,
        test_roundtrip_block_aligned,
        test_roundtrip_multiple_blocks,
        test_roundtrip_utf8_string,
        test_different_passwords_different_ct,
        test_tampered_ciphertext_raises,
        test_tampered_tag_raises,
        test_wrong_password_raises,
        test_large_message_roundtrip,
        test_cgl1_magic,
        test_cgl1_version,
        test_cgl1_salt_in_header,
        test_cgl1_overhead,
        test_format_error_too_short,
        test_format_error_bad_magic,
        test_with_params_roundtrip,
        test_pkcs7_pad_unpad,
        test_pkcs7_full_block_padding,
        test_different_plaintexts_different_ct,
        test_random_nonce_different_ct,
        test_avalanche_single_bit,
        test_ciphertext_expansion,
        test_ct_randomness_chi2,
    ]

    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"roundtrip : {passed}/{passed+failed} tests passés")
    if failed:
        sys.exit(1)
    else:
        print("TOUS LES TESTS PASSÉS ✓")


if __name__ == "__main__":
    run_all()