"""
test_params.py — Tests Tier A + Tier B pour params.py et omega.py

Vérifie :
- Dérivation complète des paramètres
- Déterminisme (mêmes entrées → mêmes sorties)
- Unicité des clés (sels différents → paramètres différents)
- Plage des valeurs dérivées
- Identité CGS2025 : ζ(8) = π⁸/9450
- Round keys : dépendance à n, unicité, plage
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from params import (
    CagouleParams, SALT_SIZE, K_MASTER_SIZE, K_STREAM_SIZE,
    BLOCK_SIZE_N, NUM_ROUND_KEYS, derive_k_master, hkdf_derive,
    hkdf_int, nextprime, _is_prime_miller_rabin,
)
from omega import (
    compute_zeta, verify_cgs2025_identity, fourier_coefficients,
    generate_round_keys, apply_round_key, remove_round_key,
    OmegaInfo,
)

# ------------------------------------------------------------------ #
#  Constantes de test                                                  #
# ------------------------------------------------------------------ #

SALT_A = b'\xAA' * SALT_SIZE
SALT_B = b'\xBB' * SALT_SIZE
PWD_1  = b'MotDePasseCAGOULE2026'
PWD_2  = b'AutreMotDePasse!'
FAST   = True    # fast_mode pour tous les tests


# ------------------------------------------------------------------ #
#  Tests nextprime / Miller-Rabin                                      #
# ------------------------------------------------------------------ #

def test_is_prime_small():
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    composites = [1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 25]
    for p in primes:
        assert _is_prime_miller_rabin(p), f"{p} devrait être premier"
    for c in composites:
        assert not _is_prime_miller_rabin(c), f"{c} ne devrait pas être premier"

def test_nextprime_basic():
    assert nextprime(2) == 2
    assert nextprime(3) == 3
    assert nextprime(4) == 5
    assert nextprime(10) == 11
    assert nextprime(100) == 101
    assert nextprime(1000) == 1009

def test_nextprime_large():
    """nextprime sur un nombre 64 bits."""
    n = (1 << 63) + 12345
    p = nextprime(n)
    assert p >= n
    assert _is_prime_miller_rabin(p)
    assert p - n < 10000  # distance raisonnable

def test_nextprime_result_is_prime():
    """Le résultat de nextprime est toujours premier."""
    import random
    rng = random.Random(42)
    for _ in range(20):
        n = rng.randint(2, 10**9)
        p = nextprime(n)
        assert _is_prime_miller_rabin(p), f"nextprime({n})={p} n'est pas premier"
        assert p >= n


# ------------------------------------------------------------------ #
#  Tests KDF et HKDF                                                   #
# ------------------------------------------------------------------ #

def test_kdf_output_length():
    k = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    assert len(k) == K_MASTER_SIZE, f"K_master doit faire {K_MASTER_SIZE} octets"

def test_kdf_deterministic():
    k1 = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    k2 = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    assert k1 == k2, "KDF doit être déterministe"

def test_kdf_different_passwords():
    k1 = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    k2 = derive_k_master(PWD_2, SALT_A, fast_mode=FAST)
    assert k1 != k2, "Mots de passe différents → K_master différents"

def test_kdf_different_salts():
    k1 = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    k2 = derive_k_master(PWD_1, SALT_B, fast_mode=FAST)
    assert k1 != k2, "Sels différents → K_master différents"

def test_hkdf_deterministic():
    k = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    h1 = hkdf_derive(k, b'TEST_INFO', 32)
    h2 = hkdf_derive(k, b'TEST_INFO', 32)
    assert h1 == h2

def test_hkdf_different_info():
    k = derive_k_master(PWD_1, SALT_A, fast_mode=FAST)
    h1 = hkdf_int(k, b'INFO_A', 8)
    h2 = hkdf_int(k, b'INFO_B', 8)
    assert h1 != h2, "Infos différentes → dérivations différentes"


# ------------------------------------------------------------------ #
#  Tests CagouleParams                                                  #
# ------------------------------------------------------------------ #

def _make_params():
    return CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)

def test_params_n_range():
    """n ∈ [4, 65536]."""
    params = _make_params()
    assert 4 <= params.n <= 65536, f"n={params.n} hors plage [4,65536]"

def test_params_p_is_prime():
    """p doit être un nombre premier."""
    params = _make_params()
    assert _is_prime_miller_rabin(params.p), f"p={params.p} n'est pas premier"

def test_params_p_approx_2_64():
    """p ≈ 2^64 (Phase 1)."""
    params = _make_params()
    assert params.p >= (1 << 63), f"p={params.p} trop petit (< 2^63)"
    assert params.p < (1 << 65), f"p={params.p} trop grand (> 2^65)"

def test_params_p_bytes():
    """p_bytes = ceil(log2(p)/8)."""
    params = _make_params()
    expected = (params.p.bit_length() + 7) // 8
    assert params.p_bytes == expected

def test_params_k_stream_length():
    """K_stream fait exactement 32 octets."""
    params = _make_params()
    assert len(params.k_stream) == K_STREAM_SIZE

def test_params_deterministic():
    """Mêmes entrées → mêmes paramètres."""
    p1 = CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)
    p2 = CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)
    assert p1.n          == p2.n
    assert p1.p          == p2.p
    assert p1.k_stream   == p2.k_stream
    assert p1.round_keys == p2.round_keys

def test_params_different_passwords():
    """Mots de passe différents → paramètres différents."""
    p1 = CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)
    p2 = CagouleParams.derive(PWD_2, SALT_A, fast_mode=FAST)
    assert p1.k_stream != p2.k_stream
    assert p1.p        != p2.p or p1.k_stream != p2.k_stream

def test_params_different_salts():
    """Sels différents → K_stream différents."""
    p1 = CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)
    p2 = CagouleParams.derive(PWD_1, SALT_B, fast_mode=FAST)
    assert p1.k_stream != p2.k_stream

def test_params_mu_valid():
    """µ doit satisfaire x⁴ + x² + 1 = 0."""
    from fp2 import Fp2Element
    params = _make_params()
    p = params.p
    mu = params.mu
    if mu.in_fp2:
        m = mu.as_fp2()
        one = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)
        assert (m**4 + m**2 + one) == zero
    else:
        m = mu.as_int()
        assert (pow(m,4,p) + pow(m,2,p) + 1) % p == 0

def test_params_diffusion_16x16():
    """Matrice de diffusion doit être 16×16."""
    params = _make_params()
    assert params.diffusion.n == BLOCK_SIZE_N == 16

def test_params_diffusion_invertible():
    """P × P⁻¹ = I."""
    params = _make_params()
    assert params.diffusion.verify_inverse()

def test_params_num_round_keys():
    """64 round keys."""
    params = _make_params()
    assert len(params.round_keys) == NUM_ROUND_KEYS == 64

def test_params_round_keys_in_zp():
    """Toutes les round keys dans [0, p-1]."""
    params = _make_params()
    for rk in params.round_keys:
        assert 0 <= rk < params.p

def test_params_salt_in_output():
    """Le sel passé en entrée est retrouvé dans params."""
    params = CagouleParams.derive(PWD_1, SALT_A, fast_mode=FAST)
    assert params.salt == SALT_A

def test_params_random_salt():
    """Sans sel fourni, le sel est aléatoire (32 octets)."""
    p1 = CagouleParams.derive(PWD_1, fast_mode=FAST)
    p2 = CagouleParams.derive(PWD_1, fast_mode=FAST)
    assert len(p1.salt) == SALT_SIZE
    assert p1.salt != p2.salt  # aléatoire → différent avec très haute prob.

def test_params_str_password():
    """Le mot de passe peut être str ou bytes."""
    p1 = CagouleParams.derive("MotDePasse", SALT_A, fast_mode=FAST)
    p2 = CagouleParams.derive(b"MotDePasse", SALT_A, fast_mode=FAST)
    assert p1.k_stream == p2.k_stream

def test_params_repr():
    params = _make_params()
    r = repr(params)
    assert "CagouleParams" in r


# ------------------------------------------------------------------ #
#  Tests omega.py                                                      #
# ------------------------------------------------------------------ #

def test_omega_cgs2025_identity():
    """ζ(8) = π⁸/9450 — identité CGS2025."""
    assert verify_cgs2025_identity(precision_dps=40), "Identité CGS2025 invalide"

def test_omega_zeta_decreasing():
    """ζ(2n) est décroissante vers 1 quand n augmente."""
    z4  = float(compute_zeta(4))
    z8  = float(compute_zeta(8))
    z16 = float(compute_zeta(16))
    assert z4 > z8 > z16 > 1.0

def test_omega_zeta_approaches_one():
    """ζ(2n) → 1 pour n grand."""
    import mpmath
    z = compute_zeta(100)
    assert abs(float(z) - 1.0) < 1e-20

def test_omega_fourier_alternating_sign():
    """Les coefficients de Fourier alternent en signe."""
    coeffs = fourier_coefficients(4, num_terms=6)
    signs = [1 if float(c) > 0 else -1 for c in coeffs]
    assert signs == [1, -1, 1, -1, 1, -1], f"Signes attendus +−+−+−, reçu {signs}"

def test_omega_fourier_decreasing_magnitude():
    """|aₖ| est décroissante en k."""
    coeffs = fourier_coefficients(4, num_terms=10)
    mags = [abs(float(c)) for c in coeffs]
    for i in range(len(mags)-1):
        assert mags[i] > mags[i+1], f"|a{i+1}|={mags[i]:.3e} <= |a{i+2}|={mags[i+1]:.3e}"

def test_omega_round_keys_count():
    """generate_round_keys retourne exactement 64 clés."""
    rks = generate_round_keys(n=4, salt=SALT_A, p=1009)
    assert len(rks) == 64

def test_omega_round_keys_in_range():
    """Toutes les round keys dans [0, p-1]."""
    p = 65537
    rks = generate_round_keys(n=4, salt=SALT_A, p=p)
    for rk in rks:
        assert 0 <= rk < p

def test_omega_round_keys_depend_on_n():
    """Round keys différentes si n diffère."""
    p = 65537
    rks4 = generate_round_keys(n=4,  salt=SALT_A, p=p)
    rks5 = generate_round_keys(n=5,  salt=SALT_A, p=p)
    assert rks4 != rks5, "round keys doivent dépendre de n"

def test_omega_round_keys_depend_on_salt():
    """Round keys différentes si sel diffère."""
    p = 65537
    rks_a = generate_round_keys(n=4, salt=SALT_A, p=p)
    rks_b = generate_round_keys(n=4, salt=SALT_B, p=p)
    assert rks_a != rks_b

def test_omega_apply_remove_round_key():
    """apply_round_key puis remove_round_key = identité."""
    p = 65537
    block = [100, 200, 300, 400]
    rk = 9999
    enc = apply_round_key(block, rk, p)
    dec = remove_round_key(enc, rk, p)
    assert dec == block

def test_omega_info():
    info = OmegaInfo(n=4)
    assert info.cgs2025_match is True
    r = repr(info)
    assert "CGS2025" in r


# ------------------------------------------------------------------ #
#  Runner                                                              #
# ------------------------------------------------------------------ #

def run_all():
    tests = [
        test_is_prime_small,
        test_nextprime_basic,
        test_nextprime_large,
        test_nextprime_result_is_prime,
        test_kdf_output_length,
        test_kdf_deterministic,
        test_kdf_different_passwords,
        test_kdf_different_salts,
        test_hkdf_deterministic,
        test_hkdf_different_info,
        test_params_n_range,
        test_params_p_is_prime,
        test_params_p_approx_2_64,
        test_params_p_bytes,
        test_params_k_stream_length,
        test_params_deterministic,
        test_params_different_passwords,
        test_params_different_salts,
        test_params_mu_valid,
        test_params_diffusion_16x16,
        test_params_diffusion_invertible,
        test_params_num_round_keys,
        test_params_round_keys_in_zp,
        test_params_salt_in_output,
        test_params_random_salt,
        test_params_str_password,
        test_params_repr,
        test_omega_cgs2025_identity,
        test_omega_zeta_decreasing,
        test_omega_zeta_approaches_one,
        test_omega_fourier_alternating_sign,
        test_omega_fourier_decreasing_magnitude,
        test_omega_round_keys_count,
        test_omega_round_keys_in_range,
        test_omega_round_keys_depend_on_n,
        test_omega_round_keys_depend_on_salt,
        test_omega_apply_remove_round_key,
        test_omega_info,
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
    print(f"params+omega : {passed}/{passed+failed} tests passés")
    if failed:
        sys.exit(1)
    else:
        print("TOUS LES TESTS PASSÉS ✓")


if __name__ == "__main__":
    run_all()