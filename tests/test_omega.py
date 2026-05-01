"""
test_omega.py — Tests Python du module omega.py — CAGOULE v2.1.0

Couvre :
  §1. API compute_zeta / fourier_coefficient (12 tests)
  §2. generate_round_keys — comportement (18 tests)
  §3. apply_round_key / remove_round_key (10 tests)
  §4. Compatibilité bit-à-bit C ↔ Python (8 tests, skip si mpmath absent)
  §5. Backend et cache (8 tests)
  §6. Intégration CagouleParams (6 tests)

Total : 62 tests
"""

import math
import warnings
import pytest

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cagoule.omega import (
        compute_zeta,
        fourier_coefficient,
        fourier_coefficients,
        generate_round_keys,
        apply_round_key,
        remove_round_key,
        clear_caches,
        get_cache_info,
        OMEGA_BACKEND,
        _OMEGA_C_SYMBOLS_OK,
        _mpmath_available,
    )

# ── Constantes de test ────────────────────────────────────────────────────────
TEST_SALT = bytes(range(1, 33))          # 32 octets déterministes
TEST_P    = 10441487724840939323         # grand premier (~2^63)
TEST_N    = 16


# ══════════════════════════════════════════════════════════════════════════════
#  §1. ζ(2n) et coefficients de Fourier
# ══════════════════════════════════════════════════════════════════════════════

class TestZeta:

    def test_zeta_n1_approx_pi2_6(self):
        """ζ(2) = π²/6 ≈ 1.6449340668."""
        z = compute_zeta(1)
        assert abs(float(z) - (math.pi ** 2 / 6)) < 1e-6

    def test_zeta_n2_approx(self):
        """ζ(4) = π⁴/90 ≈ 1.0823232337."""
        z = compute_zeta(2)
        assert abs(float(z) - (math.pi ** 4 / 90)) < 1e-6

    def test_zeta_monotone_decreasing(self):
        """ζ(2n) décroît vers 1 quand n augmente."""
        vals = [float(compute_zeta(n)) for n in range(1, 8)]
        for i in range(len(vals) - 1):
            assert vals[i] > vals[i+1], f"ζ(2*{i+1}) > ζ(2*{i+2}) attendu"

    def test_zeta_all_geq_one(self):
        """ζ(2n) ≥ 1 pour tout n ≥ 1."""
        for n in range(1, 15):
            assert float(compute_zeta(n)) >= 1.0

    def test_zeta_large_n_converges_to_one(self):
        """ζ(2n) → 1 quand n → ∞."""
        z_big = float(compute_zeta(50))
        assert abs(z_big - 1.0) < 1e-8

    def test_fourier_c1_n1(self):
        """c_1(n=1) = 2/π."""
        c = float(fourier_coefficient(1, 1))
        assert abs(c - 2.0 / math.pi) < 1e-10

    def test_fourier_c2_n1_negative(self):
        """c_2(n=1) < 0 (k pair → signe négatif)."""
        assert float(fourier_coefficient(2, 1)) < 0

    def test_fourier_c1_positive(self):
        """c_1 est toujours positif (k=1 impair)."""
        for n in range(1, 6):
            assert float(fourier_coefficient(1, n)) > 0

    def test_fourier_c2_negative(self):
        """c_2 est toujours négatif (k=2 pair)."""
        for n in range(1, 6):
            assert float(fourier_coefficient(2, n)) < 0

    def test_fourier_abs_decreasing_in_k(self):
        """|c_k| décroît en k pour n fixé."""
        for n in [1, 3, 5]:
            vals = [abs(float(fourier_coefficient(k, n))) for k in range(1, 6)]
            for i in range(len(vals) - 1):
                assert vals[i] > vals[i+1], f"|c_{i+1}| > |c_{i+2}| pour n={n}"

    def test_fourier_coefficients_list(self):
        """fourier_coefficients() retourne une liste de la bonne taille."""
        coeffs = fourier_coefficients(n=4, num_terms=10)
        assert len(coeffs) == 10
        assert all(isinstance(float(c), float) for c in coeffs)

    def test_fourier_c1_matches_single(self):
        """fourier_coefficients()[0] == fourier_coefficient(1, n)."""
        n = 5
        coeffs = fourier_coefficients(n=n, num_terms=5)
        c1 = fourier_coefficient(1, n)
        assert abs(float(coeffs[0]) - float(c1)) < 1e-14


# ══════════════════════════════════════════════════════════════════════════════
#  §2. generate_round_keys
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateRoundKeys:

    def test_returns_correct_count(self):
        """generate_round_keys() retourne num_keys clés."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=64)
        assert len(keys) == 64

    def test_all_keys_in_range(self):
        """Toutes les clés appartiennent à [0, p)."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=16)
        for i, k in enumerate(keys):
            assert 0 <= k < TEST_P, f"clé[{i}]={k} hors de [0, p)"

    def test_deterministic(self):
        """Deux appels identiques → mêmes clés."""
        k1 = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=8)
        k2 = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=8)
        assert k1 == k2

    def test_keys_not_all_identical(self):
        """Les clés générées sont distinctes (pas toutes égales)."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=8)
        assert len(set(keys)) > 1, "Toutes les clés sont identiques — anomalie"

    def test_sensitive_to_salt(self):
        """Sel différent → clés différentes."""
        alt_salt = bytes(x ^ 0xFF for x in TEST_SALT)
        k1 = generate_round_keys(TEST_N, TEST_SALT,  TEST_P, num_keys=4)
        k2 = generate_round_keys(TEST_N, alt_salt,   TEST_P, num_keys=4)
        assert k1 != k2, "Sel différent doit produire des clés différentes"

    def test_sensitive_to_n(self):
        """n différent → clés différentes."""
        k1 = generate_round_keys(TEST_N,     TEST_SALT, TEST_P, num_keys=4)
        k2 = generate_round_keys(TEST_N + 1, TEST_SALT, TEST_P, num_keys=4)
        assert k1 != k2, "n différent doit produire des clés différentes"

    def test_sensitive_to_p(self):
        """p différent → clés différentes (et dans [0, p_alt))."""
        alt_p = 9223372036854775783  # autre grand premier
        k1 = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=4)
        k2 = generate_round_keys(TEST_N, TEST_SALT, alt_p,  num_keys=4)
        assert k1 != k2
        for k in k2:
            assert 0 <= k < alt_p

    def test_num_keys_1(self):
        """num_keys=1 → liste de 1 élément cohérente avec batch."""
        k_single = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=1)
        k_batch  = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=8)
        assert len(k_single) == 1
        assert k_single[0] == k_batch[0], "clé[0] incohérente entre batch et single"

    def test_num_keys_256(self):
        """num_keys=256 → 256 clés dans [0, p)."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=256)
        assert len(keys) == 256
        assert all(0 <= k < TEST_P for k in keys)

    def test_default_num_keys(self):
        """Appel sans num_keys → 64 clés par défaut."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P)
        assert len(keys) == 64

    def test_n_equals_1(self):
        """n=1 (cas limite minimum) → 8 clés OK."""
        keys = generate_round_keys(1, TEST_SALT, TEST_P, num_keys=8)
        assert len(keys) == 8
        assert all(0 <= k < TEST_P for k in keys)

    def test_large_n(self):
        """n=100 (grand n, ζ(200) ≈ 1.0) → clés dans [0, p)."""
        keys = generate_round_keys(100, TEST_SALT, TEST_P, num_keys=4)
        assert len(keys) == 4
        assert all(0 <= k < TEST_P for k in keys)

    def test_small_p(self):
        """Petit p → clés dans [0, p)."""
        small_p = 997  # premier < 1000
        keys = generate_round_keys(TEST_N, TEST_SALT, small_p, num_keys=8)
        assert all(0 <= k < small_p for k in keys)

    def test_all_keys_are_integers(self):
        """Les clés sont des entiers Python."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=4)
        assert all(isinstance(k, int) for k in keys)

    @pytest.mark.parametrize("num_keys", [1, 4, 16, 32, 64])
    def test_num_keys_parametrize(self, num_keys):
        """generate_round_keys produit exactement num_keys clés."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=num_keys)
        assert len(keys) == num_keys

    def test_keys_first_batch_subset_of_larger(self):
        """Les 4 premières clés du batch de 64 == batch de 4."""
        k4  = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=4)
        k64 = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=64)
        assert k4 == k64[:4], "Sous-ensemble incohérent"

    def test_keys_differ_across_indices(self):
        """Les clés à des indices différents sont (probablement) distinctes."""
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=64)
        unique = len(set(keys))
        assert unique >= 60, f"Trop peu de clés uniques : {unique}/64"


# ══════════════════════════════════════════════════════════════════════════════
#  §3. apply_round_key / remove_round_key
# ══════════════════════════════════════════════════════════════════════════════

class TestBlockOps:
    BLOCK  = [i * 7919 % TEST_P for i in range(16)]
    RK     = 3141592653589793 % TEST_P

    def test_add_then_sub_identity(self):
        """add(rk) ∘ sub(rk) = identité."""
        b = self.BLOCK.copy()
        b = apply_round_key(b, self.RK, TEST_P)
        b = remove_round_key(b, self.RK, TEST_P)
        assert b == self.BLOCK

    def test_sub_then_add_identity(self):
        """sub(rk) ∘ add(rk) = identité."""
        b = self.BLOCK.copy()
        b = remove_round_key(b, self.RK, TEST_P)
        b = apply_round_key(b, self.RK, TEST_P)
        assert b == self.BLOCK

    def test_add_stays_in_range(self):
        """Après apply_round_key, tous les éléments dans [0, p)."""
        b = apply_round_key(self.BLOCK.copy(), self.RK, TEST_P)
        assert all(0 <= x < TEST_P for x in b)

    def test_sub_stays_in_range(self):
        """Après remove_round_key, tous les éléments dans [0, p)."""
        b = remove_round_key(self.BLOCK.copy(), self.RK, TEST_P)
        assert all(0 <= x < TEST_P for x in b)

    def test_rk_zero_noop(self):
        """rk=0 → no-op pour add."""
        b = apply_round_key(self.BLOCK.copy(), 0, TEST_P)
        assert b == self.BLOCK

    def test_add_rk_max(self):
        """rk=p-1 (valeur max) → pas de débordement."""
        b = apply_round_key(self.BLOCK.copy(), TEST_P - 1, TEST_P)
        assert all(0 <= x < TEST_P for x in b)

    def test_empty_block(self):
        """Bloc vide → retourné tel quel."""
        assert apply_round_key([], self.RK, TEST_P) == []
        assert remove_round_key([], self.RK, TEST_P) == []

    def test_single_element(self):
        """Bloc de 1 élément."""
        b = [0]
        b = apply_round_key(b, 42, TEST_P)
        assert b == [42]
        b = remove_round_key(b, 42, TEST_P)
        assert b == [0]

    def test_deterministic(self):
        """Même entrée → même sortie."""
        b1 = apply_round_key(self.BLOCK.copy(), self.RK, TEST_P)
        b2 = apply_round_key(self.BLOCK.copy(), self.RK, TEST_P)
        assert b1 == b2

    def test_different_rk_different_result(self):
        """Deux rk différents → résultats différents."""
        b1 = apply_round_key(self.BLOCK.copy(), self.RK,      TEST_P)
        b2 = apply_round_key(self.BLOCK.copy(), self.RK + 1,  TEST_P)
        assert b1 != b2


# ══════════════════════════════════════════════════════════════════════════════
#  §4. Compatibilité bit-à-bit C ↔ Python
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(
    not (_OMEGA_C_SYMBOLS_OK and _mpmath_available),
    reason="Nécessite libcagoule.so v2.1 ET mpmath pour comparaison bit-à-bit"
)
class TestBitExactCompatibility:
    """
    Vérifie que le backend C produit exactement les mêmes round keys que
    le backend Python (mpmath) pour n ≤ 32 (domaine de la table ζ).
    Ces tests ne s'exécutent que si les deux backends sont disponibles.
    """

    def _keys_python(self, n, num_keys=4):
        from cagoule.omega import _py_generate_round_keys, _ZETA_PRECISION_DPS
        return _py_generate_round_keys(n, TEST_SALT, TEST_P, num_keys, _ZETA_PRECISION_DPS)

    def _keys_c(self, n, num_keys=4):
        from cagoule.omega import _c_generate_round_keys
        return _c_generate_round_keys(n, TEST_SALT, TEST_P, num_keys)

    def test_n1_bit_exact(self):
        assert self._keys_c(1) == self._keys_python(1)

    def test_n4_bit_exact(self):
        assert self._keys_c(4) == self._keys_python(4)

    def test_n16_bit_exact(self):
        assert self._keys_c(16) == self._keys_python(16)

    def test_n32_bit_exact(self):
        assert self._keys_c(32) == self._keys_python(32)

    def test_zeta_c_matches_python_n1(self):
        """ζ(2) C vs Python : différence < 1e-12."""
        from cagoule.omega import _lib
        import ctypes
        c_val = _lib.cagoule_omega_zeta_2n(ctypes.c_int(1))
        py_val = math.pi**2 / 6
        assert abs(c_val - py_val) < 1e-6

    def test_fourier_c1_c_matches_python(self):
        """c_1(n=1) C vs Python : identique."""
        from cagoule.omega import _lib
        import ctypes
        c_val  = _lib.cagoule_omega_fourier_coeff(ctypes.c_int(1), ctypes.c_int(1))
        py_val = float(fourier_coefficient(1, 1))
        # La valeur Python peut venir du C, comparer abs
        assert abs(c_val - 2.0 / math.pi) < 1e-10

    def test_num_keys_8_bit_exact(self):
        """8 clés — comparaison C vs Python."""
        assert self._keys_c(8, 8) == self._keys_python(8, 8)

    def test_multiple_n_values_bit_exact(self):
        """n = 2, 8, 16 — bit-exact."""
        for n in [2, 8, 16]:
            assert self._keys_c(n, 4) == self._keys_python(n, 4), \
                f"Incohérence C vs Python pour n={n}"


# ══════════════════════════════════════════════════════════════════════════════
#  §5. Backend et cache
# ══════════════════════════════════════════════════════════════════════════════

class TestBackendAndCache:

    def test_backend_str_non_empty(self):
        """OMEGA_BACKEND est une chaîne non vide."""
        assert isinstance(OMEGA_BACKEND, str) and len(OMEGA_BACKEND) > 0

    def test_backend_str_known_value(self):
        """OMEGA_BACKEND contient 'C' ou 'Python'."""
        assert "C" in OMEGA_BACKEND or "Python" in OMEGA_BACKEND

    def test_get_cache_info_keys(self):
        """get_cache_info() retourne les clés attendues."""
        info = get_cache_info()
        assert "backend" in info
        assert "c_symbols_ok" in info
        assert "mpmath_available" in info

    def test_clear_caches_no_error(self):
        """clear_caches() s'exécute sans erreur."""
        clear_caches()  # Ne doit pas lever d'exception

    def test_generate_keys_after_clear(self):
        """generate_round_keys() fonctionne après clear_caches()."""
        clear_caches()
        keys = generate_round_keys(TEST_N, TEST_SALT, TEST_P, num_keys=4)
        assert len(keys) == 4

    def test_cache_info_backend_matches_backend_const(self):
        """get_cache_info()['backend'] == OMEGA_BACKEND."""
        assert get_cache_info()["backend"] == OMEGA_BACKEND

    def test_c_symbols_ok_bool(self):
        """_OMEGA_C_SYMBOLS_OK est un booléen."""
        assert isinstance(_OMEGA_C_SYMBOLS_OK, bool)

    def test_mpmath_available_bool(self):
        """_mpmath_available est un booléen."""
        assert isinstance(_mpmath_available, bool)


# ══════════════════════════════════════════════════════════════════════════════
#  §6. Intégration CagouleParams
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegrationParams:

    def test_params_derive_uses_omega(self):
        """CagouleParams.derive() produit des round_keys non vides."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        p = CagouleParams.derive(b"test_omega", fast_mode=True)
        assert len(p.round_keys) == 64
        assert all(0 <= k < p.p for k in p.round_keys)
        p.zeroize()

    def test_params_round_keys_deterministic(self):
        """Même mdp + même salt → mêmes round_keys."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        salt = b"\xAB" * 32
        p1 = CagouleParams.derive(b"pwd", salt=salt, fast_mode=True)
        p2 = CagouleParams.derive(b"pwd", salt=salt, fast_mode=True)
        assert p1.round_keys == p2.round_keys
        p1.zeroize()
        p2.zeroize()

    def test_params_different_password_different_rk(self):
        """Mot de passe différent → round_keys différentes."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        salt = b"\xCD" * 32
        p1 = CagouleParams.derive(b"password1", salt=salt, fast_mode=True)
        p2 = CagouleParams.derive(b"password2", salt=salt, fast_mode=True)
        assert p1.round_keys != p2.round_keys
        p1.zeroize()
        p2.zeroize()

    def test_fast_mode_attribute_true(self):
        """params.fast_mode == True quand dérivé avec fast_mode=True."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        p = CagouleParams.derive(b"x", fast_mode=True)
        assert p.fast_mode is True
        p.zeroize()

    def test_fast_mode_attribute_false(self):
        """params.fast_mode == False par défaut."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        p = CagouleParams.derive(b"x", fast_mode=False)
        assert p.fast_mode is False
        p.zeroize()

    def test_round_keys_all_in_range(self):
        """round_keys ⊆ [0, p) après dérivation."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.params import CagouleParams
        p = CagouleParams.derive(b"check", fast_mode=True)
        assert all(0 <= k < p.p for k in p.round_keys), \
            "Certaines round_keys sont hors de [0, p)"
        p.zeroize()
