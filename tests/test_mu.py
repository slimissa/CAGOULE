"""test_mu.py — Tests génération de µ (racines x⁴+x²+1) — CAGOULE v2.0.0"""

import pytest
from cagoule.fp2 import Fp2Element
from cagoule.mu import generate_mu, _verify_root_zp, _verify_root_fp2, _mu_in_fp2

# p ≡ 2 mod 3 → solution dans Fp² (stratégie C)
PRIMES_C = [5, 11, 17, 23, 29, 41, 47, 59, 71, 83]

# p ≡ 1 mod 3 → solution dans Z/pZ (stratégie A)
PRIMES_A = [7, 13, 19, 31, 37, 43, 61, 67, 73, 79]

# Cas particuliers
P_SPECIAL = [2, 3]


def poly_zp(x, p):
    """Évalue x⁴ + x² + 1 mod p."""
    return (pow(x, 4, p) + pow(x, 2, p) + 1) % p


# ============================================================
# Vérification des préconditions mathématiques
# ============================================================

class TestPreconditions:
    """Vérifie que les listes de premiers sont correctes."""

    def test_primes_a_mod_3(self):
        """Les premiers de PRIMES_A doivent être ≡ 1 mod 3."""
        for p in PRIMES_A:
            assert p % 3 == 1, f"{p} doit être ≡ 1 mod 3"

    def test_primes_c_mod_3(self):
        """Les premiers de PRIMES_C doivent être ≡ 2 mod 3."""
        for p in PRIMES_C:
            assert p % 3 == 2, f"{p} doit être ≡ 2 mod 3"


# ============================================================
# Tests stratégie A (µ dans Z/pZ)
# ============================================================

class TestStrategyA:
    @pytest.mark.parametrize("p", PRIMES_A)
    def test_valide(self, p):
        """µ doit vérifier x⁴ + x² + 1 = 0 mod p."""
        r = generate_mu(p)
        if r.strategy == "A":
            assert poly_zp(r.as_int(), p) == 0

    @pytest.mark.parametrize("p", PRIMES_A)
    def test_dans_zp(self, p):
        """µ doit être dans Z/pZ (int)."""
        r = generate_mu(p)
        if r.strategy == "A":
            assert not r.in_fp2
            assert isinstance(r.as_int(), int)
            assert 0 <= r.as_int() < p

    @pytest.mark.parametrize("p", PRIMES_A)
    def test_as_fp2(self, p):
        """as_fp2() doit retourner un élément dans Fp (partie imaginaire nulle)."""
        r = generate_mu(p)
        if r.strategy == "A":
            fp2 = r.as_fp2()
            assert fp2.b == 0
            assert fp2.a == r.as_int()


# ============================================================
# Tests stratégie C (µ dans Fp²)
# ============================================================

class TestStrategyC:
    @pytest.mark.parametrize("p", PRIMES_C)
    def test_strat_c(self, p):
        """Pour p ≡ 2 mod 3, la stratégie C doit être utilisée."""
        r = generate_mu(p)
        assert r.strategy == "C"
        assert r.in_fp2

    @pytest.mark.parametrize("p", PRIMES_C)
    def test_verification_algebrique(self, p):
        """Vérifie que µ est bien racine dans Fp²."""
        r = generate_mu(p)
        assert _verify_root_fp2(r.mu, p)

    @pytest.mark.parametrize("p", PRIMES_C)
    def test_t_cube_un(self, p):
        """µ³ = 1 dans Fp² (µ est racine cubique de l'unité)."""
        r = generate_mu(p)
        if r.strategy == "C":
            assert r.as_fp2() ** 3 == Fp2Element(1, 0, p)

    @pytest.mark.parametrize("p", PRIMES_C)
    def test_as_int_exc(self, p):
        """as_int() doit lever TypeError pour µ dans Fp²."""
        r = generate_mu(p)
        if r.strategy == "C":
            with pytest.raises(TypeError):
                r.as_int()

    @pytest.mark.parametrize("p", PRIMES_C)
    def test_as_fp2_direct(self, p):
        """as_fp2() retourne l'élément Fp²."""
        r = generate_mu(p)
        if r.strategy == "C":
            assert isinstance(r.as_fp2(), Fp2Element)

    def test_direct_fp2(self):
        """_mu_in_fp2 retourne t (0,1)."""
        mu = _mu_in_fp2(11)
        assert mu.a == 0 and mu.b == 1
        assert _verify_root_fp2(mu, 11)


# ============================================================
# Tests de robustesse
# ============================================================

class TestRobustness:
    @pytest.mark.parametrize("p", PRIMES_A + PRIMES_C + P_SPECIAL)
    def test_ne_crashe_jamais(self, p):
        """generate_mu ne doit jamais planter."""
        r = generate_mu(p)
        assert r is not None
        assert r.strategy in ("A", "C")
        assert r.p == p

    @pytest.mark.parametrize("p", PRIMES_A)
    def test_repr(self, p):
        """__repr__ doit contenir des informations utiles."""
        r = generate_mu(p)
        rep = repr(r)
        assert "MuResult" in rep
        assert "strategy" in rep
        assert f"p={p}" in rep

    def test_pas_de_timeout_agressif(self):
        """Le timeout ne doit pas déclencher prématurément."""
        # Pour p grand, la recherche peut être plus longue
        r = generate_mu(65537, timeout_s=10.0)
        assert r is not None


# ============================================================
# Tests pour petits premiers (cas limites)
# ============================================================

class TestPetitsPremiers:
    @pytest.mark.parametrize("p", [2, 3])
    def test_petits_premiers_valides(self, p):
        """Les petits premiers doivent être gérés correctement."""
        r = generate_mu(p)
        assert r.strategy in ("A", "C")
        assert r.p == p

    @pytest.mark.parametrize("p", [2, 3])
    def test_petits_premiers_racine(self, p):
        """Vérifie que le résultat est racine dans le corps approprié."""
        r = generate_mu(p)
        un = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)

        if r.strategy == "A":
            assert poly_zp(r.as_int(), p) == 0
        else:
            mu = r.as_fp2()
            assert mu ** 4 + mu ** 2 + un == zero


# ============================================================
# Tests des propriétés de µ
# ============================================================

class TestMuProperties:
    @pytest.mark.parametrize("p", PRIMES_A + PRIMES_C + P_SPECIAL)
    def test_est_racine(self, p):
        """µ doit toujours être racine de x⁴ + x² + 1."""
        r = generate_mu(p)
        un = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)

        if r.strategy == "A":
            assert poly_zp(r.as_int(), p) == 0
        else:
            mu = r.as_fp2()
            assert mu ** 4 + mu ** 2 + un == zero

    @pytest.mark.parametrize("p", PRIMES_A + PRIMES_C)
    def test_mu_est_distinct_de_1(self, p):
        """µ ne doit pas être 1."""
        r = generate_mu(p)
        if r.strategy == "A":
            assert r.as_int() != 1 % p
        else:
            assert r.as_fp2() != Fp2Element(1, 0, p)

    @pytest.mark.parametrize("p", PRIMES_A + PRIMES_C)
    def test_mu_est_distinct_de_0(self, p):
        """µ ne doit pas être 0."""
        r = generate_mu(p)
        if r.strategy == "A":
            assert r.as_int() != 0
        else:
            assert not r.as_fp2().is_zero()