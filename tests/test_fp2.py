"""test_fp2.py — Tests Fp² = Z/pZ[t]/(t²+t+1) — CAGOULE v3.1.0"""

import pytest
from cagoule.fp2 import Fp2Element

# Premiers de test (petits à moyens)
PRIMES = [5, 7, 11, 13, 17, 19, 23, 97, 257, 65537]
PRIMES_SMALL = [5, 7, 11, 13, 17]  # Pour tests exhaustifs


def E(a, b, p):
    """Helper pour créer un élément Fp2."""
    return Fp2Element(a, b, p)


def invertible(x):
    """Vérifie si x est inversible (norme ≠ 0)."""
    return (x.a * x.a - x.a * x.b + x.b * x.b) % x.p != 0


# ============================================================
# Tests arithmétiques basiques
# ============================================================

class TestArithmetic:
    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_add_comm(self, p):
        """Addition commutative."""
        assert E(2, 3, p) + E(4, 1, p) == E(4, 1, p) + E(2, 3, p)

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_neutre_add(self, p):
        """Élément neutre additif (0,0)."""
        x = E(3, 4, p)
        assert x + E(0, 0, p) == x

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_neg(self, p):
        """Opposé : x + (-x) = 0."""
        x = E(3, 4, p)
        assert x + (-x) == E(0, 0, p)

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_mul_neutre(self, p):
        """Élément neutre multiplicatif (1,0)."""
        x = E(3, 4, p)
        assert x * E(1, 0, p) == x

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_pow0(self, p):
        """x^0 = 1."""
        assert E(2, 3, p) ** 0 == E(1, 0, p)

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_pow1(self, p):
        """x^1 = x."""
        x = E(2, 3, p)
        assert x ** 1 == x

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_pow2(self, p):
        """x^2 = x * x."""
        x = E(2, 3, p)
        assert x ** 2 == x * x

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_pow_negatif(self, p):
        """x^-1 doit être l'inverse de x."""
        x = E(2, 3, p)
        if invertible(x):
            assert x ** -1 == x.inverse()


# ============================================================
# Tests algébriques spécifiques à Fp²
# ============================================================

class TestAlgebraic:
    @pytest.mark.parametrize("p", PRIMES)
    def test_t_relation(self, p):
        """t² + t + 1 = 0 dans Fp²."""
        t = Fp2Element.t_generator(p)
        un = E(1, 0, p)
        zero = E(0, 0, p)
        assert t * t + t + un == zero

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_cube_un(self, p):
        """t³ = 1 (t est racine cubique de l'unité)."""
        t = Fp2Element.t_generator(p)
        assert t ** 3 == E(1, 0, p)

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_x4x2_1(self, p):
        """t⁴ + t² + 1 = 0 (t est racine de x⁴+x²+1)."""
        t = Fp2Element.t_generator(p)
        un = E(1, 0, p)
        zero = E(0, 0, p)
        assert t ** 4 + t ** 2 + un == zero

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_generator(self, p):
        """Vérifie le générateur t."""
        t = Fp2Element.t_generator(p)
        assert t.a == 0 and t.b == 1

    @pytest.mark.parametrize("p", PRIMES)
    def test_fermat(self, p):
        """Petit théorème de Fermat: x^(p²-1) = 1 pour x inversible."""
        x = E(2, 1, p)
        if invertible(x):
            assert x ** (p * p - 1) == E(1, 0, p)


# ============================================================
# Tests d'inverse
# ============================================================

class TestInverse:
    @pytest.mark.parametrize("p", [7, 13, 97, 257])
    def test_inv_produit(self, p):
        """x * x.inverse() = 1."""
        x = E(3, 4, p)
        if invertible(x):
            assert x * x.inverse() == E(1, 0, p)

    def test_inv_zero_exc(self):
        """L'inverse de zéro doit lever ZeroDivisionError."""
        with pytest.raises(ZeroDivisionError):
            E(0, 0, 7).inverse()

    def test_diff_field_exc(self):
        """L'addition entre corps différents doit lever ValueError."""
        with pytest.raises(ValueError):
            E(1, 2, 7) + E(1, 2, 11)

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_inv_exhaustif(self, p):
        """Vérifie l'inverse pour tous les éléments inversibles."""
        one = E(1, 0, p)
        for a in range(p):
            for b in range(p):
                x = E(a, b, p)
                if x.is_zero() or not invertible(x):
                    continue
                inv = x.inverse()
                assert x * inv == one
                assert inv * x == one  # commutativité


# ============================================================
# Tests de sqrt (optionnel)
# ============================================================

class TestSqrt:
    """
    CORRECTIF v3.0.1 : remplace l'ancien test qui acceptait silencieusement
    ArithmeticError comme un pass — masquant le fait que la formule
    (p²+1)//4 (puis (p²+p)//4) était simplement fausse pour ce corps,
    sans jamais distinguer "pas de racine pour cet élément" (normal,
    ~moitié des éléments) de "l'algorithme est cassé pour ce p" (bug réel).

    sqrt() utilise maintenant Tonelli-Shanks général sur le groupe
    multiplicatif de Fp² — valide SSI Z/pZ[t]/(t²+t+1) est un corps,
    ce qui équivaut à p ≡ 2 (mod 3) (sinon t²+t+1 se factorise par CRT
    et l'anneau a des diviseurs de zéro — Tonelli-Shanks ne s'applique pas).
    """

    @staticmethod
    def _brute_force_sqrt(elem: Fp2Element, p: int):
        for a in range(p):
            for b in range(p):
                r = Fp2Element(a, b, p)
                if r * r == elem:
                    return r
        return None

    @pytest.mark.parametrize("p", [pr for pr in PRIMES_SMALL if pr % 3 == 2])
    def test_sqrt_matches_brute_force_on_field_primes(self, p):
        """
        Pour chaque p ≡ 2 (mod 3) (cas où Fp² est un vrai corps), sqrt()
        DOIT être cohérent avec la recherche exhaustive — pas de tolérance
        à l'échec silencieux. Couvre tous les éléments non nuls (p petit).
        """
        for a in range(p):
            for b in range(p):
                elem = Fp2Element(a, b, p)
                if elem.is_zero():
                    continue
                bf = self._brute_force_sqrt(elem, p)
                try:
                    r = elem.sqrt()
                    assert bf is not None, (
                        f"sqrt() a trouvé une racine pour {elem} (p={p}) "
                        f"mais la recherche exhaustive n'en trouve aucune."
                    )
                    assert r * r == elem, f"sqrt({elem})²  ≠  {elem} (p={p})"
                except ArithmeticError:
                    assert bf is None, (
                        f"sqrt() a levé ArithmeticError pour {elem} (p={p}) "
                        f"alors qu'une racine {bf} existe — algorithme cassé, "
                        f"pas juste 'pas de racine pour cet élément'."
                    )

    @pytest.mark.parametrize("p", [pr for pr in PRIMES_SMALL if pr % 3 == 1])
    def test_sqrt_rejects_non_field_primes_explicitly(self, p):
        """
        Pour p ≡ 1 (mod 3), Z/pZ[t]/(t²+t+1) n'est PAS un corps — sqrt()
        doit lever une ArithmeticError explicite mentionnant la précondition
        de corps, jamais silencieusement un résultat faux ni un message
        générique de "pas de racine pour cet élément".
        """
        t = Fp2Element.t_generator(p)
        with pytest.raises(ArithmeticError, match="N'EST PAS UN CORPS"):
            t.sqrt()

    def test_sqrt_production_primes_field_cases(self):
        """
        Sur les 6 primes de production (Mersenne-64) où p ≡ 2 (mod 3),
        toute racine trouvée doit être algébriquement correcte
        (r² == élément d'origine). Échantillonnage (p trop grand pour
        une vérification exhaustive).
        """
        import random
        from cagoule.params import MERSENNE_POOL
        rng = random.Random(20260101)
        n_verified = 0
        for k, p in MERSENNE_POOL:
            if p % 3 != 2:
                continue  # cas non-corps, couvert par le test suivant
            for _ in range(10):
                a, b = rng.randrange(p), rng.randrange(p)
                elem = Fp2Element(a, b, p)
                if elem.is_zero():
                    continue
                try:
                    r = elem.sqrt()
                    assert r * r == elem, f"sqrt incorrect pour p=2^64-{k}"
                    n_verified += 1
                except ArithmeticError as e:
                    assert "non résidu quadratique" in str(e), (
                        f"Erreur inattendue sur prime de production p=2^64-{k}: {e}"
                    )
        assert n_verified > 0, "Aucune racine vérifiée — le test n'exerce rien"

    def test_sqrt_production_primes_non_field_cases(self):
        """
        Les 2 primes de production où p ≡ 1 (mod 3) (k=189, k=279) doivent
        rejeter sqrt() explicitement. Confirme que generate_mu() les évite
        déjà via la stratégie A (Z/pZ direct, pas Fp²) — sqrt() cassé sur
        ces primes ne peut donc pas affecter le pipeline réel.
        """
        from cagoule.params import MERSENNE_POOL
        non_field_primes = [(k, p) for k, p in MERSENNE_POOL if p % 3 != 2]
        assert len(non_field_primes) == 2, (
            "Nombre de primes non-corps inattendu — vérifier MERSENNE_POOL"
        )
        for k, p in non_field_primes:
            t = Fp2Element.t_generator(p)
            with pytest.raises(ArithmeticError, match="N'EST PAS UN CORPS"):
                t.sqrt()


# ============================================================
# Tests de conversion
# ============================================================

class TestConversions:
    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_from_int(self, p):
        """from_int doit créer (value mod p, 0)."""
        x = Fp2Element.from_int(5, p)
        assert x.a == 5 % p and x.b == 0

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_to_int(self, p):
        """to_int doit retourner a mod p si b=0."""
        assert Fp2Element.from_int(5, p).to_int() == 5 % p

    def test_to_int_exc(self):
        """to_int doit lever ValueError si b ≠ 0."""
        with pytest.raises(ValueError):
            E(1, 2, 7).to_int()

    def test_is_zero(self):
        """is_zero détecte (0,0)."""
        assert E(0, 0, 7).is_zero()
        assert not E(1, 0, 7).is_zero()

    def test_is_one(self):
        """is_one détecte (1,0)."""
        assert E(1, 0, 7).is_one()
        assert not E(0, 1, 7).is_one()


# ============================================================
# Tests de validation des préconditions
# ============================================================

class TestConstruction:
    def test_p_invalide(self):
        """p doit être ≥ 2."""
        with pytest.raises(ValueError):
            Fp2Element(1, 2, 1)

    @pytest.mark.parametrize("p", PRIMES)
    def test_p_valide(self, p):
        """Construction avec p valide."""
        x = E(1, 2, p)
        assert x.p == p