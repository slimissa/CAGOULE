"""
test_fp2.py — Tests complets pour fp2.py (extension quadratique Fp²)

Couvre :
- Arithmétique de base (add, sub, mul, pow, neg)
- Inversion et norme
- Racine carrée dans Fp²
- Cas limites (zéro, un, p=2, p=3)
- Plongement Fp → Fp²
- Vérification algébrique : t² + t + 1 = 0

Note : Pour p ≡ 1 mod 3 (ex: 7, 13, 19, 97), Fp² contient des diviseurs de zéro
(éléments avec norme nulle). Les tests d'inversion ignorent ces éléments.
"""

import pytest


# ─── Fixtures ────────────────────────────────────────────────────────────────

PRIMES = [5, 7, 11, 13, 17, 19, 23, 97, 257, 65537]


def E(a, b, p):
    """Raccourci : créer un Fp2Element."""
    from cagoule.fp2 import Fp2Element
    return Fp2Element(a, b, p)


def is_invertible(x) -> bool:
    """Vérifie si un élément Fp² est inversible (norme ≠ 0)."""
    norm = (x.a * x.a - x.a * x.b + x.b * x.b) % x.p
    return norm != 0


# ─── Arithmétique de base ─────────────────────────────────────────────────────

class TestFp2Arithmetic:

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_add_commutatif(self, p):
        x = E(2, 3, p)
        y = E(4, 1, p)
        assert x + y == y + x

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_add_associatif(self, p):
        x, y, z = E(1, 2, p), E(3, 4, p), E(0, 1, p)
        assert (x + y) + z == x + (y + z)

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_add_neutre(self, p):
        x = E(3, 4, p)
        zero = E(0, 0, p)
        assert x + zero == x

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_neg(self, p):
        x = E(3, 4, p)
        assert x + (-x) == E(0, 0, p)

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_sub(self, p):
        x = E(3, 4, p)
        y = E(1, 2, p)
        assert x - y == E(2, 2, p)

    @pytest.mark.parametrize("p", [5, 7, 13])
    def test_mul_commutatif(self, p):
        x = E(2, 3, p)
        y = E(1, 4, p)
        assert x * y == y * x

    @pytest.mark.parametrize("p", [5, 7, 13])
    def test_mul_associatif(self, p):
        x, y, z = E(1, 2, p), E(3, 1, p), E(2, 3, p)
        assert (x * y) * z == x * (y * z)

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_mul_neutre(self, p):
        x = E(3, 4, p)
        one = E(1, 0, p)
        assert x * one == x

    @pytest.mark.parametrize("p", [5, 7, 13])
    def test_distributivite(self, p):
        x, y, z = E(2, 1, p), E(3, 4, p), E(1, 2, p)
        assert x * (y + z) == x * y + x * z

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_scalar_mul(self, p):
        x = E(2, 3, p)
        assert 3 * x == x + x + x

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_pow_zero(self, p):
        x = E(2, 3, p)
        assert x ** 0 == E(1, 0, p)

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_pow_un(self, p):
        x = E(2, 3, p)
        assert x ** 1 == x

    @pytest.mark.parametrize("p", [5, 7, 13, 97])
    def test_pow_deux(self, p):
        x = E(2, 3, p)
        assert x ** 2 == x * x

    @pytest.mark.parametrize("p", [5, 7, 13])
    def test_pow_grand(self, p):
        x = E(2, 1, p)
        # Petit théorème de Fermat généralisé : x^(p²-1) = 1 dans Fp²*
        # Attention: ne s'applique qu'aux éléments inversibles
        if is_invertible(x):
            result = x ** (p * p - 1)
            assert result == E(1, 0, p)
        else:
            pytest.skip(f"Élément non inversible pour p={p}")


# ─── Vérification de la relation t² + t + 1 = 0 ──────────────────────────────

class TestGeneratorT:

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_satisfait_relation(self, p):
        """t² + t + 1 = 0 dans Fp² par construction."""
        from cagoule.fp2 import Fp2Element
        t = Fp2Element.t_generator(p)
        un = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)
        assert t * t + t + un == zero, f"t²+t+1 ≠ 0 pour p={p}"

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_cube_vaut_un(self, p):
        """t est une racine primitive cubique de l'unité : t³ = 1."""
        from cagoule.fp2 import Fp2Element
        t = Fp2Element.t_generator(p)
        un = Fp2Element(1, 0, p)
        assert t ** 3 == un, f"t³ ≠ 1 pour p={p}"

    @pytest.mark.parametrize("p", PRIMES)
    def test_t_est_racine_x4_x2_1(self, p):
        """t est racine de x⁴+x²+1 — la même équation utilisée pour µ."""
        from cagoule.fp2 import Fp2Element
        t = Fp2Element.t_generator(p)
        un = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)
        result = t ** 4 + t ** 2 + un
        assert result == zero, f"t⁴+t²+1 ≠ 0 pour p={p}"


# ─── Inversion ────────────────────────────────────────────────────────────────

class TestFp2Inverse:

    @pytest.mark.parametrize("p", [7, 13, 97, 257])
    def test_inverse_produit(self, p):
        """x * x⁻¹ = 1 (vérifie d'abord que x est inversible)."""
        x = E(3, 4, p)
        if not is_invertible(x):
            pytest.skip(f"Élément non inversible pour p={p} (norme nulle)")
        assert x * x.inverse() == E(1, 0, p)

    @pytest.mark.parametrize("p", [7, 13, 97, 257])
    def test_inverse_de_un(self, p):
        un = E(1, 0, p)
        assert un.inverse() == un

    @pytest.mark.parametrize("p", [5, 7, 11, 13])
    def test_inverse_exhaustif(self, p):
        """
        Vérifie x * x⁻¹ = 1 pour tous les x inversibles de Fp².

        Note : pour p ≡ 1 mod 3, certains éléments non nuls ont une norme
        nulle (diviseurs de zéro) et ne sont pas inversibles — on les exclut.
        Pour p ≡ 2 mod 3, tous les éléments non nuls sont inversibles.
        """
        from cagoule.fp2 import Fp2Element
        one = Fp2Element(1, 0, p)
        count = 0
        for a in range(p):
            for b in range(p):
                x = Fp2Element(a, b, p)
                if x.is_zero():
                    continue
                # Exclure les diviseurs de zéro (norme nulle)
                norm = (a * a - a * b + b * b) % p
                if norm == 0:
                    continue
                assert x * x.inverse() == one, f"x*x⁻¹ ≠ 1 pour ({a},{b}) mod {p}"
                count += 1
        assert count > 0, "Aucun élément inversible trouvé"

    def test_inverse_zero_leve_exception(self):
        from cagoule.fp2 import Fp2Element
        with pytest.raises(ZeroDivisionError):
            Fp2Element(0, 0, 7).inverse()

    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_pow_negatif(self, p):
        """x ** -1 = x.inverse() (vérifie d'abord que x est inversible)."""
        x = E(2, 3, p)
        if not is_invertible(x):
            pytest.skip(f"Élément non inversible pour p={p} (norme nulle)")
        assert x ** -1 == x.inverse()
        assert x ** -2 == (x * x).inverse()


# ─── Racine carrée ────────────────────────────────────────────────────────────

class TestFp2Sqrt:

    @pytest.mark.parametrize("p", [7, 11, 13, 17, 19])
    def test_sqrt_zero(self, p):
        zero = E(0, 0, p)
        assert zero.sqrt() == zero

    @pytest.mark.parametrize("p", [7, 11, 13, 17, 19, 97])
    def test_sqrt_carre_inverse(self, p):
        """(x.sqrt())² = x pour les éléments qui ont une racine."""
        from cagoule.fp2 import Fp2Element
        # Construire un carré certain
        x = Fp2Element(2, 3, p)
        x2 = x * x
        root = x2.sqrt()
        # La racine au carré doit redonner x²
        assert root * root == x2

    @pytest.mark.parametrize("p", [7, 13, 17])
    def test_sqrt_element_fp(self, p):
        """Racine d'un élément de Fp (b=0) donne bien un élément dont le carré = x."""
        from cagoule.fp2 import Fp2Element
        # Trouver un carré dans Fp
        for a in range(1, p):
            if pow(a, (p - 1) // 2, p) == 1:  # a est un carré dans Fp
                x = Fp2Element(a, 0, p)
                root = x.sqrt()
                assert root * root == x
                break


# ─── Plongement et conversions ────────────────────────────────────────────────

class TestFp2Conversions:

    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_from_int(self, p):
        from cagoule.fp2 import Fp2Element
        x = Fp2Element.from_int(5, p)
        assert x.a == 5 % p
        assert x.b == 0

    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_to_int(self, p):
        from cagoule.fp2 import Fp2Element
        x = Fp2Element.from_int(5, p)
        assert x.to_int() == 5 % p

    def test_to_int_echec_si_b_nonzero(self):
        from cagoule.fp2 import Fp2Element
        with pytest.raises(ValueError):
            Fp2Element(1, 2, 7).to_int()

    @pytest.mark.parametrize("p,a", [(7, 3), (13, 7), (97, 42)])
    def test_eq_int(self, p, a):
        from cagoule.fp2 import Fp2Element
        x = Fp2Element(a, 0, p)
        assert x == a

    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_is_zero(self, p):
        assert E(0, 0, p).is_zero()
        assert not E(1, 0, p).is_zero()
        assert not E(0, 1, p).is_zero()

    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_is_one(self, p):
        assert E(1, 0, p).is_one()
        assert not E(0, 1, p).is_one()
        assert not E(0, 0, p).is_one()


# ─── Compatibilité de corps ───────────────────────────────────────────────────

class TestFp2FieldCheck:

    def test_op_corps_differents_leve_exception(self):
        from cagoule.fp2 import Fp2Element
        x = Fp2Element(1, 2, 7)
        y = Fp2Element(1, 2, 11)
        with pytest.raises(ValueError):
            _ = x + y
        with pytest.raises(ValueError):
            _ = x * y