"""
test_matrix.py — Tests pour matrix.py

Couvre :
- Construction Vandermonde et Cauchy
- Inversion (P × P⁻¹ = I)
- apply / apply_inverse (round-trip)
- Cas dégénérés (nœuds non distincts → fallback Cauchy)
"""
import pytest


PRIMES = [7, 11, 13, 17, 97]


class TestVandermonde:

    @pytest.mark.parametrize("p", PRIMES)
    def test_construction(self, p):
        from cagoule.matrix import vandermonde_matrix
        nodes = list(range(1, 5))  # 4 nœuds distincts
        m = vandermonde_matrix(nodes, p)
        assert len(m) == 4
        assert all(len(row) == 4 for row in m)

    @pytest.mark.parametrize("p", PRIMES)
    def test_inversible(self, p):
        from cagoule.matrix import vandermonde_matrix, matrix_inverse_mod, matrix_mul_mod, is_identity
        nodes = [(i + 1) % p for i in range(4)]
        if len(set(nodes)) < 4:
            pytest.skip("Nœuds non distincts pour ce p")
        m = vandermonde_matrix(nodes, p)
        m_inv = matrix_inverse_mod(m, p)
        prod = matrix_mul_mod(m, m_inv, p)
        assert is_identity(prod, p)


class TestDiffusionMatrix:

    @pytest.mark.parametrize("p", PRIMES)
    def test_roundtrip_apply(self, p):
        """apply_inverse(apply(v)) = v."""
        from cagoule.matrix import DiffusionMatrix
        nodes = [(i * 3 + 1) % p for i in range(4)]
        seen = set()
        unique = []
        for n in nodes:
            while n in seen:
                n = (n + 1) % p
            unique.append(n)
            seen.add(n)
        dm = DiffusionMatrix.from_nodes(unique, p)
        v = [i % p for i in range(4)]
        assert dm.apply_inverse(dm.apply(v)) == v

    @pytest.mark.parametrize("p", PRIMES)
    def test_verify_inverse(self, p):
        from cagoule.matrix import DiffusionMatrix
        nodes = [(i * 2 + 1) % p for i in range(4)]
        seen = set()
        unique = []
        for n in nodes:
            while n in seen:
                n = (n + 1) % p
            unique.append(n)
            seen.add(n)
        dm = DiffusionMatrix.from_nodes(unique, p)
        assert dm.verify_inverse()

    def test_fallback_cauchy(self):
        """Nœuds non distincts → fallback Cauchy automatique."""
        from cagoule.matrix import DiffusionMatrix
        p = 97
        nodes = [1, 1, 2, 3]  # collision → Cauchy
        dm = DiffusionMatrix.from_nodes(nodes, p)
        assert dm.kind == "cauchy"
        assert dm.verify_inverse()

    @pytest.mark.parametrize("p", [13, 97, 257])
    def test_repr(self, p):
        from cagoule.matrix import DiffusionMatrix
        nodes = list(range(1, 5))
        dm = DiffusionMatrix.from_nodes(nodes, p)
        assert "DiffusionMatrix" in repr(dm)
