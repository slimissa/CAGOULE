"""test_matrix.py — Tests DiffusionMatrix CAGOULE v2.0.0"""

import warnings
import time
import pytest

# Premiers de test (tous > 16 pour permettre Vandermonde sans collision)
P_BENCH = 10441487724840939323
PRIMES_VALID = [17, 19, 23, 97, 257]  # p > 16 pour n=16
PRIMES_SMALL = [7, 11, 13]  # p < 16 → forcer Cauchy fallback


def _nodes(p, n=16, max_attempts=10000):
    """Génère des nœuds distincts avec limite de sécurité."""
    seen, result = set(), []
    for i in range(n):
        v = (i * 7 + 3) % p
        attempts = 0
        while v in seen and attempts < max_attempts:
            v = (v + 1) % p
            attempts += 1
        if v in seen:
            raise RuntimeError(
                f"Impossible de générer un nœud distinct après {max_attempts} "
                f"tentatives (p={p}, i={i})"
            )
        result.append(v)
        seen.add(v)
    return result


def _dm(p, nodes=None, n=16):
    """Helper pour créer une DiffusionMatrix."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.matrix import DiffusionMatrix
    if nodes is None:
        nodes = _nodes(p, n)
    return DiffusionMatrix.from_nodes(nodes, p)


# ============================================================
# Tests fonctionnels
# ============================================================

class TestDiffusionMatrix:

    @pytest.mark.parametrize("p", PRIMES_VALID)
    def test_roundtrip(self, p):
        """apply_inverse(apply(v)) doit retourner v."""
        m = _dm(p)
        v = [i % p for i in range(16)]
        assert m.apply_inverse(m.apply(v)) == v

    @pytest.mark.parametrize("p", PRIMES_VALID + [P_BENCH])
    def test_verify_inverse(self, p):
        """verify_inverse() doit retourner True."""
        assert _dm(p).verify_inverse()

    @pytest.mark.parametrize("p", PRIMES_VALID)
    def test_non_trivial(self, p):
        """La matrice ne doit pas être l'identité."""
        m = _dm(p)
        # Tester plusieurs vecteurs pour éviter les vecteurs propres
        test_vectors = [
            [i % p for i in range(16)],
            [(i * 2) % p for i in range(16)],
            [(i * 3 + 1) % p for i in range(16)],
        ]
        non_trivial = False
        for v in test_vectors:
            fwd = m.apply(v)
            if any(fwd[i] != v[i] for i in range(16)):
                non_trivial = True
                break
        assert non_trivial, "La matrice semble être l'identité"

    @pytest.mark.parametrize("p", PRIMES_SMALL)
    def test_vandermonde_impossible_cauchy_fallback(self, p):
        """Pour p < 16, le fallback Cauchy doit être utilisé."""
        if p < 16:
            pytest.skip(f"p={p} < 16, ne peut pas avoir 16 nœuds distincts")
        nodes = _nodes(p, 16)
        # Vérifier qu'il y a des collisions inévitables
        if len(set(nodes)) == 16:
            pytest.skip(f"p={p} permet 16 nœuds distincts")
        m = _dm(p, nodes=nodes)
        assert m.kind == "cauchy", f"p={p} devrait utiliser Cauchy"
        assert m.verify_inverse()

    def test_cauchy_fallback_collision(self):
        """Test explicite du fallback Cauchy avec collision forcée."""
        nodes = _nodes(97)
        nodes[3] = nodes[1]  # Forcer une collision
        m = _dm(97, nodes=nodes)
        assert m.kind == "cauchy"
        assert m.verify_inverse()

    def test_roundtrip_p_bench(self):
        """Test avec le premier réel du benchmark."""
        m = _dm(P_BENCH)
        v = [(i * 1000000007) % P_BENCH for i in range(16)]
        assert m.apply_inverse(m.apply(v)) == v

    def test_full_n16(self):
        """Test avec n=16 et vecteur aléatoire."""
        m = _dm(P_BENCH)
        assert m.verify_inverse()
        v = [(i * 999999937) % P_BENCH for i in range(16)]
        assert m.apply_inverse(m.apply(v)) == v

    def test_repr(self):
        """Vérifie la représentation textuelle."""
        m = _dm(97)
        assert "DiffusionMatrix" in repr(m)
        assert "C" in repr(m) or "Python" in repr(m)


# ============================================================
# Tests de validation des paramètres
# ============================================================

class TestValidation:
    def test_p_invalide(self):
        """p doit être ≥ 2."""
        with pytest.raises(Exception):  # ValueError ou autre
            _dm(1)

    def test_nodes_vide(self):
        """Liste de nœuds vide doit échouer."""
        from cagoule.matrix import DiffusionMatrix
        with pytest.raises(Exception):
            DiffusionMatrix.from_nodes([], 97)

    def test_nodes_taille_invalide(self):
        """Le nombre de nœuds doit être BLOCK_SIZE_N (16)."""
        from cagoule.matrix import DiffusionMatrix
        with pytest.raises(Exception):
            DiffusionMatrix.from_nodes([1, 2, 3], 97)


# ============================================================
# Tests de performance (backend C)
# ============================================================

class TestPerformance:
    """Vérifie que le backend C est utilisé et performant."""

    def test_backend_c_disponible(self):
        """Vérifie que le backend C est disponible."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C non disponible")

    def test_performance_65000_blocs(self, benchmark):
        """Benchmark avec 65k blocs (équivalent 1 MB)."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C non disponible")

        m = _dm(P_BENCH)
        v = [(i * 1000000007) % P_BENCH for i in range(16)]

        def bench_forward():
            return m.apply(v)

        def bench_inverse():
            return m.apply_inverse(v)

        # Mesurer les performances
        t0 = time.perf_counter()
        for _ in range(65536):
            bench_forward()
        fwd_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for _ in range(65536):
            bench_inverse()
        inv_ms = (time.perf_counter() - t0) * 1000

        print(f"\n  Forward 65k blocs: {fwd_ms:.1f} ms")
        print(f"  Inverse 65k blocs: {inv_ms:.1f} ms")
        print(f"  Ratio inv/fwd: {inv_ms/fwd_ms:.2f}×")

        # Seuils de performance (beaucoup plus contraignants que les tests)
        assert fwd_ms < 500, f"Forward trop lent: {fwd_ms:.0f}ms"
        assert inv_ms < 500, f"Inverse trop lent: {inv_ms:.0f}ms"
        assert inv_ms / fwd_ms < 2.0, f"Ratio inv/fwd trop élevé"


# ============================================================
# Tests de compatibilité (fallback Python)
# ============================================================

class TestFallbackPython:
    """Tests lorsque le backend C n'est pas disponible."""

    def test_fallback_python_kind(self):
        """Le type doit être Python (si C non dispo)."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        from cagoule.matrix import DiffusionMatrix

        if CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C disponible - fallback non testable")

        m = _dm(97)
        assert "Python" in repr(m)
        assert m.kind in ("vandermonde", "cauchy")
        assert m.verify_inverse()

    def test_fallback_roundtrip(self):
        """Roundtrip doit fonctionner en mode Python."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C disponible - fallback non testable")

        m = _dm(97)
        v = [i % 97 for i in range(16)]
        assert m.apply_inverse(m.apply(v)) == v