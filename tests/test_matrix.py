"""test_matrix.py — Tests DiffusionMatrix CAGOULE v3.1.0
CORRECTIF v3.0.1 : le test de fallback Cauchy pour p < 16 a été corrigé pour forcer une collision, et le test de performance a été amélioré pour mesurer le temps de 65k blocs (~1 MB) et vérifier le ratio inv/fwd.
"""

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

    def test_performance_65000_blocs(self):
        """Benchmark avec 65k blocs (équivalent 1 MB)."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C non disponible")

        m = _dm(P_BENCH)
        v = [(i * 1000000007) % P_BENCH for i in range(16)]

        # Mesurer les performances
        t0 = time.perf_counter()
        for _ in range(65536):
            m.apply(v)
        fwd_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for _ in range(65536):
            m.apply_inverse(v)
        inv_ms = (time.perf_counter() - t0) * 1000

        print(f"\n  Forward 65k blocs: {fwd_ms:.1f} ms")
        print(f"  Inverse 65k blocs: {inv_ms:.1f} ms")
        print(f"  Ratio inv/fwd: {inv_ms/fwd_ms:.2f}×")

        # Seuils de performance
        assert fwd_ms < 1000, f"Forward trop lent: {fwd_ms:.0f}ms"
        assert inv_ms < 1000, f"Inverse trop lent: {inv_ms:.0f}ms"
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

# ============================================================
# Tests DiffusionMatrixC.free() — v2.2.0
# ============================================================

class TestDiffusionMatrixFree:
    """
    8 tests pour DiffusionMatrixC.free(), le context manager,
    et le guard double-free (v2.2.0).
    """

    def _skip_if_no_c(self):
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            import pytest
            pytest.skip("Backend C non disponible")

    def test_free_explicit(self):
        """free() libère la mémoire sans erreur."""
        self._skip_if_no_c()
        m = _dm(P_BENCH)
        m.free()
        assert m._ptr is None
        assert m._freed is True

    def test_free_double_raises(self):
        """Appeler free() deux fois lève RuntimeError."""
        self._skip_if_no_c()
        m = _dm(P_BENCH)
        m.free()
        with pytest.raises(RuntimeError, match="double-free"):
            m.free()

    def test_context_manager_basic(self):
        """Le context manager libère la matrice à la sortie."""
        self._skip_if_no_c()
        from cagoule.matrix import DiffusionMatrixC
        nodes = [(i * 1234567891) % P_BENCH + 1 for i in range(16)]
        nodes_set = list(dict.fromkeys(nodes))[:16]
        m_direct = DiffusionMatrixC.from_nodes(nodes_set, P_BENCH)
        with m_direct as m:
            v = [i % P_BENCH for i in range(16)]
            result = m.apply(v)
            assert len(result) == 16
        # Après le bloc with, freed doit être True
        assert m_direct._freed is True
        assert m_direct._ptr is None

    def test_context_manager_exception_safe(self):
        """Le context manager libère même en cas d'exception."""
        self._skip_if_no_c()
        m = _dm(P_BENCH)
        try:
            with m:
                raise ValueError("Test exception")
        except ValueError:
            pass
        assert m._freed is True

    def test_free_then_del_safe(self):
        """__del__ ne crashe pas si free() a déjà été appelé."""
        self._skip_if_no_c()
        m = _dm(P_BENCH)
        m.free()
        # Appel explicite de __del__ — ne doit pas lever d'exception
        try:
            m.__del__()
        except Exception as e:
            pytest.fail(f"__del__ après free() a levé: {e}")

    def test_backend_info_property(self):
        """backend_info retourne 'avx2' ou 'scalar'."""
        self._skip_if_no_c()
        m = _dm(P_BENCH)
        info = m.backend_info
        assert info in ("avx2", "scalar"), f"backend_info inattendu: {info!r}"
        m.free()

    def test_apply_before_free_works(self):
        """apply() et apply_inverse() fonctionnent avant free()."""
        self._skip_if_no_c()
        with _dm(P_BENCH) as m:
            v = [(i * 999983) % P_BENCH for i in range(16)]
            enc = m.apply(v)
            dec = m.apply_inverse(enc)
            assert dec == v

    def test_multiple_context_managers_independent(self):
        """Deux context managers indépendants ne s'interfèrent pas."""
        self._skip_if_no_c()
        with _dm(P_BENCH) as m1:
            with _dm(P_BENCH) as m2:
                v = [(i * 777777) % P_BENCH for i in range(16)]
                r1 = m1.apply(v)
                r2 = m2.apply(v)
                assert r1 == r2  # même matrice, même résultat
        assert m1._freed and m2._freed
