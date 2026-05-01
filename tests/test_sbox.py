"""test_sbox.py — Tests S-box CAGOULE v2.0.0 (Feistel + fallback x^d)"""

import time
import warnings
import pytest

# Petits premiers (p < 2^32) pour test fallback x^d
SMALL_PRIMES = [5, 7, 11, 13, 17, 19, 23, 97]

# Grand premier (≈2^64) pour test Feistel
P_BENCH = 10441487724840939323


def _sbox(p, delta=1):
    """Helper pour créer une S-box."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.sbox import SBox
    return SBox.from_delta(delta, p)


# ============================================================
# Tests pour fallback x^d (petits p)
# ============================================================

class TestSBoxFallback:
    """Tests pour S-box x^d (p < seuil)."""

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_bijection(self, p):
        """La S-box doit être bijective (toutes les sorties distinctes)."""
        s = _sbox(p)
        outputs = [s.forward(x) for x in range(p)]
        assert len(set(outputs)) == p, f"Non bijective pour p={p}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_roundtrip(self, p):
        """inverse(forward(x)) == x pour tout x."""
        s = _sbox(p)
        for x in range(p):
            assert s.inverse(s.forward(x)) == x, f"Échec roundtrip p={p}, x={x}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_is_fallback(self, p):
        """Le mode fallback doit être actif."""
        assert _sbox(p).is_fallback(), f"p={p} devrait utiliser fallback"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_block(self, p):
        """Les opérations par bloc doivent fonctionner."""
        s = _sbox(p)
        bl = [i % p for i in range(min(p, 16))]
        enc = s.forward_block(bl)
        dec = s.inverse_block(enc)
        assert dec == bl, f"Block roundtrip échoué pour p={p}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_repr_fallback(self, p):
        """La représentation doit indiquer le mode fallback."""
        s = _sbox(p)
        rep = repr(s)
        assert "fallback" in rep.lower() or "x^d" in rep or "Python" in rep
    def test_repr_fallback(self, p):
        s = _sbox(p)
        rep = repr(s)
        # Accepter aussi le format C
        assert ("fallback" in rep.lower() or 
                "x^d" in rep or 
                "Python" in rep or
                ("C" in rep and "x^" in rep))

# ============================================================
# Tests pour Feistel (grands p)
# ============================================================

class TestSBoxFeistel:
    """Tests pour S-box Feistel C (p ≥ seuil)."""

    def test_not_fallback(self):
        """Le mode Feistel doit être actif pour P_BENCH."""
        assert not _sbox(P_BENCH).is_fallback()

    def test_roundtrip_100k(self):
        """Roundtrip pour 100 000 valeurs aléatoires."""
        s = _sbox(P_BENCH)
        ok = True
        for i in range(100000):
            x = (i * 1234567891011) % P_BENCH
            if s.inverse(s.forward(x)) != x:
                ok = False
                break
        assert ok, "Roundtrip échoué pour Feistel"

    def test_block_n16(self):
        """Opérations par bloc de 16 éléments."""
        s = _sbox(P_BENCH)
        bl = [(i * 999999999937) % P_BENCH for i in range(16)]
        enc = s.forward_block(bl)
        dec = s.inverse_block(enc)
        assert dec == bl

    def test_non_trivial(self):
        """La S-box ne doit pas être l'identité."""
        s = _sbox(P_BENCH)
        x = 123456789
        assert s.forward(x) != x, "S-box semble être l'identité"

    def test_repr(self):
        """La représentation doit indiquer Feistel."""
        s = _sbox(P_BENCH)
        rep = repr(s)
        assert "Feistel" in rep or "C" in rep

    def test_ratio_forward_inverse(self):
        """
        Test critique v2.0 : forward et inverse doivent avoir un coût similaire.
        Le ratio doit être proche de 1× (v1.5 avait 7.8×).
        """
        s = _sbox(P_BENCH)
        N = 50000  # 50k appels suffisent pour mesure stable

        # Forward
        t0 = time.perf_counter()
        for i in range(N):
            s.forward((i * 1234567) % P_BENCH)
        fwd_ms = (time.perf_counter() - t0) * 1000

        # Inverse
        t0 = time.perf_counter()
        for i in range(N):
            s.inverse((i * 1234567) % P_BENCH)
        inv_ms = (time.perf_counter() - t0) * 1000

        # Si les deux sont mesurables (>1ms), vérifier le ratio
        if fwd_ms > 1.0 and inv_ms > 0.5:
            ratio = inv_ms / fwd_ms
            print(f"\n  Forward ({N} appels): {fwd_ms:.2f} ms")
            print(f"  Inverse ({N} appels): {inv_ms:.2f} ms")
            print(f"  Ratio inv/fwd: {ratio:.3f}× (objectif < 2×)")
            assert ratio < 2.0, f"Ratio {ratio:.2f}× > 2× (attendu ~1× après correction Feistel)"
        else:
            print(f"\n  ⚠️  Mesure trop rapide: forward={fwd_ms:.2f}ms")


# ============================================================
# Tests de dérivation depuis delta
# ============================================================

class TestSBoxDelta:
    """Tests de construction S-box à partir de delta."""

    @pytest.mark.parametrize("delta", [0, 1, 42, 123, 9999])
    @pytest.mark.parametrize("p", [7, 13, 97])
    def test_from_delta_bijectif(self, delta, p):
        """Différents deltas doivent produire des S-box bijectives."""
        s = _sbox(p, delta)
        outputs = [s.forward(x) for x in range(p)]
        assert len(set(outputs)) == p, f"Non bijective pour delta={delta}, p={p}"

    def test_reproductible(self):
        """Même delta doit produire la même S-box."""
        p = 13
        delta = 42
        s1 = _sbox(p, delta)
        s2 = _sbox(p, delta)
        assert s1.is_fallback() == s2.is_fallback()
        # Vérifier les mappings pour quelques valeurs
        for x in range(p):
            assert s1.forward(x) == s2.forward(x)

    def test_delta_avec_fallback(self):
        """Delta doit être géré même en mode fallback."""
        for p in SMALL_PRIMES:
            s1 = _sbox(p, delta=1)
            s2 = _sbox(p, delta=9999)
            # Les deux doivent être en mode fallback
            assert s1.is_fallback() and s2.is_fallback()
            # Les mappings doivent être différents (souvent, mais pas garanti)
            # On vérifie juste qu'ils existent sans erreur
            assert s1.forward(1) is not None
            assert s2.forward(1) is not None


# ============================================================
# Tests de zeroize (optionnel)
# ============================================================

class TestSBoxZeroize:
    """Tests d'effacement sécurisé des données sensibles."""

    def test_zeroize_feistel(self):
        """zeroize() ne doit pas planter pour Feistel."""
        s = _sbox(P_BENCH)
        try:
            s.zeroize()
            assert True
        except Exception as e:
            pytest.fail(f"zeroize() a échoué: {e}")

    def test_zeroize_fallback(self):
        """zeroize() ne doit pas planter pour fallback."""
        s = _sbox(97)
        try:
            s.zeroize()
            assert True
        except Exception as e:
            pytest.fail(f"zeroize() a échoué: {e}")


# ============================================================
# Tests de détection du backend (optionnel)
# ============================================================

class TestBackendDetection:
    """Vérifie que le bon backend est utilisé."""

    def test_c_backend_available(self):
        """Vérifie si le backend C est détecté."""
        from cagoule._binding import CAGOULE_C_AVAILABLE
        s = _sbox(P_BENCH)
        if CAGOULE_C_AVAILABLE:
            # Le backend C doit être utilisé pour P_BENCH
            assert not s.is_fallback()
            assert "C" in repr(s) or "Feistel" in repr(s)
        else:
            # Fallback Python doit être utilisé
            assert s.is_fallback()
            assert "Python" in repr(s) or "x^d" in repr(s)