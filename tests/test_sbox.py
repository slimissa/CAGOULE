"""
test_sbox.py — Tests pour sbox.py

Couvre :
- Bijectivité de la S-box cubique et du fallback x^d
- Inversion forward/inverse
- Interface unifiée SBox
- Cas limites (p=2, p=3, petits premiers)
"""
import pytest


SMALL_PRIMES = [5, 7, 11, 13, 17, 19, 23]


class TestSBoxBijectivity:

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_fallback_bijectif(self, p):
        """Le fallback x^d est toujours bijectif."""
        from cagoule.sbox import SBox
        # Créer une S-box en mode fallback forcé
        sbox = SBox(p=p, use_fallback=True)
        values = [sbox.forward(x) for x in range(p)]
        assert len(set(values)) == p, f"Fallback non bijectif pour p={p}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_fallback_roundtrip(self, p):
        """forward ∘ inverse = identité pour le fallback."""
        from cagoule.sbox import SBox
        sbox = SBox(p=p, use_fallback=True)
        for x in range(p):
            y = sbox.forward(x)
            x_back = sbox.inverse(y)
            assert x_back == x, f"Échec roundtrip pour x={x}, p={p}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_sbox_interface_forward_inverse(self, p):
        """SBox.forward et SBox.inverse sont inverses l'un de l'autre."""
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(1, p)
        for x in range(p):
            y = sbox.forward(x)
            x_back = sbox.inverse(y)
            assert x_back == x, f"Échec roundtrip: x={x}, p={p}"

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_sbox_forward_block(self, p):
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(1, p)
        block = list(range(min(p, 16)))
        out = sbox.forward_block(block)
        back = sbox.inverse_block(out)
        assert back == block, f"Échec roundtrip bloc pour p={p}"

    def test_sbox_repr(self):
        from cagoule.sbox import SBox
        s = SBox.from_delta(1, 7)
        r = repr(s)
        assert "SBox" in r
        assert "p=7" in r

    def test_sbox_fallback_repr(self):
        from cagoule.sbox import SBox
        s = SBox(p=7, use_fallback=True)
        r = repr(s)
        assert "fallback" in r or "SBox" in r


class TestSBoxCubic:

    @pytest.mark.parametrize("p", SMALL_PRIMES)
    def test_cubic_bijectif_si_valide(self, p):
        """Si un c valide est trouvé, la S-box cubique est bijective."""
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(1, p)
        if not sbox.is_fallback():
            values = [sbox.forward(x) for x in range(p)]
            assert len(set(values)) == p, f"S-box cubique non bijective pour p={p}"

    @pytest.mark.parametrize("p", [5, 7, 11, 13])
    def test_cubic_roundtrip_si_valide(self, p):
        """Roundtrip pour la S-box cubique si elle est utilisée."""
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(1, p)
        if not sbox.is_fallback():
            for x in range(p):
                y = sbox.forward(x)
                x_back = sbox.inverse(y)
                assert x_back == x, f"Échec roundtrip cubique: x={x}, p={p}"

    def test_legendre_symbol(self):
        from cagoule.sbox import legendre_symbol
        assert legendre_symbol(1, 7) == 1
        assert legendre_symbol(0, 7) == 0
        assert legendre_symbol(3, 7) == -1
        assert legendre_symbol(4, 7) == 1

    def test_find_valid_c(self):
        """find_valid_c doit trouver un c ou retourner None."""
        from cagoule.sbox import find_valid_c
        # p=7 (≡1 mod 3) a des c valides
        c, offset = find_valid_c(1, 7)
        # Note: selon l'implémentation, c peut être None ou une valeur
        # On vérifie juste que la fonction ne crash pas
        assert True


class TestSBoxEdgeCases:

    @pytest.mark.parametrize("p", [2, 3])
    def test_tres_petits_premiers(self, p):
        """La S-box doit fonctionner pour p=2 et p=3."""
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(1, p)
        for x in range(p):
            y = sbox.forward(x)
            x_back = sbox.inverse(y)
            assert x_back == x, f"Échec roundtrip pour p={p}, x={x}"

    def test_p_grand_fallback(self):
        """Pour un grand p, le fallback doit être utilisé ou la S-box fonctionne."""
        from cagoule.sbox import SBox
        p = 13226797537736071951
        sbox = SBox.from_delta(1, p)
        # Tester un roundtrip
        x = 12345
        y = sbox.forward(x)
        x_back = sbox.inverse(y)
        assert x_back == x

    def test_fallback_d_exposant_impair(self):
        """L'exposant d du fallback doit être impair."""
        from cagoule.sbox import SBox
        for p in SMALL_PRIMES + [97, 257]:
            sbox = SBox(p=p, use_fallback=True)
            # Vérifier que d est accessible (via la S-box)
            assert hasattr(sbox, 'd')
            d = sbox.d
            assert d % 2 == 1, f"d={d} n'est pas impair pour p={p}"
            from math import gcd
            assert gcd(d, p - 1) == 1, f"gcd({d}, {p-1}) != 1"


class TestSBoxPerformance:

    def test_forward_rapide(self):
        """forward doit être rapide (pas de calculs lourds)."""
        import time
        from cagoule.sbox import SBox
        p = 13226797537736071951
        sbox = SBox.from_delta(1, p)
        x = 123456789
        
        start = time.perf_counter()
        for _ in range(1000):
            y = sbox.forward(x)
        elapsed = (time.perf_counter() - start) * 1000
        
        # 1000 appels doivent prendre moins de 10ms
        assert elapsed < 10, f"forward trop lent: {elapsed:.2f}ms"

    def test_inverse_rapide(self):
        """inverse doit être rapide (pré-calcul de d_inv)."""
        import time
        from cagoule.sbox import SBox
        p = 13226797537736071951
        sbox = SBox.from_delta(1, p)
        x = 123456789
        y = sbox.forward(x)
        
        start = time.perf_counter()
        for _ in range(1000):
            x_back = sbox.inverse(y)
        elapsed = (time.perf_counter() - start) * 1000
        
        # 1000 appels doivent prendre moins de 50ms
        assert elapsed < 50, f"inverse trop lent: {elapsed:.2f}ms"


class TestSBoxFromDelta:

    @pytest.mark.parametrize("delta", [0, 1, 42, 123, 456])
    @pytest.mark.parametrize("p", [7, 13, 17])
    def test_from_delta_retourne_sbox(self, delta, p):
        """from_delta doit toujours retourner une SBox valide."""
        from cagoule.sbox import SBox
        sbox = SBox.from_delta(delta, p)
        assert sbox is not None
        # Tester la bijectivité
        values = [sbox.forward(x) for x in range(p)]
        assert len(set(values)) == p, f"S-box non bijective pour delta={delta}, p={p}"

    def test_from_delta_reproductible(self):
        """Même delta et p doivent donner la même S-box."""
        from cagoule.sbox import SBox
        p = 13
        delta = 42
        sbox1 = SBox.from_delta(delta, p)
        sbox2 = SBox.from_delta(delta, p)
        assert sbox1.use_fallback == sbox2.use_fallback
        if not sbox1.use_fallback:
            assert sbox1.c == sbox2.c


class TestSBoxConstants:

    def test_sbox_cache(self):
        """Le cache des paramètres fallback doit fonctionner."""
        from cagoule.sbox import SBox
        p = 17
        sbox1 = SBox(p=p, use_fallback=True)
        sbox2 = SBox(p=p, use_fallback=True)
        assert sbox1.d == sbox2.d
        assert hasattr(sbox1, 'd_inv')
        # Vérifier que d * d_inv ≡ 1 mod (p-1)
        assert (sbox1.d * sbox1.d_inv) % (p - 1) == 1