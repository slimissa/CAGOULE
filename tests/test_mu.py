"""
test_mu.py — Tests Tier A + Tier B pour la génération de µ

Tier A : résolution dans Z/pZ, fallback Fp², vérification des racines
Tier B : génération sur plusieurs premiers, validation des nœuds Vandermonde
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fp2 import Fp2Element
from mu import generate_mu, MuResult, generate_vandermonde_nodes


# ------------------------------------------------------------------ #
#  Constantes et utilitaires                                          #
# ------------------------------------------------------------------ #

PRIMES_MOD1 = [7, 13, 19, 31, 37, 43, 61, 67, 73, 79]      # p ≡ 1 mod 3 → stratégie A
PRIMES_MOD2 = [5, 11, 17, 23, 29, 41, 47, 53, 59, 71]      # p ≡ 2 mod 3 → stratégie C
PRIMES_SMALL = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79]

# Pour les tests de nœuds distincts, on utilise des p suffisamment grands
# pour éviter les collisions (p > 1000)
PRIMES_LARGE_FOR_NODES = [1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061]
LARGE_PRIME = 18446744073709551557


def _hkdf_mock(key: bytes, info: bytes, length: int, index: int = 0) -> int:
    """
    Mock de HKDF pour les tests.
    Inclut l'index pour garantir des valeurs distinctes.
    """
    import hashlib
    data = key + info + str(index).encode() + b"CAGOULE_TEST_SEED"
    for _ in range(5):
        data = hashlib.sha256(data).digest()
    return int.from_bytes(data[:length], 'big')


def _hkdf_mock_legacy(key: bytes, info: bytes, length: int) -> int:
    """
    Mock de HKDF legacy pour compatibilité avec les tests existants.
    """
    import hashlib
    data = key + info + b"CAGOULE_TEST_SEED"
    for _ in range(5):
        data = hashlib.sha256(data).digest()
    return int.from_bytes(data[:length], 'big')


# ------------------------------------------------------------------ #
#  Tier A — Tests fonctionnels                                         #
# ------------------------------------------------------------------ #

def test_mu_strategy_a():
    """Stratégie A : µ doit être trouvé dans Z/pZ pour p ≡ 1 mod 3."""
    for p in PRIMES_MOD1:
        result = generate_mu(p, timeout_s=1)
        assert not result.is_fp2(), f"p={p} devrait être en stratégie A (Z/pZ)"
        assert result.strategy == "A", f"p={p} stratégie={result.strategy}"
        mu = result.as_int()
        assert (pow(mu, 4, p) + pow(mu, 2, p) + 1) % p == 0, f"p={p}, mu={mu}"


def test_mu_strategy_c():
    """Stratégie C : µ = t dans Fp² pour p ≡ 2 mod 3."""
    for p in PRIMES_MOD2:
        result = generate_mu(p, timeout_s=1)
        assert result.is_fp2(), f"p={p} devrait être en stratégie C (Fp²)"
        assert result.strategy == "C", f"p={p} stratégie={result.strategy}"
        mu = result.as_fp2()
        t = Fp2Element.t_generator(p)
        assert mu == t, f"p={p}: µ devrait être t"


def test_mu_never_crashes():
    """Le système ne crashe jamais — µ est toujours trouvé."""
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        try:
            result = generate_mu(p, timeout_s=1)
            assert result is not None
        except Exception as e:
            assert False, f"p={p} a levé une exception: {e}"


def test_mu_verify_root_in_fp2():
    """Vérifier que µ = t satisfait x⁴ + x² + 1 = 0 dans Fp²."""
    for p in PRIMES_MOD2:
        t = Fp2Element.t_generator(p)
        t4 = t ** 4
        t2 = t ** 2
        one = Fp2Element(1, 0, p)
        zero = Fp2Element(0, 0, p)
        result = t4 + t2 + one
        assert result == zero, f"p={p}: t⁴+t²+1 = {result} ≠ 0"


def test_mu_verify_root_in_zp():
    """Vérifier que µ trouvé dans Z/pZ satisfait x⁴ + x² + 1 = 0."""
    for p in PRIMES_MOD1[:5]:
        result = generate_mu(p, timeout_s=1)
        mu = result.as_int()
        value = (pow(mu, 4, p) + pow(mu, 2, p) + 1) % p
        assert value == 0, f"p={p}: mu={mu} donne {value} ≠ 0"


def test_mu_timeout_doesnt_crash():
    """Timeout ne doit pas faire crasher, même sur de grands p."""
    p = LARGE_PRIME
    try:
        result = generate_mu(p, timeout_s=0.1)
        assert result is not None
    except Exception as e:
        assert False, f"Timeout a causé une exception: {e}"


def test_mu_repr():
    """Test de la représentation MuResult."""
    p = 13
    result = generate_mu(p)
    r = repr(result)
    assert "MuResult" in r
    assert "strategy" in r
    assert "p=13" in r


def test_mu_as_int_raises_for_fp2():
    """as_int() doit lever TypeError si µ est dans Fp²."""
    p = 11
    result = generate_mu(p)
    assert result.is_fp2()
    try:
        result.as_int()
        assert False, "as_int() devrait lever TypeError pour µ dans Fp²"
    except TypeError:
        pass


def test_mu_as_fp2_works_for_fp2():
    """as_fp2() doit fonctionner pour µ dans Fp²."""
    p = 11
    result = generate_mu(p)
    mu_fp2 = result.as_fp2()
    assert isinstance(mu_fp2, Fp2Element)
    assert mu_fp2.p == p


def test_mu_as_fp2_plugs_int():
    """as_fp2() doit plonger un entier dans Fp² si nécessaire."""
    p = 13
    result = generate_mu(p)
    assert not result.is_fp2()
    mu_fp2 = result.as_fp2()
    assert isinstance(mu_fp2, Fp2Element)
    assert mu_fp2.b == 0
    assert mu_fp2.a == result.as_int()


# ------------------------------------------------------------------ #
#  Tier B — Tests de propriétés                                        #
# ------------------------------------------------------------------ #

def test_mu_many_primes():
    """Génération de µ sur de nombreux premiers."""
    for p in PRIMES_SMALL:
        result = generate_mu(p, timeout_s=1)
        if p % 3 == 1:
            assert not result.is_fp2(), f"p={p}: devrait être Z/pZ"
        else:
            assert result.is_fp2(), f"p={p}: devrait être Fp²"
        
        if result.is_fp2():
            mu = result.as_fp2()
            one = Fp2Element(1, 0, p)
            zero = Fp2Element(0, 0, p)
            assert (mu**4 + mu**2 + one) == zero, f"p={p}"
        else:
            mu = result.as_int()
            assert (pow(mu, 4, p) + pow(mu, 2, p) + 1) % p == 0, f"p={p}"


def test_mu_vandermonde_nodes_generation():
    """
    Génération des nœuds Vandermonde à partir de µ.
    Utilise un grand p pour éviter les collisions.
    """
    p = LARGE_PRIME
    result = generate_mu(p, timeout_s=1)
    k_master = b"test_k_master_32_bytes_for_vandermonde_nodes"
    n = 8
    
    # Utiliser la version avec index pour garantir des valeurs distinctes
    def hkdf_with_index(key, info, length):
        # Extraire l'index de info
        info_str = info.decode()
        if "NODE_" in info_str:
            idx = int(info_str.split("_")[1])
            return _hkdf_mock(key, info, length, idx)
        return _hkdf_mock_legacy(key, info, length)
    
    nodes = generate_vandermonde_nodes(result, n, k_master, hkdf_with_index)
    
    assert len(nodes) == n
    if result.is_fp2():
        assert nodes[0] == result.mu.a % p
    else:
        assert nodes[0] == result.as_int() % p
    assert len(set(nodes)) == n, f"Nœuds non distincts: {nodes}"


def test_mu_vandermonde_nodes_distinct():
    """
    Les nœuds générés doivent être distincts.
    Utilise de grands premiers pour éviter les collisions.
    """
    k_master = b"test_k_master_for_distinctness"
    
    def hkdf_with_index(key, info, length):
        info_str = info.decode()
        if "NODE_" in info_str:
            idx = int(info_str.split("_")[1])
            return _hkdf_mock(key, info, length, idx)
        return _hkdf_mock_legacy(key, info, length)
    
    # Utiliser de très grands premiers
    for p in [1009, 1013, 1019]:
        result = generate_mu(p, timeout_s=1)
        for n in [4, 8, 16]:
            nodes = generate_vandermonde_nodes(result, n, k_master, hkdf_with_index)
            assert len(set(nodes)) == n, f"p={p}, n={n}: nœuds non distincts"


def test_mu_vandermonde_nodes_fp2():
    """
    Génération des nœuds quand µ est dans Fp².
    Utilise un grand p.
    """
    p = 1009  # Premier > 1000, ≡ 1 mod 3? Vérifions: 1009 % 3 = 1
    # Pour être sûr d'avoir Fp², prenons p ≡ 2 mod 3
    p = 1013  # 1013 % 3 = 2 → stratégie C
    result = generate_mu(p, timeout_s=1)
    assert result.is_fp2()
    
    k_master = b"test_k_master_for_fp2"
    n = 8
    
    def hkdf_with_index(key, info, length):
        info_str = info.decode()
        if "NODE_" in info_str:
            idx = int(info_str.split("_")[1])
            return _hkdf_mock(key, info, length, idx)
        return _hkdf_mock_legacy(key, info, length)
    
    nodes = generate_vandermonde_nodes(result, n, k_master, hkdf_with_index)
    
    assert len(nodes) == n
    assert nodes[0] == result.mu.a % p
    assert len(set(nodes)) == n, f"Nœuds non distincts: {nodes}"


def test_mu_vandermonde_nodes_distinct_large_n():
    """Test avec n plus grand sur p suffisamment grand."""
    p = 65537  # Grand premier
    result = generate_mu(p, timeout_s=1)
    k_master = b"test_k_master_large_n"
    n = 32
    
    def hkdf_with_index(key, info, length):
        info_str = info.decode()
        if "NODE_" in info_str:
            idx = int(info_str.split("_")[1])
            return _hkdf_mock(key, info, length, idx)
        return _hkdf_mock_legacy(key, info, length)
    
    nodes = generate_vandermonde_nodes(result, n, k_master, hkdf_with_index)
    assert len(set(nodes)) == n, f"n=32: nœuds non distincts sur p={p}"


def test_mu_consistency_same_p():
    """Pour un même p, µ doit être cohérent (même stratégie)."""
    p = 13
    mu1 = generate_mu(p)
    mu2 = generate_mu(p)
    
    assert mu1.strategy == mu2.strategy
    if mu1.is_fp2():
        assert mu1.as_fp2() == mu2.as_fp2()
    else:
        assert mu1.as_int() == mu2.as_int()


def test_mu_property_t_is_cube_root_of_unity():
    """Dans Fp², t doit être une racine cubique de l'unité (t³ = 1)."""
    for p in PRIMES_MOD2:
        result = generate_mu(p)
        if result.is_fp2():
            t = result.as_fp2()
            one = Fp2Element(1, 0, p)
            assert (t ** 3) == one, f"p={p}: t³ = {t**3} ≠ 1"


def test_mu_no_solution_in_zp_leads_to_fp2():
    """Quand aucune solution dans Z/pZ, bascule automatiquement vers Fp²."""
    for p in PRIMES_MOD2:
        result = generate_mu(p)
        assert result.is_fp2(), f"p={p} devrait basculer vers Fp²"


# ------------------------------------------------------------------ #
#  Runner                                                              #
# ------------------------------------------------------------------ #

def run_all():
    tests = [
        test_mu_strategy_a,
        test_mu_strategy_c,
        test_mu_never_crashes,
        test_mu_verify_root_in_fp2,
        test_mu_verify_root_in_zp,
        test_mu_timeout_doesnt_crash,
        test_mu_repr,
        test_mu_as_int_raises_for_fp2,
        test_mu_as_fp2_works_for_fp2,
        test_mu_as_fp2_plugs_int,
        test_mu_many_primes,
        test_mu_vandermonde_nodes_generation,
        test_mu_vandermonde_nodes_distinct,
        test_mu_vandermonde_nodes_fp2,
        test_mu_vandermonde_nodes_distinct_large_n,
        test_mu_consistency_same_p,
        test_mu_property_t_is_cube_root_of_unity,
        test_mu_no_solution_in_zp_leads_to_fp2,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"mu.py : {passed}/{passed+failed} tests passés")
    if failed:
        print(f"ÉCHECS : {failed}")
        sys.exit(1)
    else:
        print("TOUS LES TESTS PASSÉS ✓")


if __name__ == "__main__":
    run_all()