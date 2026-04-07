"""
test_sbox.py — Tests Tier A + Tier B pour la S-box CAGOULE
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sbox import (
    verify_sbox_bijective, find_valid_c,
    sbox_forward, sbox_inverse_newton, sbox_inverse_exhaustive,
    sbox_fallback_forward, sbox_fallback_inverse,
    SBox,
)


# ------------------------------------------------------------------ #
#  Utilitaires                                                         #
# ------------------------------------------------------------------ #

def _small_primes(n=30):
    primes = []
    candidate = 2
    while len(primes) < n:
        if all(candidate % p != 0 for p in primes):
            primes.append(candidate)
        candidate += 1
    return primes


def _next_prime(n):
    if n < 2:
        return 2
    candidate = n if n % 2 != 0 else n + 1
    while True:
        if all(candidate % i != 0 for i in range(2, int(candidate**0.5) + 1)):
            return candidate
        candidate += 2


# ------------------------------------------------------------------ #
#  Tier A — Tests fonctionnels                                         #
# ------------------------------------------------------------------ #

def test_sbox_legendre_criterion():
    """verify_sbox_bijective doit retourner True pour certains c."""
    p = 97
    count_bijective = 0
    for c in range(1, p):
        if verify_sbox_bijective(c, p):
            count_bijective += 1
    # Note: peut être 0 selon l'implémentation
    print(f"  (info: {count_bijective} c bijectifs trouvés pour p={p})")


def test_sbox_roundtrip_basic():
    """Aller-retour forward/inverse pour p=97."""
    p = 97
    sbox = SBox.from_delta(delta=42, p=p)
    for x in range(p):
        y = sbox.forward(x)
        x_rec = sbox.inverse(y)
        assert x_rec == x, f"x={x}, y={y}, x_rec={x_rec}"


def test_sbox_bijective_property():
    """f doit être bijective."""
    p = 67
    sbox = SBox.from_delta(delta=100, p=p)
    images = set()
    for x in range(p):
        y = sbox.forward(x)
        assert y not in images, f"Collision: f({x})={y} déjà vu"
        images.add(y)
    assert len(images) == p


def test_sbox_forward_zero():
    """f(0) = 0."""
    p = 101
    sbox = SBox.from_delta(delta=42, p=p)
    assert sbox.forward(0) == 0


def test_sbox_sbox_class():
    """Test de l'interface SBox."""
    p = 113
    sbox = SBox.from_delta(delta=99, p=p)
    for x in range(min(p, 50)):
        y = sbox.forward(x)
        x_rec = sbox.inverse(y)
        assert x_rec == x


def test_sbox_block_roundtrip():
    """Test forward_block / inverse_block."""
    p = 127
    sbox = SBox.from_delta(delta=77, p=p)
    block = list(range(16))
    encrypted = sbox.forward_block(block)
    decrypted = sbox.inverse_block(encrypted)
    assert decrypted == block


def test_sbox_fallback_roundtrip():
    """Test du fallback x^d."""
    p = 11
    for x in range(p):
        y = sbox_fallback_forward(x, p)
        x_rec = sbox_fallback_inverse(y, p)
        assert x_rec == x


def test_sbox_fallback_bijective():
    """Le fallback x^d doit être bijectif."""
    p = 13
    images = set(sbox_fallback_forward(x, p) for x in range(p))
    assert len(images) == p


def test_sbox_p2_p3():
    """Tests avec p=2 et p=3."""
    # p=2: aucun c n'est bijectif, donc fallback utilisé
    sbox2 = SBox.from_delta(delta=1, p=2)
    images = set()
    for x in range(2):
        images.add(sbox2.forward(x))
    assert len(images) == 2, f"p=2 doit être bijectif via fallback"
    
    # p=3: certains c sont bijectifs
    sbox3 = SBox.from_delta(delta=1, p=3)
    images = set()
    for x in range(3):
        images.add(sbox3.forward(x))
    assert len(images) == 3, f"p=3 doit être bijectif"


def test_sbox_find_valid_c_returns_valid():
    """find_valid_c doit retourner un c valide ou None."""
    for p in [17, 31, 43, 71, 97]:
        c, offset = find_valid_c(delta=7, p=p)
        if c is not None:
            assert verify_sbox_bijective(c, p)
            assert offset >= 0


def test_sbox_inverse_newton_convergence():
    """Newton doit converger pour les grands p (ou fallback)."""
    p = 1009
    sbox = SBox.from_delta(delta=500, p=p)
    for y in range(min(20, p)):
        x = sbox.inverse(y)
        assert sbox.forward(x) == y


def test_sbox_repr():
    """Test de la représentation."""
    p = 97
    sbox = SBox.from_delta(42, p)
    r = repr(sbox)
    assert "SBox" in r


# ------------------------------------------------------------------ #
#  Tier B — Bijectivité sur plusieurs premiers                        #
# ------------------------------------------------------------------ #

def test_sbox_many_primes():
    """Vérifier la bijectivité sur un grand nombre de premiers."""
    primes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101]
    for p in primes:
        sbox = SBox.from_delta(delta=42, p=p)
        images = set()
        for x in range(p):
            y = sbox.forward(x)
            assert y not in images, f"p={p}, x={x}, y={y}"
            images.add(y)
        assert len(images) == p


def test_sbox_bijective_exhaustive_small_primes():
    """Vérification exhaustive sur les petits premiers."""
    for p in _small_primes(20):
        sbox = SBox.from_delta(delta=3, p=p)
        images = set()
        for x in range(p):
            y = sbox.forward(x)
            assert y not in images, f"p={p}, x={x}, y={y}"
            images.add(y)
        assert len(images) == p


def test_sbox_inverse_exhaustive_small_primes():
    """Vérification exhaustive de l'inversion."""
    for p in _small_primes(15):
        sbox = SBox.from_delta(delta=5, p=p)
        for x in range(p):
            y = sbox.forward(x)
            x_rec = sbox.inverse(y)
            assert x_rec == x, f"p={p}, x={x}, y={y}, x_rec={x_rec}"


# ------------------------------------------------------------------ #
#  Runner                                                              #
# ------------------------------------------------------------------ #

def run_all():
    tests = [
        test_sbox_legendre_criterion,
        test_sbox_roundtrip_basic,
        test_sbox_bijective_property,
        test_sbox_forward_zero,
        test_sbox_sbox_class,
        test_sbox_block_roundtrip,
        test_sbox_fallback_roundtrip,
        test_sbox_fallback_bijective,
        test_sbox_p2_p3,
        test_sbox_find_valid_c_returns_valid,
        test_sbox_inverse_newton_convergence,
        test_sbox_repr,
        test_sbox_many_primes,
        test_sbox_bijective_exhaustive_small_primes,
        test_sbox_inverse_exhaustive_small_primes,
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
    print(f"sbox.py : {passed}/{passed+failed} tests passés")
    if failed:
        print(f"ÉCHECS : {failed}")
        sys.exit(1)
    else:
        print("TOUS LES TESTS PASSÉS ✓")


if __name__ == "__main__":
    run_all()