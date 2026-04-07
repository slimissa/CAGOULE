"""
test_matrix.py — Tests Tier A + Tier B pour les matrices de diffusion

Tier A : inversibilité, Vandermonde, Cauchy, aller-retour sur blocs
Tier B : M × M⁻¹ = I sur N=16 et N=32, nœuds distincts
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from matrix import (
    vandermonde_matrix, cauchy_matrix, build_diffusion_matrix,
    matrix_inverse_mod, matrix_mul_mod, matrix_vec_mul_mod,
    is_identity, DiffusionMatrix,
)

# ------------------------------------------------------------------ #
#  Constantes                                                          #
# ------------------------------------------------------------------ #

P_SMALL = 101
P_MEDIUM = 65537
LARGE_PRIME = 18446744073709551557


# ------------------------------------------------------------------ #
#  Tier A — Tests fonctionnels                                         #
# ------------------------------------------------------------------ #

def test_vandermonde_2x2():
    """Vandermonde 2×2 avec nœuds distincts."""
    p = 7
    nodes = [2, 3]
    m = vandermonde_matrix(nodes, p)
    assert m[0] == [1, 2], f"Ligne 0 incorrecte : {m[0]}"
    assert m[1] == [1, 3], f"Ligne 1 incorrecte : {m[1]}"


def test_vandermonde_invertible():
    """Vandermonde avec nœuds distincts doit être inversible."""
    p = P_SMALL
    nodes = [1, 2, 3, 4]
    m = vandermonde_matrix(nodes, p)
    m_inv = matrix_inverse_mod(m, p)
    product = matrix_mul_mod(m, m_inv, p)
    assert is_identity(product, p), "M × M⁻¹ ≠ I pour Vandermonde 4×4"


def test_cauchy_invertible():
    """Matrice de Cauchy doit être inversible si les conditions sont respectées."""
    p = P_SMALL
    alpha = [1, 2, 3, 4]
    beta  = [10, 20, 30, 40]
    m = cauchy_matrix(alpha, beta, p)
    m_inv = matrix_inverse_mod(m, p)
    product = matrix_mul_mod(m, m_inv, p)
    assert is_identity(product, p), "Cauchy 4×4 : M × M⁻¹ ≠ I"


def test_build_diffusion_vandermonde():
    """build_diffusion_matrix choisit Vandermonde si nœuds distincts."""
    p = P_SMALL
    nodes = [3, 7, 11, 19]
    m, kind = build_diffusion_matrix(nodes, p)
    assert kind == "vandermonde"


def test_build_diffusion_cauchy_fallback():
    """
    build_diffusion_matrix tombe sur Cauchy si nœuds en collision.
    Utilise un p plus grand pour éviter les annulations.
    """
    p = 101  # Plus grand que 7 pour éviter les problèmes d'annulation
    nodes = [2, 2, 3, 5]  # collision : nodes[0] == nodes[1]
    m, kind = build_diffusion_matrix(nodes, p)
    assert kind == "cauchy"
    
    # Vérifier que la matrice est inversible
    m_inv = matrix_inverse_mod(m, p)
    product = matrix_mul_mod(m, m_inv, p)
    assert is_identity(product, p), "Cauchy fallback devrait être inversible"


def test_diffusion_matrix_apply_inverse():
    """DiffusionMatrix.apply puis apply_inverse doit redonner le vecteur d'origine."""
    p = P_SMALL
    nodes = [5, 11, 23, 41]
    dm = DiffusionMatrix.from_nodes(nodes, p)
    v = [10, 20, 30, 40]
    w = dm.apply(v)
    v_rec = dm.apply_inverse(w)
    assert v_rec == v, f"Aller-retour échoué : {v} → {w} → {v_rec}"


def test_diffusion_matrix_verify_inverse():
    """DiffusionMatrix.verify_inverse doit retourner True."""
    p = P_SMALL
    nodes = [2, 5, 13, 29]
    dm = DiffusionMatrix.from_nodes(nodes, p)
    assert dm.verify_inverse(), "verify_inverse() doit retourner True"


def test_matrix_singular_raises():
    """Une matrice singulière doit lever ValueError."""
    p = 7
    m = [[1, 2], [1, 2]]
    try:
        matrix_inverse_mod(m, p)
        assert False, "Doit lever ValueError"
    except ValueError:
        pass


def test_vandermonde_node_zero():
    """Nœud 0 dans Vandermonde — première colonne tout à 1, reste à 0."""
    p = 13
    nodes = [0, 1, 2]
    m = vandermonde_matrix(nodes, p)
    assert m[0] == [1, 0, 0], f"Nœud 0 incorrect : {m[0]}"


def test_matrix_vec_mul():
    """Test de la multiplication matrice-vecteur."""
    p = 7
    m = [[1, 2], [3, 4]]
    v = [1, 1]
    result = matrix_vec_mul_mod(m, v, p)
    assert result == [3, 0], f"Résultat incorrect : {result}"


def test_identity_detection():
    """is_identity doit reconnaître la matrice identité."""
    p = 11
    I = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
    assert is_identity(I, p)
    not_I = [[1, 0, 0], [0, 1, 0], [0, 0, 2]]
    assert not is_identity(not_I, p)


def test_diffusion_matrix_repr():
    """Test de la représentation."""
    p = P_SMALL
    nodes = [7, 11, 19, 31]
    dm = DiffusionMatrix.from_nodes(nodes, p)
    r = repr(dm)
    assert "DiffusionMatrix" in r


def test_cauchy_zero_denominator_raises():
    """Cauchy doit lever ValueError si alpha[i]+beta[j]=0."""
    p = 11
    alpha = [1, 2]
    beta = [10, 9]
    try:
        cauchy_matrix(alpha, beta, p)
        assert False, "Doit lever ValueError"
    except ValueError:
        pass


# ------------------------------------------------------------------ #
#  Tier B — Tests de propriétés                                        #
# ------------------------------------------------------------------ #

def test_matrix_invertible_n16():
    """M × M⁻¹ = I pour N=16."""
    p = P_MEDIUM
    nodes = [(2 * i + 1) % p for i in range(16)]
    assert len(set(nodes)) == 16, "Nœuds non distincts"
    dm = DiffusionMatrix.from_nodes(nodes, p)
    assert dm.kind == "vandermonde"
    assert dm.verify_inverse(), "N=16 : M × M⁻¹ ≠ I"


def test_matrix_invertible_n32():
    """M × M⁻¹ = I pour N=32."""
    p = P_MEDIUM
    nodes = [(3 * i + 7) % p for i in range(32)]
    assert len(set(nodes)) == 32, "Nœuds non distincts"
    dm = DiffusionMatrix.from_nodes(nodes, p)
    assert dm.verify_inverse(), "N=32 : M × M⁻¹ ≠ I"


def test_nodes_distinct():
    """Vérifier que les nœuds générés sont distincts."""
    p = P_MEDIUM
    for n in [4, 8, 16, 32]:
        nodes = [(5 * i + 3) % p for i in range(n)]
        assert len(set(nodes)) == n
        dm = DiffusionMatrix.from_nodes(nodes, p)
        assert dm.kind == "vandermonde"


def test_vandermonde_many_primes():
    """Inversibilité Vandermonde sur plusieurs premiers."""
    test_primes = [97, 101, 257, 1009, 65537]
    for p in test_primes:
        nodes = [i + 1 for i in range(8)]
        nodes = [n % p for n in nodes]
        if len(set(nodes)) < 8:
            continue
        m = vandermonde_matrix(nodes, p)
        m_inv = matrix_inverse_mod(m, p)
        product = matrix_mul_mod(m, m_inv, p)
        assert is_identity(product, p), f"p={p}"


def test_diffusion_full_roundtrip_n16():
    """Aller-retour complet sur un bloc de 16 éléments."""
    p = P_MEDIUM
    nodes = [(7 * i + 3) % p for i in range(16)]
    dm = DiffusionMatrix.from_nodes(nodes, p)
    v = [(i * 12345 + 67890) % p for i in range(16)]
    w = dm.apply(v)
    v_rec = dm.apply_inverse(w)
    assert v_rec == v


def test_cauchy_fallback_with_collision():
    """Test du fallback Cauchy avec nœuds en collision."""
    p = 101  # Premier plus grand pour éviter les annulations
    nodes = [5, 5, 10, 15, 20]  # collision volontaire
    
    m, kind = build_diffusion_matrix(nodes, p)
    assert kind == "cauchy"
    
    # Vérifier l'inversibilité
    m_inv = matrix_inverse_mod(m, p)
    product = matrix_mul_mod(m, m_inv, p)
    assert is_identity(product, p), "Cauchy fallback devrait être inversible"


def test_cauchy_fallback_small_p():
    """Test spécifique pour petits p avec gestion d'annulation."""
    p = 7
    nodes = [2, 2, 3]
    
    # Pour p=7, on utilise des beta spécifiques qui évitent les annulations
    # 2+?=7 → ?=5 à éviter; 3+?=7 → ?=4 à éviter
    beta = [1, 2, 6]  # 1,2,6 mod 7
    m, kind = build_diffusion_matrix(nodes, p, beta=beta)
    assert kind == "cauchy"
    
    m_inv = matrix_inverse_mod(m, p)
    product = matrix_mul_mod(m, m_inv, p)
    assert is_identity(product, p), f"Cauchy fallback pour p={p} devrait être inversible"


# ------------------------------------------------------------------ #
#  Runner                                                              #
# ------------------------------------------------------------------ #

def run_all():
    tests = [
        test_vandermonde_2x2,
        test_vandermonde_invertible,
        test_cauchy_invertible,
        test_build_diffusion_vandermonde,
        test_build_diffusion_cauchy_fallback,
        test_diffusion_matrix_apply_inverse,
        test_diffusion_matrix_verify_inverse,
        test_matrix_singular_raises,
        test_vandermonde_node_zero,
        test_matrix_vec_mul,
        test_identity_detection,
        test_diffusion_matrix_repr,
        test_cauchy_zero_denominator_raises,
        test_matrix_invertible_n16,
        test_matrix_invertible_n32,
        test_nodes_distinct,
        test_vandermonde_many_primes,
        test_diffusion_full_roundtrip_n16,
        test_cauchy_fallback_with_collision,
        test_cauchy_fallback_small_p,
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
    print(f"matrix.py : {passed}/{passed+failed} tests passés")
    if failed:
        print(f"ÉCHECS : {failed}")
        sys.exit(1)
    else:
        print("TOUS LES TESTS PASSÉS ✓")


if __name__ == "__main__":
    run_all()