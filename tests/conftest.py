"""
conftest.py — Fixtures partagées pour la suite de tests CAGOULE.
"""
import json
import sys
from pathlib import Path

import pytest

# S'assurer que le package est importable depuis la racine du repo
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def kat():
    """Charge le vecteur KAT de référence depuis kat_vectors.json."""
    path = Path(__file__).parent.parent / "cagoule" / "kat_vectors.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def fast_params():
    """
    Paramètres CAGOULE dérivés avec fast_mode=True (KDF réduit pour les tests).
    Mise en cache au niveau session pour éviter de re-dériver à chaque test.
    """
    from cagoule.params import CagouleParams
    return CagouleParams.derive(b"test_password_cagoule", fast_mode=True)


@pytest.fixture(scope="session")
def small_prime():
    """Petit premier pour les tests exhaustifs (S-box, matrice, µ)."""
    return 257  # premier ≈ 2⁸, assez petit pour les boucles exhaustives


@pytest.fixture(scope="session")
def medium_prime():
    """Premier moyen pour les tests d'inversion."""
    return 65537  # premier de Fermat, classique en crypto
