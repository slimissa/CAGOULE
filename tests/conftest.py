"""conftest.py — Fixtures partagées CAGOULE v2.0.0"""

import json
import os
import sys
import warnings
from pathlib import Path

import pytest

# ============================================================
# Configuration du path et des variables d'environnement
# ============================================================

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Localiser libcagoule.so
SO_PATH = ROOT / "cagoule" / "libcagoule.so"
if SO_PATH.exists():
    os.environ.setdefault("LIBCAGOULE_PATH", str(SO_PATH))

# ============================================================
# Fixtures de session
# ============================================================

@pytest.fixture(scope="session")
def kat():
    """Charge les vecteurs KAT depuis kat_vectors.json."""
    path = ROOT / "cagoule" / "kat_vectors.json"
    if not path.exists():
        pytest.skip(f"Fichier KAT introuvable: {path}")
    with open(path) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def fast_params():
    """Paramètres rapides (Scrypt) pour les tests unitaires."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.params import CagouleParams
    
    p = CagouleParams.derive(b"test_password_cagoule", fast_mode=True)
    yield p
    p.zeroize()


@pytest.fixture(scope="session")
def small_prime():
    """Petit premier (257) pour tests bijectifs."""
    return 257


@pytest.fixture(scope="session")
def medium_prime():
    """Premier moyen (65537) pour tests de matrice."""
    return 65537


@pytest.fixture(scope="session")
def large_prime():
    """Grand premier (≈2^64) pour tests réels."""
    return 10441487724840939323


# ============================================================
# Fixtures optionnelles
# ============================================================

@pytest.fixture(scope="session")
def benchmark_data():
    """Données aléatoires (1 MB) pour les benchmarks."""
    return os.urandom(1024 * 1024)


@pytest.fixture(autouse=True)
def clean_caches():
    """Nettoie les caches avant chaque test."""
    try:
        from cagoule.omega import clear_caches
        clear_caches()
    except ImportError:
        pass
    yield


@pytest.fixture(scope="session", autouse=True)
def set_test_logging():
    """Désactive les logs verbeux pendant les tests."""
    try:
        from cagoule.logger import set_level
        set_level("ERROR")
    except ImportError:
        pass


@pytest.fixture(scope="session")
def c_backend_available():
    """Vérifie que le backend C est disponible (skip si absent)."""
    try:
        from cagoule._binding import CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C non disponible (libcagoule.so manquant)")
        return True
    except ImportError:
        pytest.skip("Backend C non disponible")
        return False