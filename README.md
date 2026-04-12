# CAGOULE v1.5.0

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-247%2F247-brightgreen)](https://github.com/slimissa/CAGOULE/tree/master/tests)
[![NIST](https://img.shields.io/badge/NIST_SP_800--22-14%2F14-brightgreen)](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final)
[![PyPI](https://img.shields.io/badge/PyPI-1.5.0-blue)](https://pypi.org/project/cagoule/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Actions](https://github.com/slimissa/CAGOULE/actions/workflows/tests.yml/badge.svg)](https://github.com/slimissa/CAGOULE/actions/workflows/tests.yml)

**Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée**

Système de chiffrement symétrique hybride fusionnant des primitives cryptographiques modernes avec des structures mathématiques issues du **Concours Général Sénégalais 2025** (CGS2025).

> ⚠️ **Usage académique.** CAGOULE est un projet de recherche et d'expérimentation cryptographique. Ne pas utiliser en production sans audit de sécurité indépendant.

---

## Qu'est-ce que CAGOULE ?

CAGOULE chiffre en **deux couches successives** :

```
Plaintext
  │
  ▼  PKCS7 pad → blocs de 16 octets → Z/pZ  (p ≈ 2⁶⁴, premier dérivé du mot de passe)
  │
  ┌─────────────────────────────── COUCHE 1 : CBC-like interne ───────────────────────────────┐
  │  1. v = m_i + prev_cipher   mod p   ← CBC mixing                                         │
  │  2. w = P × v               mod p   ← diffusion Vandermonde 16×16                        │
  │  3. u = S-box(w) = w³ + cw  mod p   ← confusion algébrique                               │
  │  4. c = u + round_key_Ω     mod p   ← clé de ronde dérivée de ζ(2n)                     │
  └────────────────────────────────────────────────────────────────────────────────────────────┘
  │
  ┌─────────────────────────────── COUCHE 2 : AEAD (RFC 8439) ────────────────────────────────┐
  │  ChaCha20-Poly1305  — nonce 96 bits aléatoire — tag Poly1305 128 bits                    │
  └────────────────────────────────────────────────────────────────────────────────────────────┘
  │
  ▼  Format CGL1 : Magic(4) | Version(1) | Salt(32) | Nonce(12) | CT | Tag(16)
```

La **couche interne** exploite la théorie des groupes, les matrices de Vandermonde, les extensions quadratiques Fp², et la fonction zêta de Riemann comme source de clés de ronde. La **couche externe** (ChaCha20-Poly1305) garantit la confidentialité et l'authenticité selon les standards IETF.

---

## Nouveautés v1.5.0

La v1.5.0 est la version finale et stabilisée de la Phase 1 Python. Elle corrige les problèmes structurels des versions antérieures et apporte des optimisations majeures.

### Performance

| Métrique | v1.1 | v1.5.0 | Gain |
|----------|------|--------|------|
| Déchiffrement 1 Ko (avec KDF) | ~285 ms | ~11 ms | **−96%** |
| Déchiffrement 1 Ko (sans KDF) | ~18.5 ms | ~11 ms | −40% |
| S-box inverse (10 000 appels) | ~79 ms | ~2 ms | **−97%** |
| Tests passés | ~70% | 247/247 | 100% |

### Corrections structurelles

- **Imports absolus → relatifs** — La v1.1 levait `ImportError` à l'installation via pip. Tous les `from cipher import` sont devenus `from .cipher import` dans les 6 fichiers concernés.
- **Paramètre `params` dans `decrypt()`** — Permet de réutiliser des paramètres KDF pré-calculés et d'éviter une re-dérivation Argon2id (~285 ms) à chaque appel.
- **Cache `_FALLBACK_CACHE` dans `sbox.py`** — `pow(d, -1, p-1)` est maintenant calculé une seule fois à l'initialisation, au lieu d'être recalculé à chaque `inverse()`.
- **Déroulage de boucle dans `matrix.py`** — Chemin optimisé pour n=16 (taille fixe de CAGOULE) sans boucle Python intermédiaire.
- **Tests corrigés** — Mots de passe cohérents entre `encrypt()` et `decrypt()` avec `fast_mode=True`, filtre des diviseurs de zéro dans les tests Fp² (éléments à norme nulle pour p ≡ 1 mod 3).

### Nouvelles fonctionnalités

- **`cagoule/utils.py`** — `secure_zeroize()`, `SensitiveBuffer` (context manager), `analyze_sbox()` avec uniformité différentielle et non-linéarité.
- **`cagoule/logger.py`** — Logging structuré DEBUG/INFO/WARNING/ERROR via `CAGOULE_LOG_LEVEL` ou `--verbose`/`--debug` dans la CLI. Les fallbacks S-box et la stratégie µ sont maintenant loggés.
- **`CagouleParams.zeroize()`** — Efface K_master, K_stream et les round keys après usage. Support du context manager `with CagouleParams.derive(...) as p:`.
- **14 tests NIST SP 800-22** — Validation statistique complète (Frequency, Runs, DFT, Entropy, Linear Complexity...). Tous les tests passent avec p-value > 0.01 sur 128 Ko de données chiffrées.
- **`scripts/benchmark.py`** — KDF, chiffrement par taille, effet avalanche (~50%), analyse S-box, usage mémoire.
- **KAT v1.5** — Vecteur de test mis à jour pour la v1.5.0 (n_zeta=22190, p=16984848376641921697).

---

## Installation

```bash
pip install cagoule
```

### Dépendances

| Paquet | Version | Rôle |
|--------|---------|------|
| `cryptography` | ≥ 42.0 | ChaCha20-Poly1305, HKDF-SHA256, Scrypt |
| `mpmath` | ≥ 1.3 | Précision arbitraire pour ζ(2n) et constantes CGS2025 |
| `argon2-cffi` | ≥ 23.0 | KDF Argon2id — fallback Scrypt si absent |

---

## Utilisation rapide

### API Python

```python
from cagoule import encrypt, decrypt, CagouleAuthError

# Chiffrement
ciphertext = encrypt(b"Message secret", b"mon_mot_de_passe")

# Déchiffrement
plaintext = decrypt(ciphertext, b"mon_mot_de_passe")
assert plaintext == b"Message secret"

# Mauvais mot de passe → exception typée
try:
    decrypt(ciphertext, b"mauvais")
except CagouleAuthError:
    print("Authentification échouée")
```

### API avancée — réutilisation des paramètres

```python
from cagoule.params import CagouleParams
from cagoule import encrypt, decrypt

# Dériver les paramètres une seule fois (Argon2id ~300 ms)
with CagouleParams.derive(b"password", fast_mode=False) as params:
    # Chiffrer et déchiffrer sans re-dériver
    ct1 = encrypt(b"Message 1", b"password", params=params)
    ct2 = encrypt(b"Message 2", b"password", params=params)
    pt1 = decrypt(ct1, b"password", params=params)
    pt2 = decrypt(ct2, b"password", params=params)
# params.zeroize() est appelé automatiquement ici
```

### Nettoyage mémoire sécurisé

```python
from cagoule.utils import secure_zeroize, SensitiveBuffer

# Zéroïser un bytearray
key = bytearray(b"clé_secrète")
secure_zeroize(key)  # key est maintenant rempli de \x00

# Context manager automatique
with SensitiveBuffer(32) as buf:
    buf[:] = os.urandom(32)
    # utiliser buf...
# buf est zéroïsé ici automatiquement
```

### Logging

```bash
# Via variable d'environnement
CAGOULE_LOG_LEVEL=DEBUG python3 mon_script.py

# Via CLI
cagoule encrypt fichier.txt -p "mdp" --verbose
cagoule encrypt fichier.txt -p "mdp" --debug
```

### CLI

```bash
# Chiffrer un fichier
cagoule encrypt secret.txt -p "MonMotDePasse"

# Déchiffrer
cagoule decrypt secret.txt.cgl1 -p "MonMotDePasse"

# Inspecter (sans déchiffrer)
cagoule inspect secret.txt.cgl1

# Benchmark complet
cagoule bench -n 3

# Analyse S-box et performances
python3 scripts/benchmark.py --quick

# Version et informations
cagoule version
```

---

## Architecture interne

### Paramètres dérivés depuis le mot de passe

Tous les paramètres cryptographiques sont dérivés déterministement depuis `(password, salt)` :

| Paramètre | Dérivation | Rôle |
|-----------|-----------|------|
| `n` | HKDF → [4, 65536] | Paramètre secret de ζ(2n) |
| `p` | HKDF → nextprime(≈2⁶⁴) | Corps de travail Z/pZ |
| `µ` | Racine de x⁴+x²+1 | Nœud de la matrice Vandermonde |
| `c` | HKDF → S-box x³+cx | Constante de confusion |
| `K_stream` | HKDF → 256 bits | Clé ChaCha20 |
| Round keys | ζ(2n) → Fourier → HKDF | 64 clés de ronde mod p |

**Entropie supplémentaire :** n est secret (16 bits d'entropie). Sans n, les round keys sont mathématiquement irrécupérables, même en connaissant K_master.

### Génération de µ (racine de x⁴+x²+1)

Le système utilise deux stratégies en cascade, garantissant que µ est toujours disponible :

| Stratégie | Condition | Méthode |
|-----------|-----------|---------|
| **A** | p ≡ 1 mod 3 | Tonelli-Shanks dans Z/pZ sur x²±x+1=0 |
| **C** | p ≡ 2 mod 3 | µ = t dans Fp² = Z/pZ[t]/(t²+t+1), avec t³=1 ✓ |

### Constantes mathématiques CGS2025

| Constante | Formule | Valeur |
|-----------|---------|--------|
| ρ (nombre d'or) | (1+√5)/2 | 1.61803398874989... |
| β (volume S) | (8π/81)(55ρ+34) | 34.21... |
| **Ω = ζ(8)** | **π⁸/9450** | **1.00407735619794...** |
| x₀ | 3π | 9.42477796076937... |
| δ = |(Z/13Z)*| | 12 | Ordre du groupe multiplicatif |

L'identité ζ(8) = π⁸/9450 est vérifiée à 60 décimales et exploitée pour générer les 64 clés de ronde via les coefficients de Fourier aₖ = (2/π) × (−1)^(k+1) / k^(2n).

---

## Format binaire CGL1

| Offset | Taille | Champ | Description |
|--------|--------|-------|-------------|
| 0–3 | 4 oct. | Magic | `CGL1` (0x43474C31) |
| 4 | 1 oct. | Version | `0x01` |
| 5–36 | 32 oct. | Salt | Sel Argon2id (inclus dans AAD) |
| 37–48 | 12 oct. | Nonce | Nonce ChaCha20 (96 bits, aléatoire) |
| 49–N | variable | CT | Ciphertext ChaCha20 |
| N–N+16 | 16 oct. | Tag | Tag Poly1305 (128 bits) |

**Overhead fixe : 65 octets.**

---

## Structure du projet

```
cagoule/
├── pyproject.toml
├── README.md
├── scripts/
│   └── benchmark.py           ← Benchmark complet (NOUVEAU v1.5)
├── tests/
│   ├── conftest.py
│   ├── test_cipher.py
│   ├── test_format.py
│   ├── test_fp2.py
│   ├── test_kat.py
│   ├── test_matrix.py
│   ├── test_mu.py
│   ├── test_nist.py           ← 14 tests NIST SP 800-22 (NOUVEAU v1.5)
│   └── test_sbox.py
├── run_tests.py               ← Runner sans pytest (247 tests)
└── cagoule/
    ├── __init__.py
    ├── __version__.py
    ├── cipher.py              ← Chiffrement CBC-like + AEAD
    ├── cli.py                 ← CLI (--verbose / --debug en v1.5)
    ├── constants.py           ← Constantes CGS2025 (ζ, ρ, β, x₀)
    ├── decipher.py            ← Déchiffrement + paramètre params (v1.5)
    ├── format.py              ← Parsing / sérialisation CGL1
    ├── fp2.py                 ← Extension quadratique Fp²
    ├── kat_vectors.json       ← Vecteurs KAT v1.5
    ├── logger.py              ← Logging structuré (NOUVEAU v1.5)
    ├── matrix.py              ← Vandermonde / Cauchy + déroulage n=16 (v1.5)
    ├── mu.py                  ← Racine x⁴+x²+1 (Stratégies A et C)
    ├── omega.py               ← Pilier Ω : ζ(2n) → round keys
    ├── params.py              ← KDF + dérivation + zeroize() (v1.5)
    ├── sbox.py                ← S-box x³+cx + cache _FALLBACK_CACHE (v1.5)
    └── utils.py               ← secure_zeroize, SensitiveBuffer (NOUVEAU v1.5)
```

---

## Tests

```bash
# Runner sans dépendance externe (recommandé)
python3 run_tests.py

# Avec pytest
pytest --cov=cagoule

# Tests NIST uniquement (lents — génère 128 Ko de données)
pytest tests/test_nist.py -v

# Benchmark
python3 scripts/benchmark.py --quick --no-kdf
python3 scripts/benchmark.py --sbox    # analyse S-box exhaustive
```

### Résultats v1.5.0

```
════════════════════════════════════════════════════════════
  CAGOULE v1.5.0 — Résultats des tests
════════════════════════════════════════════════════════════
  ✅ 247 passés   ❌ 0 échoués   Total : 247   ⏱ 1.1s
════════════════════════════════════════════════════════════
```

| Fichier | Tests | Couverture |
|---------|-------|-----------|
| `test_format.py` | 14 | Parsing CGL1, sérialisation, inspect, erreurs |
| `test_sbox.py` | 22 | Bijectivité, roundtrip, cache d_inv |
| `test_matrix.py` | 17 | Inversion, roundtrip, fallback Cauchy |
| `test_fp2.py` | 43 | Arithmétique complète, relation t²+t+1=0, inversion |
| `test_mu.py` | 52 | Stratégies A et C, vérification algébrique |
| `test_cipher.py` | 35 | Round-trips 1–512 octets, auth error, UTF-8 |
| `test_nist.py` | 15 | 14 tests NIST SP 800-22 |
| `test_kat.py` | 12 | Vecteurs KAT v1.5 déterministes |

---

## Sécurité

### Garanties
- **KDF mémoire-dur** : Argon2id (t=3, m=64 MB, p=1) — résistant aux attaques GPU/ASIC. Fallback Scrypt (n=2¹⁷) si argon2-cffi est absent.
- **AEAD** : ChaCha20-Poly1305 RFC 8439 — confidentialité + authenticité. Toute altération du ciphertext lève `CagouleAuthError`.
- **Nettoyage mémoire** : `secure_zeroize()` + `ctypes.memset` écrasent K_master, K_stream et les round keys. Best-effort en Python (le GC peut avoir copié les valeurs).
- **Validation statistique** : 14 tests NIST SP 800-22 passés — la sortie est indistinguable d'un aléatoire uniforme.
- **Écriture atomique** (cagoule-pass) : fichier temporaire + rename OS — pas de corruption partielle.

### Limites connues
- La S-box x³+cx sur Z/pZ n'a pas les propriétés de résistance différentielle et linéaire d'une S-box AES. Usage académique exclusivement.
- En Python, les objets `str` et `bytes` sont immuables — le GC peut conserver des copies des mots de passe. Préférer `bytearray` et `SensitiveBuffer`.

---

## Changelog

### v1.5.0 (Avril 2026) — Version finale Phase 1

**Corrections critiques**
- Imports absolus → relatifs dans 6 modules (`ImportError` corrigé)
- Cache `_FALLBACK_CACHE` dans `sbox.py` — `pow(d, -1, p-1)` calculé une seule fois (×40 plus rapide)
- Déroulage de boucle `matrix_vec_mul_mod_optimized` pour n=16 (−40% déchiffrement)
- Paramètre `params` optionnel dans `decrypt()` — évite la re-dérivation KDF (−96%)
- Tests : mots de passe cohérents, filtre diviseurs de zéro dans `test_fp2.py`

**Nouvelles fonctionnalités**
- `utils.py` — `secure_zeroize()`, `SensitiveBuffer`, `analyze_sbox()`
- `logger.py` — Logging structuré DEBUG/INFO/WARNING/ERROR
- `CagouleParams.zeroize()` et support context manager
- 14 tests NIST SP 800-22 dans `tests/test_nist.py`
- `scripts/benchmark.py` — KDF, débit, avalanche, analyse S-box
- KAT v1.5 mis à jour

### v1.2.1 / v1.2.0 (Avril 2026)
- Publication sur PyPI
- CI GitHub Actions
- Structure package corrigée (layout `cagoule/cagoule/`)

### v1.1.0 (Avril 2026)
- Version initiale
- Pipeline CBC-like + ChaCha20-Poly1305
- CLI encrypt / decrypt / inspect / bench
- 162 tests de base

---

## Applications

CAGOULE est la base cryptographique de l'écosystème CAGOULE :

- **[cagoule-pass](https://github.com/slimissa/cagoule-pass)** — Gestionnaire de mots de passe CLI chiffré avec CAGOULE (43 tests, coffre CGL1)

---

## Auteur

**Slim Issa** — [github.com/slimissa](https://github.com/slimissa)

Projet académique inspiré des mathématiques du Concours Général Sénégalais 2025.

---

## Licence

MIT — voir [LICENSE](LICENSE)