# CAGOULE v1.1

**Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée**

Système de chiffrement symétrique hybride fusionnant des primitives cryptographiques modernes avec des structures mathématiques issues du **Concours Général Sénégalais 2025** (CGS2025).

---

## Architecture

```
Plaintext
  │
  ▼  PKCS7 pad → blocs de 16 octets → Z/pZ
  ▼
┌─────────────────────────────────────────┐
│  CBC-like interne                       │
│  1. v = m + prev_cipher mod p           │  ← mixing
│  2. w = P × v mod p                     │  ← diffusion Vandermonde
│  3. u = S-box(w)                        │  ← confusion x³+cx
│  4. c = u + round_key_Ω mod p          │  ← clé de ronde ζ(2n)
└─────────────────────────────────────────┘
  │
  ▼  ChaCha20-Poly1305 (RFC 8439) — AEAD
  │
Format CGL1 : Magic(4) | Version(1) | Salt(32) | Nonce(12) | CT | Tag(16)
```

### Paramètres dérivés depuis le mot de passe

| Paramètre | Dérivation | Rôle |
|-----------|-----------|------|
| `n` | HKDF ∈ [4, 65536] | paramètre de ζ(2n) pour les round keys |
| `p` | HKDF → nextprime(≈2⁶⁴) | corps de travail Z/pZ |
| `µ` | racine de x⁴+x²+1 dans Z/pZ ou Fp² | nœud de la matrice Vandermonde |
| `c` | HKDF → S-box x³+cx | constante de confusion |
| `K_stream` | HKDF → 256 bits | clé ChaCha20 |
| Round keys | ζ(2n) → coefficients de Fourier → HKDF | 64 clés de ronde |

### Constantes CGS2025

- `ζ(8) = π⁸/9450` (identité vérifiée à 60 décimales)
- `x₀ = 3π` (solution de `cos(π/4 − x/3) = −√2/2`)
- `ρ = (1+√5)/2` (nombre d'or)

---

## Installation

```bash
pip install .
# Avec dépendances de développement :
pip install ".[dev]"
```

### Dépendances

- `cryptography` ≥ 42 — ChaCha20-Poly1305, HKDF, Scrypt
- `mpmath` ≥ 1.3 — précision arbitraire pour ζ(2n)
- `argon2-cffi` ≥ 23 — KDF principal (fallback Scrypt si absent)

---

## Utilisation

### Python API

```python
from cagoule import encrypt, decrypt, CagouleAuthError

# Chiffrement
ct = encrypt(b"Message secret", b"mon_mot_de_passe")

# Déchiffrement
plaintext = decrypt(ct, b"mon_mot_de_passe")

# Mauvais mot de passe → exception typée
try:
    decrypt(ct, b"mauvais")
except CagouleAuthError:
    print("Authentification échouée")
```

### CLI

```bash
# Chiffrer un fichier
cagoule encrypt secret.txt -p "MonMotDePasse"

# Déchiffrer
cagoule decrypt secret.txt.cgl1 -p "MonMotDePasse"

# Inspecter (sans déchiffrer)
cagoule inspect secret.txt.cgl1

# Benchmark
cagoule bench -n 5

# Version
cagoule version
```

---

## Format CGL1

| Offset | Taille | Champ |
|--------|--------|-------|
| 0–3 | 4 | Magic : `CGL1` (0x43474C31) |
| 4 | 1 | Version : `0x01` |
| 5–36 | 32 | Salt Argon2id (inclus dans AAD) |
| 37–48 | 12 | Nonce ChaCha20 (96 bits) |
| 49–N | variable | Ciphertext ChaCha20 |
| N–N+16 | 16 | Tag Poly1305 |

**Overhead fixe : 65 octets.**

---

## Structure du projet

```
cagoule/
├── pyproject.toml
├── README.md
└── cagoule/
    ├── __init__.py          # API publique
    ├── __version__.py       # version
    ├── cipher.py            # chiffrement CBC-like + AEAD
    ├── decipher.py          # déchiffrement inverse
    ├── params.py            # dérivation complète des paramètres
    ├── omega.py             # pilier Ω : ζ(2n) → round keys
    ├── sbox.py              # S-box x³+cx et fallback x^d
    ├── matrix.py            # matrices Vandermonde / Cauchy mod p
    ├── mu.py                # racine de x⁴+x²+1 (Z/pZ ou Fp²)
    ├── fp2.py               # extension quadratique Fp²
    ├── constants.py         # constantes CGS2025
    ├── format.py            # parsing / sérialisation CGL1
    ├── cli.py               # interface ligne de commande
    └── kat_vectors.json     # Known Answer Tests v1.1
```

---

## Tests

```bash
pytest
pytest --cov=cagoule
```

---

## Sécurité

- **KDF** : Argon2id (t=3, m=64 MB, p=1) — fallback Scrypt (n=2¹⁷)
- **AEAD** : ChaCha20-Poly1305 RFC 8439 — authentification + confidentialité
- **Entropie supplémentaire** : n ∈ [4, 65536] secret → les round keys sont mathématiquement irrécupérables sans n
- **Tag invalide** → `CagouleAuthError` sans fuite d'information

> ⚠️ Ce projet est à but académique et expérimental. Ne pas utiliser en production sans audit de sécurité indépendant.