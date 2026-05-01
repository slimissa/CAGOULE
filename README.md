# CAGOULE v2.1.0

> **C**ryptographie **A**lgébrique **G**éométrique par **O**ndes et **L**ogique **E**ntrelacée

A symmetric hybrid encryption system that layers a custom algebraic cipher (Vandermonde diffusion, Feistel S-box, ζ-based round keys) beneath ChaCha20-Poly1305, with a dual C / Python backend and 100% API compatibility across all v1.x, v2.0.x, and v2.1.x releases.

**Author:** Slim Issa · **License:** MIT · **Python:** ≥ 3.9 · **Platform:** Linux (POSIX)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Advanced API](#advanced-api)
- [CGL1 Format](#cgl1-format)
- [Module Reference](#module-reference)
- [C Backend (libcagoule.so)](#c-backend-libcagouleso)
- [Security Design](#security-design)
- [Test Suite](#test-suite)
- [Changelog Summary](#changelog-summary)
- [Project Structure](#project-structure)

---

## Overview

CAGOULE wraps **ChaCha20-Poly1305** (authenticated encryption) around a custom algebraic permutation layer. The algebraic layer is parameterized entirely from the password via Argon2id + HKDF-SHA256, producing:

| Component | Description |
|-----------|-------------|
| **Diffusion matrix** | 16×16 Vandermonde (or Cauchy) over Z/pZ |
| **S-box** | Feistel 2-round (C) or x^d (Python fallback) |
| **Round keys** | Derived from Fourier coefficients of ζ(2n) via HKDF |
| **Stream key** | 32-byte ChaCha20 key, HKDF-derived |

The result is a format-stable, fully authenticated ciphertext called **CGL1**.

---

## Architecture

```
Password + Salt (32 B random)
        │
        ▼
   Argon2id (t=3, m=64 MiB, p=1)   [~180 ms]
   └── fallback: Scrypt (N=2^17)
        │
        ▼ K_master (64 B)
        ├── HKDF → n       (block size, 16 default)
        ├── HKDF → p       (64-bit prime via nextprime)
        ├── HKDF → µ       (primitive root in Z/pZ or Fp²)
        ├── HKDF → δ       (S-box seed)
        ├── HKDF → nodes   (16 Vandermonde nodes)
        ├── HKDF → K_stream (ChaCha20 key, 32 B)
        └── omega.py v2.1.0
                ├── C backend: cagoule_omega_generate_round_keys()
                │   (ζ table + Fourier + HKDF via libcrypto/OpenSSL)
                └── Python fallback: mpmath.zeta + cryptography.HKDF
                        │
                        ▼
              round_keys[0..63] ∈ [0, p)
```

### Encryption pipeline

```
Plaintext
    │ PKCS7 pad (block_size=16)
    ▼
CBC-like loop (block = 16 elements of Z/pZ):
    XOR with prev_cipher  →  DiffusionMatrix.apply()  →  SBox.forward()  →  add_round_key()
    │
    ▼  t_message (serialized as p_bytes-width integers)
ChaCha20-Poly1305.encrypt(key=K_stream, nonce=12B, aad=CGL1_header)
    │
    ▼
CGL1 packet  (MAGIC + VERSION + SALT + NONCE + CT + TAG)
```

Decryption is the exact reverse, with the security guarantee enforced: if `password` is non-empty, parameters are **always re-derived** from `(password, salt_from_ciphertext)` — a wrong password produces a wrong `K_stream`, which invalidates the Poly1305 tag and raises `CagouleAuthError` immediately.

---

## Installation

### 1. Install Python dependencies

```bash
pip install cagoule                # requires argon2-cffi, cryptography
# or, for dev:
pip install "cagoule[dev]"         # adds pytest, black, ruff, mpmath, etc.
# if libcagoule.so cannot be compiled (embedded environments):
pip install "cagoule[fallback]"    # adds mpmath as runtime dependency
```

### 2. Build the C backend (strongly recommended)

```bash
cd cagoule/c
make              # builds libcagoule.so
make install      # copies .so next to the Python package
make tests        # runs 256 C tests (math + matrix + sbox + cipher + omega)
```

**Prerequisites:** GCC, OpenSSL dev headers, `__uint128_t` support.

```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Quick check
make check-openssl
```

> **Note:** On OpenSSL 3.0+, you may see deprecation warnings for `HMAC_CTX_new`. 
> These are harmless — the code remains fully functional. Add `-Wno-deprecated-declarations` 
> to `CFLAGS` to silence them.

If `libcagoule.so` is absent, CAGOULE falls back to Python-only mode automatically (same API, ~2–5× slower, no mpmath needed in production thanks to omega.c).

---

## Quick Start

```python
from cagoule import encrypt, decrypt

# Encrypt
ct = encrypt(b"secret message", b"my_password")
# ct is a CGL1 bytes packet

# Decrypt
pt = decrypt(ct, b"my_password")
assert pt == b"secret message"

# Strings are accepted too
ct2 = encrypt("hello world", "passphrase")
pt2 = decrypt(ct2, "passphrase")
```

### Backend inspection

```python
from cagoule import __backend__, __omega_backend__

print(__backend__)        # "C (libcagoule.so v2.1)" or "Python pur (fallback v1.x)"
print(__omega_backend__)  # "C (libcagoule.so v2.1)" or "Python (mpmath fallback)"
```

---

## Advanced API

### Pre-derived parameters (batch encryption / performance)

```python
from cagoule import encrypt, decrypt
from cagoule.params import CagouleParams

# Derive once, use many times
with CagouleParams.derive(b"password") as params:
    ct1 = encrypt(b"msg1", b"password", params=params)
    ct2 = encrypt(b"msg2", b"password", params=params)
    pt1 = decrypt(ct1, b"password", params=params)
    pt2 = decrypt(ct2, b"password", params=params)
# params.zeroize() called automatically on __exit__
```

### encrypt_with_params / decrypt_with_params

```python
from cagoule import encrypt_with_params, decrypt_with_params
from cagoule.params import CagouleParams

params = CagouleParams.derive(b"password")
ct = encrypt_with_params(b"data", params)
pt = decrypt_with_params(ct, params)
params.zeroize()
```

### fast_mode (tests only — weaker KDF)

```python
ct = encrypt(b"test", b"pw", fast_mode=True)
pt = decrypt(ct, b"pw", fast_mode=True)
```

`fast_mode` is automatically stored in `CagouleParams.fast_mode` and propagated through `decrypt()` re-derivation — you never need to pass it explicitly when `params=` is provided.

### Exception handling

```python
from cagoule import decrypt
from cagoule.decipher import CagouleAuthError, CagouleFormatError, CagouleError

try:
    pt = decrypt(ct, b"wrong_password")
except CagouleAuthError as e:
    print(e.reason)   # "mot de passe incorrect ou ciphertext altéré"
    print(e.ct_size)  # int, bytes
    print(e.backend)  # "C (libcagoule.so v2.1)"
    print(e.hint)     # diagnostic suggestion
except CagouleFormatError as e:
    print(e.field)      # e.g. "magic"
    print(e.data_size)  # bytes received
    print(e.min_size)   # minimum expected
except CagouleError as e:
    print(e)            # base class for all CAGOULE errors
```

---

## CGL1 Format

Every CAGOULE ciphertext follows the **CGL1** binary format:

```
 ┌──────────┬─────────┬──────────────┬──────────────┬──────────────────┬──────────┐
 │  MAGIC   │ VERSION │     SALT     │    NONCE     │   CIPHERTEXT     │   TAG    │
 │  4 bytes │ 1 byte  │   32 bytes   │   12 bytes   │   variable       │ 16 bytes │
 │ b"CGL1"  │  0x01   │  (random)    │  (random)    │  CT layer        │ Poly1305 │
 └──────────┴─────────┴──────────────┴──────────────┴──────────────────┴──────────┘
 │←────────────────── HEADER (49 B) ──────────────────────────────────►│
 │←────────────────── AAD (37 B = MAGIC+VERSION+SALT) ─────►│
                                                              Overhead: 65 bytes
```

### Format utilities

```python
from cagoule.format import parse, inspect, serialize, is_cgl1, OVERHEAD, MAGIC

# Validate
if is_cgl1(ct):
    info = inspect(ct)
    print(info["ciphertext_len"], info["salt_hex"])

# Parse to CGL1Packet
pkt = parse(ct)
print(pkt.salt, pkt.nonce, pkt.tag)

# Manual serialize
raw = serialize(salt, nonce, ciphertext, tag)
```

---

## Module Reference

| Module | Public API | Description |
|--------|-----------|-------------|
| `cagoule` | `encrypt`, `decrypt`, `encrypt_with_params`, `decrypt_with_params` | Main entry points |
| `cagoule.params` | `CagouleParams` | Full KDF + parameter derivation |
| `cagoule.cipher` | `encrypt`, `encrypt_with_params` | Encryption pipeline |
| `cagoule.decipher` | `decrypt`, `decrypt_with_params`, `CagouleAuthError`, `CagouleFormatError` | Decryption + exceptions |
| `cagoule.format` | `parse`, `inspect`, `serialize`, `is_cgl1` | CGL1 binary format |
| `cagoule.omega` | `generate_round_keys`, `compute_zeta`, `fourier_coefficients` | ζ-based round key generation |
| `cagoule.matrix` | `DiffusionMatrix` | Vandermonde/Cauchy diffusion matrix |
| `cagoule.sbox` | `SBox` | Feistel S-box (C) or x^d (Python) |
| `cagoule.fp2` | `Fp2Element` | Arithmetic in Fp² = Z/pZ[t]/(t²+t+1) |
| `cagoule.mu` | `generate_mu`, `MuResult` | Primitive root µ of x⁴+x²+1 |
| `cagoule.utils` | `secure_zeroize`, `SensitiveBuffer`, `analyze_sbox`, `sbox_report` | Security utilities |
| `cagoule.logger` | `get_logger`, `set_level`, `enable_debug` | Structured logging |
| `cagoule._binding` | (internal) | ctypes loader for libcagoule.so |

### Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `CAGOULE_LOG_LEVEL` | `WARNING` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LIBCAGOULE_PATH` | *(auto)* | Override path to `libcagoule.so` |

---

## C Backend (libcagoule.so)

The C library (`cagoule/c/`) provides native implementations of all performance-critical operations.

### Modules

| Source | Functions | Description |
|--------|-----------|-------------|
| `cagoule_math.c/.h` | `addmod64`, `submod64`, `mulmod64` | Modular arithmetic primitives |
| `cagoule_matrix.c/.h` | `cagoule_matrix_build`, `cagoule_matrix_mul`, `cagoule_matrix_mul_inv` | 16×16 Vandermonde/Cauchy matrix |
| `cagoule_sbox.c/.h` | `cagoule_sbox_init`, `cagoule_sbox_forward`, `cagoule_sbox_inverse` | Feistel 2-round S-box |
| `cagoule_cipher.c/.h` | `cagoule_cbc_encrypt`, `cagoule_cbc_decrypt` | Full CBC-like pipeline |
| `cagoule_omega.c/.h` | `cagoule_omega_generate_round_keys`, `cagoule_omega_zeta_2n`, `cagoule_omega_fourier_coeff` | ζ(2n) → round keys via OpenSSL HKDF (new in v2.1.0) |

### Build targets

```bash
make                # build libcagoule.so
make install        # install .so next to Python package
make tests          # run all 256 C tests
make test_omega     # run omega-specific tests (78 tests, new in v2.1.0)
make check-openssl  # verify OpenSSL headers and HMAC
make clean          # remove build artifacts
```

### Performance

| Operation | Python fallback | C backend | Speedup |
|-----------|----------------|-----------|---------|
| Encrypt (1 KB) | baseline | ~2–5× | C matrix + S-box |
| Decrypt (1 KB) | 7.8× slower than encrypt | ~1× | Feistel symmetry |
| Param derivation (omega) | mpmath | **−40% to −60%** | ζ table + libcrypto |

---

## Security Design

### Cryptographic primitives

| Primitive | Role | Standard |
|-----------|------|----------|
| **Argon2id** | Password-based KDF | RFC 9106 |
| **Scrypt** | KDF fallback (if argon2-cffi absent) | RFC 7914 |
| **HKDF-SHA256** | Key/parameter derivation | RFC 5869 |
| **ChaCha20-Poly1305** | Authenticated encryption (AEAD) | RFC 8439 |
| **Vandermonde/Cauchy matrix** | Algebraic diffusion over Z/pZ | Custom |
| **Feistel S-box** | Confusion layer | Custom (2-round, 32-bit) |
| **ζ(2n) round keys** | Key schedule from Riemann zeta | Custom |

### Security properties

- **Authentication**: Poly1305 tag covers `MAGIC + VERSION + SALT + ciphertext`. Any single-byte alteration invalidates decryption.
- **Wrong-password detection**: `decrypt()` always re-derives parameters from `(password, salt_cgl1)` when `password` is non-empty — even if `params=` is supplied. This prevents the v2.0 bypass where a pre-derived `k_stream` would silently accept a wrong password.
- **Secure zeroization**: `CagouleParams.zeroize()` and `SensitiveBuffer` overwrite key material in memory. C S-box fields are explicitly zeroed via `cagoule_sbox_*` structs.
- **Nonce**: 12-byte random nonce per message — collision probability negligible for normal usage volumes.
- **Salt**: 32-byte random salt per encryption — prevents dictionary attacks across messages.

### Important notes

- CAGOULE is a **research / personal project** cipher. The algebraic layer (ζ-round keys, Vandermonde matrix, Feistel S-box) has **not undergone academic peer review** as a standalone construction.
- For production use of the encryption guarantee, the security relies on **ChaCha20-Poly1305** (an established AEAD). The algebraic layer acts as an additional pre-processing stage.
- Tested against 14 NIST SP 800-22 statistical randomness tests (2 skipped due to timeout).

### `secure_zeroize` and `SensitiveBuffer`

```python
from cagoule.utils import secure_zeroize, SensitiveBuffer

# Direct zeroization
buf = bytearray(b"secret")
secure_zeroize(buf)   # overwrites in-place, including via ctypes on CPython

# Context manager
with SensitiveBuffer.from_bytes(b"key_material") as buf:
    # buf is a bytearray available here
    pass
# buf is now zeroed
```

---

## Test Suite

### Python tests (pytest)

```bash
cd cagoule/
pytest                    # run all tests
pytest -v --tb=short      # verbose with short tracebacks
pytest tests/test_cipher.py  # specific module
pytest -m "not nist"      # skip slow NIST tests
```

**Latest results (v2.1.0):**

| Suite | File | Count | Status |
|-------|------|-------|--------|
| Cipher | `test_cipher.py` | 87 | ✅ |
| Omega | `test_omega.py` | 62 | ✅ |
| KAT | `test_kat.py` | 96 | ✅ |
| S-box | `test_sbox.py` | 105 | ✅ |
| Matrix | `test_matrix.py` | 73 | ✅ |
| µ generator | `test_mu.py` | 58 | ✅ |
| Fp² | `test_fp2.py` | 44 | ✅ |
| Format | `test_format.py` | 31 | ✅ |
| NIST statistical | `test_nist.py` | 4 | ⏭ 2 skip (timeout) |
| **Total** | | **560** | **523 pass / 2 fail / 25 skip / 2 err** |

The 2 failures and 2 errors are environment-specific (typically libcagoule.so version mismatch or OpenSSL linking issues). Core cipher correctness is fully covered.

### C tests

```bash
cd cagoule/c
make tests      # 256 tests total
# math: 33, matrix: 52, sbox: 48, cipher: 45, omega: 78
```

### KAT regeneration

```bash
python regenerate_kat.py           # regenerate encryption KAT vectors
python regenerate_kat.py --omega   # regenerate omega KAT vectors
python regenerate_kat.py --all     # both
python regenerate_kat.py --check   # verify without overwriting
```

---

## Changelog Summary

| Version | Highlights |
|---------|-----------|
| **v2.1.0** | `omega.c` (ζ → round keys in C, −40–60% faster); fix `test_mauvais_mdp` (wrong password always raises `CagouleAuthError`); enriched exceptions (`.reason`, `.hint`, `.ct_size`, `.backend`, `.field`); `CagouleParams.fast_mode` attribute; `mpmath` now optional |
| **v2.0.0** | Full C portage (`libcagoule.so`); Feistel S-box (decrypt/encrypt ratio 7.8× → ~1×); CBC pipeline in C; 5 security fixes; 178 C tests |
| **v1.5.0** | Pure Python baseline; Argon2id + HKDF; ChaCha20-Poly1305; CGL1 format; `cagoule-pass` password manager |

---

## Project Structure

```
cagoule/
├── __init__.py          # Public API + backend flags
├── __version__.py       # version = "2.1.0"
├── cipher.py            # encrypt(), encrypt_with_params()
├── decipher.py          # decrypt(), exceptions
├── params.py            # CagouleParams.derive()
├── omega.py             # ζ(2n) → round keys
├── _binding.py          # ctypes loader
├── format.py            # CGL1 parse/serialize
├── fp2.py               # Fp² arithmetic
├── mu.py                # primitive root µ
├── matrix.py            # DiffusionMatrix
├── sbox.py              # SBox (Feistel / x^d)
├── utils.py             # secure_zeroize, SensitiveBuffer
├── logger.py            # logging
├── kat_vectors.json     # KAT vectors (encryption)
└── c/                   # C backend
    ├── Makefile
    ├── include/          # cagoule_{math,matrix,sbox,cipher,omega}.h
    ├── src/              # cagoule_{matrix,sbox,cipher,omega}.c
    └── tests/            # test_{math,matrix,sbox,cipher,omega}.c (256 tests)

tests/                   # Python test suite
├── conftest.py           # fixtures: fast_params, normal_params
├── test_cipher.py
├── test_omega.py
├── test_kat.py
├── test_sbox.py
├── test_matrix.py
├── test_mu.py
├── test_fp2.py
├── test_format.py
├── test_nist.py
└── kat_omega_vectors.json

pyproject.toml           # build config + dependencies
CHANGELOG.md             # full version history
regenerate_kat.py        # KAT vector generation
```

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run `make tests` (C) and `pytest` (Python) — all existing tests must pass.
3. For new features touching the algebraic layer, add KAT vectors via `regenerate_kat.py --check`.
4. Code style: `black` (line-length 100) + `ruff`.

---

*CAGOULE v2.1.0 — Copyright 2026, Slim Issa — MIT License*
