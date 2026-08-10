# CAGOULE v3.1.0

**Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée**

![Version](https://img.shields.io/badge/version-3.1.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Python](https://img.shields.io/badge/python-3.12%2B-blue) ![Platform](https://img.shields.io/badge/platform-x86--64%20%7C%20ARM64-lightgrey) ![C Tests](https://img.shields.io/badge/C%20tests-16%2F16%20passing-brightgreen) ![Python Tests](https://img.shields.io/badge/python%20tests-722%20passing-brightgreen) ![Security](https://img.shields.io/badge/security-research--grade-yellow)

> ⚠️ **Research-grade software.** CAGOULE is not a production replacement for AES-GCM or ChaCha20-Poly1305. The algebraic layer has no published IND-CPA proof — this is documented and tracked, not hidden. The outer ChaCha20-Poly1305 AEAD (the default mode) provides standard IND-CCA2 security regardless of the algebraic layer's status. See [SECURITY.md](SECURITY.md).

---

## What is CAGOULE?

CAGOULE is a hybrid symmetric encryption research project combining battle-tested standard primitives with a novel algebraic construction, built for study, experimentation, and eventual formal analysis.

**Standard layer** (always active, proven):

- **Argon2id** — memory-hard password-based key derivation
- **HKDF-SHA256** — key expansion and domain separation
- **ChaCha20-Poly1305** — authenticated encryption (default mode)

**Algebraic layer** (the research contribution):

- Dynamic Mersenne-64 prime pool — 8 primes, password-derived selection
- Vandermonde / Cauchy MDS diffusion matrix — 16×16 over Z/pZ
- 2-round Feistel S-box — round keys derived from ζ(2n) Fourier coefficients
- CTR mode — full AVX2 4x pipeline, ARM NEON backend (v3.1.0)

The algebraic layer applies a password-specific permutation to each plaintext block before ChaCha20-Poly1305 encrypts the result. **Even if the algebraic layer were broken, ChaCha20-Poly1305 still provides standard confidentiality and integrity** — it is not a decorative outer wrapper, it is the actual security guarantee in the default mode.

### Why build this?

AES and ChaCha20 are the right choice for production encryption. CAGOULE exists for a different reason: its algebraic structure (`x^d mod p`, Vandermonde matrices, prime-field arithmetic) lives in the same mathematical setting as ZK-SNARKs and algebraic cryptanalysis tools. This makes it useful as:

- A research platform for studying algebraic cipher design
- A testbed for cryptanalysis experiments against a known, documented construction
- A prototype for ZK-circuit-friendly authenticated encryption

---

## Architecture

```
Password ──► Argon2id (memory-hard) ──► k_master (32B)
                                              │
                              ┌───────────────┴────────────────────┐
                              │                                    │
                         HKDF-SHA256                          HKDF-SHA256
                              │                                    │
                    ┌─────────▼─────────┐                          │
                    │  Algebraic layer  │                          │
                    │                   │                    k_stream (32B)
                    │  Prime p (Z/pZ)   │                          │
                    │  Vandermonde MDS  │                          ▼
                    │  Feistel S-box    │              ChaCha20-Poly1305 AEAD
                    │  ζ(2n) round keys │              (confidentiality +
                    │  CTR streaming    │               integrity, proven)
                    └────────┬──────────┘                          │
                             │ ct_alg                              │
                             └──────────────┬──────────────────────┘
                                            │
                                       CGL1 v0x02
                         MAGIC | VERSION | SALT | NONCE | CT_AEAD | TAG
                          (4)      (1)     (32)   (12)     (n)      (16)
                                    65-byte overhead
```

### Experimental mode (v0x03 — research only)

v3.1.0 introduces a second pipeline where ChaCha20 is removed and Poly1305 authenticates the algebraic ciphertext directly.

```
CGL1 v0x03:  MAGIC | VERSION | SALT | CT_ALG | TAG
              (4)     (1)      (32)    (n)      (16)
               53-byte overhead (no NONCE field — no ChaCha20)
```

This mode:

- **Is opt-in only** — requires both `allow_experimental=True` *and* `CAGOULE_EXPERIMENTAL_NO_AEAD=1` in the environment
- **Has no IND-CPA guarantee** — confidentiality depends entirely on the algebraic layer, which is unproven
- Exists to benchmark and analyze the algebraic layer in isolation
- Will not become the default until a formal security argument exists for the algebraic layer alone

**Do not use v0x03 for real data.**

---

## What's New in v3.1.0

### Feature 1 — Experimental mode without ChaCha20 (v0x03)

`cipher_ctr_raw.py` and `cagoule_encrypt_with_handle_raw()` implement the Poly1305-only pipeline behind the double opt-in gate described above. Wire overhead drops from 65 to 53 bytes. Not suitable for production data.

### Feature 2 — Unified C API (`cagoule_api.c`)

A single C layer wraps the full pipeline (KDF → matrix → S-box → CTR → AEAD → CGL1 header) behind one call, in two shapes:

```c
#include "cagoule_api.h"

/* Single message — full KDF paid on every call */
int cagoule_encrypt_v3(const uint8_t *password, size_t pwd_len,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t *out, size_t *out_len);
int cagoule_decrypt_v3(const uint8_t *password, size_t pwd_len,
                        const uint8_t *ciphertext, size_t ct_len,
                        uint8_t *out, size_t *out_len);

/* Bulk — amortize Argon2id across N messages */
CagouleKeyHandle *cagoule_derive_key(const uint8_t *password, size_t pwd_len,
                                      const uint8_t *salt, size_t salt_len);
int cagoule_encrypt_with_handle(CagouleKeyHandle *h, const uint8_t *pt, size_t pt_len,
                                 uint8_t *out, size_t *out_len);
int cagoule_decrypt_with_handle(CagouleKeyHandle *h, const uint8_t *ct, size_t ct_len,
                                 uint8_t *out, size_t *out_len);
void cagoule_key_handle_free(CagouleKeyHandle *h);
```

This does **not** eliminate a "ctypes overhead" problem — direct measurement of the per-primitive Python path shows ctypes marshaling overhead is under 1% of per-message cost; it was never the bottleneck earlier drafts of this document implied. The real value of this API is elsewhere:

- **Single call, no per-primitive Python↔C round trips** — one function does KDF, matrix, S-box, CTR, AEAD, and header assembly, instead of the caller orchestrating each stage.
- **Caller-owned output buffer** — `memset(out, 0, out_len)` after use is a reliable zeroization path, sidestepping the CPython `bytes` immutability limitation present in the pure-Python layer.
- **MAC-first guarantee** — the tag is verified in an internal buffer before any plaintext is written to `out`. No unauthenticated plaintext is ever released to the caller.

If you're choosing between this API and the per-primitive Python path purely for throughput, measure your own workload first — the gap is smaller than the difference in ergonomics.

`cagoule_encrypt_v3`/`cagoule_decrypt_v3` are also exported to Python as `encrypt_v3`/`decrypt_v3` (see [Quick Start](#quick-start) below) — primarily infrastructure for cross-language known-answer testing, not the primary production path (which remains `encrypt_ctr`/`decrypt_ctr` with pre-derived `CagouleParams` for anything beyond a single message).

### Feature 3 — ARM NEON backend

`cagoule_matrix_neon.c` implements the 16×16 Vandermonde matrix multiply using 128-bit NEON intrinsics (2 lanes). ARM's native unsigned comparison eliminates the MSB-flip workaround AVX2's signed-only `_mm256_cmpgt_epi64` requires.

Targets: Apple Silicon (M1–M4), AWS Graviton 2/3, Raspberry Pi 4/5. Compiled automatically when `__ARM_NEON` is defined and the build targets `aarch64`. Same dispatch mechanism as the existing AVX2 path — no API changes. Runtime detection is available via `cagoule_matrix_backend_is_neon()` (C) and `get_backend_info_v310()` (Python) — see [Quick Start](#quick-start).

**Status: compiled and cross-compiled, not yet run on physical ARM hardware.** Treat NEON throughput as unvalidated until measured on real Apple Silicon / Graviton / Raspberry Pi silicon, not just cross-compiled.

There is **no NEON S-box implementation** — only the matrix-multiply backend has a NEON path. On any platform, the S-box runs scalar or AVX2 (x86 only); it never runs on NEON. `get_backend_info_v310()`'s `sbox_backend` field will never report `"neon"`.

### Feature 4 — Streaming API with per-chunk MAC (`cagoule_stream.c`)

Large files are processed in configurable chunks (default 64 KB). Each chunk gets an independent Poly1305 tag, keyed via `HKDF(k_master, "CAGOULE_CHUNK" || chunk_index, 32)`, with the chunk index bound into the AAD alongside the session salt — so a chunk can't be silently reordered, replayed, or dropped without detection.

```c
#include "cagoule_stream.h"

CagouleStreamCtx *ctx = cagoule_stream_init(password, pwd_len, /*chunk_size=*/65536, /*allow_experimental=*/0);

uint8_t buf[65536];
ssize_t n;
while ((n = read(fd_in, buf, sizeof(buf))) > 0) {
    size_t out_cap = cagoule_stream_update_out_len(ctx, (size_t)n);
    uint8_t *out = malloc(out_cap);
    size_t out_len = out_cap;
    cagoule_stream_update(ctx, buf, (size_t)n, out, &out_len);
    write(fd_out, out, out_len);
    free(out);
}
cagoule_stream_free(ctx);
```

Per-chunk overhead: **36 bytes** (8-byte chunk index + 12-byte nonce + 16-byte Poly1305 tag) in the default AEAD mode. At 64 KB chunks that's ≈0.055% overhead, independent of file size — e.g. ≈281 KB on a 500 MB file, not a fixed cost regardless of size.

This is **C-API only for v3.1.0** — there is no dedicated CGL1 VERSION byte for the streaming wire format (a deliberate scope decision, not an oversight); the caller owns chunk framing and persistence between chunks.

**Python binding** (`cagoule.CagouleStreamCtx`, added this cycle):

```python
from cagoule import CagouleStreamCtx

with CagouleStreamCtx(b"password") as enc:
    ct1 = enc.update(b"first chunk of plaintext")
    ct2 = enc.update(b"second chunk")
    salt = enc.session_salt          # transmit to the decrypting side out-of-band

with CagouleStreamCtx.from_salt(b"password", salt) as dec:
    pt1 = dec.decrypt(ct1)
    pt2 = dec.decrypt(ct2)
```

Buffer sizing is automatic (via `cagoule_stream_update_out_len`/`cagoule_stream_decrypt_out_len`); tampering, reordering, and wrong-password chunks all raise `RuntimeError` with a message from the C error code, and no unauthenticated plaintext is ever returned.

---

## Security fixes carried from v3.0.1

v3.1.0 carries all 10 fixes from v3.0.1. The most critical:

| Fix | Description |
|---|---|
| Bug 2 — CTR IV | `IV = HKDF(k_master, "CAGOULE_CTR_V31" + nonce, 8)` — bound to the per-message nonce, not `k_master` alone |
| Bug 6 — Python S-box | Full Feistel port in Python, bit-exact vs C across all 8 production primes |
| Bug 3 — pickle | `CagouleParams.__reduce__` raises `TypeError` — `k_master` no longer exposed via IPC |

### Additional fixes, this cycle

27 issues fixed across 9 source files during the v3.1.0 implementation and audit pass. Selected items:

- `cagoule_api.c` — nonce generated before `derive_iv`, correct experimental-gate error code, output zeroized on CTR error
- `cagoule_ctr.c` — union type-pun for all `(int64_t)p` casts, UBSan-clean
- `cagoule_sbox.c` — `_invmod_generic` uses `__int128`, correct for Mersenne-64 inputs
- `cagoule_stream.c` — `allow_experimental` without the environment gate falls through to the safe default rather than returning an error
- `_buffer_pool.py` — reuse-path zeroize, re-entrancy guard, specific exception handling in `_zeroize_buf`
- `cipher_ctr.py` — size assertion before `memmove`, per-element type check in bulk paths
- `decipher_ctr.py` — per-element error collection in `decrypt_bulk_ctr` (no abort on first failure)
- `params.py` — `fast_mode` correctly applied on the Argon2id path, `delta` constrained to `[1, p-1]`

**Poly1305 key-reuse fix (v0x03 raw mode):** `poly_key` is now derived fresh per message, bound to a random per-call salt — closing a key-reuse forgery vector present in an earlier v3.1.0 draft.

**CTR AVX2 performance fix:** the AVX2 CTR matrix multiply was performing a full modular reduction after every multiply-accumulate (256 reductions per 16×16 block) instead of accumulating raw products and reducing once (16 reductions per block) — the same deferred-reduction strategy the scalar path already used. `cagoule_matrix_mul_avx2_lazy` applies this fix; CBC continues using the original, unmodified `cagoule_matrix_mul_avx2`, since the byte-range-input precondition the fix relies on does not hold for CBC's full-field-element chaining. Verified via 1.6M+ adversarial fuzz trials against the always-correct reference implementation (0 mismatches), in addition to the full regression suite.

---

## Performance

Measured on x86-64 Linux, single core, `-O3 -march=native`.

| Operation | Throughput | Notes |
|---|---|---|
| CTR encrypt 1 MB (C, v0x02, production config) | ~50 MB/s | Z-Domain Shifting active, matching real usage |
| CTR encrypt 1 MB (Python e2e) | ~22–32 MB/s | ctypes overhead confirmed <1% |
| CTR encrypt 1 MB (C, v0x03 experimental) | ~35 MB/s | No ChaCha20 — research only |
| CBC encrypt 1 MB (C) | ~7–9 MB/s | Legacy path, unchanged by this cycle's fixes |
| S-box forward (AVX2, 65K blocks) | ~120 MB/s | 4-lane vectorized |
| S-box forward (scalar, 65K blocks) | ~86 MB/s | Auto-vectorized by GCC |
| `mulmod64` (scalar) | ~5.9 ns/op | ~170M ops/s |

**Where the time goes** (CTR encrypt, per 16-byte block):

```
Matrix multiply (16×16 mulmod64)   ≈ 44%
S-box (16 Feistel passes)          ≈ 43%
Round key addition + Z-shift       ≈  8%
Counter block + XOR                ≈  5%
```

Matrix and S-box cost are roughly equal — S-box optimization is a legitimate target for future performance work, not wasted effort.

> **Methodology note.** These numbers vary meaningfully by hardware and by measurement environment — on a single-vCPU virtualized sandbox with no CPU pinning or governor control, repeated runs of the identical build have varied by up to 2× across sessions. Treat this table as directionally accurate (production config < best case; Python e2e roughly half of C throughput; CTR meaningfully faster than CBC) rather than as precise, reproducible absolute figures. **Re-measure on your own target hardware before citing a specific number externally** — a figure measured on one machine should not be assumed to transfer to another, including this document's own numbers.

For context: AES-256-GCM reaches ~4 GB/s with AES-NI. ChaCha20-Poly1305 reaches ~500 MB/s in software. CAGOULE is not competing on throughput — it is built for algebraic flexibility and ZK-circuit compatibility, not raw speed.

---

## Quick Start

### Build the C backend

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install gcc libssl-dev libargon2-dev

# Build
cd cagoule/c
make clean && make all
# libcagoule.so → cagoule/c/ and cagoule/ (keep both copies in sync —
# _find_lib() warns loudly at import time if they diverge in content;
# it loads the newer one and does not crash, but re-sync before trusting
# any benchmark numbers)

# Verify
make tests   # 16/16 binaries, 468,000+ assertions
```

### Install Python dependencies

Requires Python 3.12+ (see `pyproject.toml`'s `requires-python`).

```bash
pip install cryptography argon2-cffi
pip install mpmath  # optional: cross-backend ζ(2n) verification tests
```

### Basic usage

```python
from cagoule import encrypt, decrypt

# Encrypt — CTR mode, CGL1 v0x02 (ChaCha20-Poly1305 + algebraic layer)
ciphertext = encrypt(b"secret message", b"my password")

# Decrypt — auto-dispatches v0x01 CBC / v0x02 CTR from the header
plaintext = decrypt(ciphertext, b"my password")
assert plaintext == b"secret message"
```

### KDF amortization (bulk encryption) — recommended pattern

```python
from cagoule.params import CagouleParams
from cagoule.cipher_ctr import encrypt_ctr

with CagouleParams.derive(b"my password") as params:
    ciphertexts = [
        encrypt_ctr(msg, b"my password", params=params)
        for msg in messages
    ]
# params.zeroize() called automatically on exit
```

Argon2id runs once, not per-message. Each ciphertext remains independently decryptable across sessions — decryption re-derives `params` from `(password, header_salt)`, it does not require the original `params` object to still exist.

### Unified C API — single message (Python)

```python
from cagoule import encrypt_v3, decrypt_v3

ciphertext, n = encrypt_v3(b"my password", b"secret message")
plaintext, n = decrypt_v3(b"my password", ciphertext)
assert plaintext == b"secret message"
```

Each call pays a full Argon2id derivation — use `encrypt_ctr`/`decrypt_ctr` with pre-derived `CagouleParams` (above) for anything beyond a single message.

### Streaming (large files, Python)

```python
from cagoule import CagouleStreamCtx

with CagouleStreamCtx(b"my password") as enc:
    chunks = [enc.update(block) for block in read_in_chunks(input_file)]
    salt = enc.session_salt

with CagouleStreamCtx.from_salt(b"my password", salt) as dec:
    plaintext = b"".join(dec.decrypt(c) for c in chunks)
```

### Backend detection

```python
from cagoule._binding import get_backend_info_v310
print(get_backend_info_v310())
# {'matrix_backend': 'avx2', 'omega_backend': 'C', 'sbox_backend': 'avx2',
#  'ctr_backend': 'C', 'ctr_4x_available': True, 'neon_backend': False}
```

`matrix_backend` reports `'neon'` on aarch64 builds where the NEON path is compiled and active; `sbox_backend` never reports `'neon'` (see Feature 3 above).

### Experimental mode (research only)

```python
import os
os.environ["CAGOULE_EXPERIMENTAL_NO_AEAD"] = "1"

from cagoule.cipher_ctr_raw import encrypt_ctr_raw, decrypt_ctr_raw

# Requires both: the environment variable above AND allow_experimental=True
ct = encrypt_ctr_raw(b"benchmark data", b"password", allow_experimental=True)
pt = decrypt_ctr_raw(ct, b"password", allow_experimental=True)
```

Do not use v0x03 for real data. Confidentiality depends solely on the algebraic layer, which has no published security proof.

---

## Project Structure

```
CAGOULE/
├── cagoule/                        # Python package
│   ├── __init__.py                 # Public API — encrypt/decrypt/CagouleParams/
│   │                                #   encrypt_v3/decrypt_v3/CagouleStreamCtx
│   ├── params.py                   # CagouleParams: KDF + key schedule
│   ├── cipher.py                   # CBC encrypt  (CGL1 v0x01)
│   ├── cipher_ctr.py               # CTR encrypt  (CGL1 v0x02) ← main path
│   ├── cipher_ctr_raw.py           # CTR experimental (CGL1 v0x03)
│   ├── decipher.py                 # CBC decrypt
│   ├── decipher_ctr.py             # CTR decrypt (v0x02 + v0x03)
│   ├── stream.py                   # CagouleStreamCtx — streaming API binding
│   ├── sbox.py                     # S-box (C backend + Python Feistel fallback)
│   ├── matrix.py                   # Vandermonde/Cauchy diffusion matrix
│   ├── omega.py                    # ζ(2n) round-key derivation
│   ├── fp2.py                      # Fp² arithmetic (mu generation)
│   ├── mu.py                       # μ parameter selection
│   ├── _binding.py                 # ctypes bindings to libcagoule.so
│   ├── _buffer_pool.py             # Thread-local buffer pool (re-entrancy safe)
│   ├── format.py                   # CGL1 wire format spec reference
│   └── c/                          # C backend
│       ├── Makefile
│       ├── src/
│       │   ├── cagoule_math.c          # Modular arithmetic (mulmod64, addmod64)
│       │   ├── cagoule_matrix.c        # 16×16 Vandermonde/Cauchy multiply
│       │   ├── cagoule_matrix_avx2.c   # AVX2 4-lane matrix (x86-64)
│       │   ├── cagoule_matrix_neon.c   # NEON 2-lane matrix (ARM, aarch64 only)
│       │   ├── cagoule_sbox.c          # 2-round Feistel S-box + AVX2
│       │   ├── cagoule_sbox_avx2.c     # AVX2 S-box block operations
│       │   ├── cagoule_cipher.c        # CBC pipeline
│       │   ├── cagoule_ctr.c           # CTR pipeline (AVX2 4x unrolled)
│       │   ├── cagoule_omega.c         # ζ(2n) round-key derivation
│       │   ├── cagoule_kdf.c           # Argon2id + HKDF-SHA256 wrappers
│       │   ├── cagoule_params.c        # C-side parameter struct
│       │   ├── cagoule_api.c           # Unified C API
│       │   └── cagoule_stream.c        # Streaming per-chunk MAC
│       ├── include/                    # Public headers
│       ├── tests/                      # C test sources — 16 binaries, 468,000+ assertions
│       └── fuzz/                       # libFuzzer harness
├── tests/                          # Python test suite — 722 tests, 12 skipped
├── README.md
├── CHANGELOG.md
├── SECURITY.md
├── ARCHITECTURE.md
├── LICENSE
├── pyproject.toml
├── regenerate_kat.py
├── sbox_analysis_report.md        # S-box differential/linear analysis
└── sbox_analysis_report.json
```

---

## Running Tests

```bash
# Full Python suite
python3 -m pytest tests/ -q

# C test suite
cd cagoule/c
make tests

# Fuzzing (requires clang)
clang -O1 -fsanitize=fuzzer,address,undefined \
    -Iinclude fuzz/fuzz_cipher.c -L. -lcagoule -o fuzz_cipher
./fuzz_cipher -max_len=65536 -runs=1000000

# KAT cross-backend verification
python3 regenerate_kat.py --check

# Cross-backend ζ(2n) verification (requires mpmath)
python3 -m pytest tests/test_omega.py -k BitExact -v
```

---

## Wire Format (CGL1)

All CAGOULE ciphertexts are self-describing. The version byte determines the decryption pipeline — `decrypt()` dispatches automatically.

```
v0x01  CBC + ChaCha20-Poly1305 (legacy):
  CGL1 | 0x01 | SALT(32) | NONCE(12) | CT(n) | TAG(16)

v0x02  CTR + ChaCha20-Poly1305 (default):
  CGL1 | 0x02 | SALT(32) | NONCE(12) | CT(n) | TAG(16)
  Overhead: 65 bytes

v0x03  CTR + Poly1305 only (experimental):
  CGL1 | 0x03 | SALT(32) | CT(n) | TAG(16)
  Overhead: 53 bytes
  AAD: MAGIC | VERSION | SALT (authenticated, not encrypted)
```

**Compatibility notes:**

- v3.0.1 → v3.1.0: v0x02 ciphertexts are forward-compatible (IV formula unchanged from the v3.0.1 final fix)
- v3.0.0 → v3.0.1: v0x02 CTR ciphertexts are **incompatible** (IV formula changed by the v3.0.1 Bug 2 fix — this was a real confidentiality fix, not a cosmetic change)
- v0x01 CBC ciphertexts are compatible across all versions
- The streaming API (Feature 4) has its own per-chunk wire format, distinct from CGL1 — see [Feature 4](#feature-4--streaming-api-with-per-chunk-mac-cagoule_streamc) above

---

## Security Status

| Property | Status | Evidence |
|---|---|---|
| ChaCha20-Poly1305 AEAD | ✅ Proven | Standard, 15+ years, IETF RFC 8439 |
| Argon2id KDF | ✅ Proven | PHC winner, IETF RFC 9106 |
| HKDF-SHA256 | ✅ Proven | IETF RFC 5869 |
| CTR IV uniqueness | ✅ Fixed v3.0.1 | Nonce-bound IV, empirically verified |
| Python S-box keyed | ✅ Fixed v3.0.1 | Bit-exact Feistel port, 16K+ comparisons |
| Algebraic degree | ⚠️ Low (d=1, 2 rounds) | Known limitation — insufficient confusion on its own; see note below |
| Algebraic IND-CPA | ⚠️ Conjectured | DDT/LAT analysis performed, no formal proof |
| Formal security reduction | ❌ Open problem | No reduction to a standard hardness assumption |
| Branch Number (MDS property) | ⚠️ Mathematically implied, not independently computed by this project's own tooling | See note below |

**On the algebraic degree limitation:** a 2-round Feistel network with a linear round function (`x * rk mod p`) has algebraic degree 1 — insufficient for strong confusion on its own. This is a known, documented weakness of the current algebraic layer, not a hidden one. It is the reason the default mode (v0x02) always wraps the algebraic layer in ChaCha20-Poly1305, which does not depend on the algebraic layer's strength at all.

**On the Branch Number row, precisely stated:** an n×n Vandermonde matrix over a field, constructed from n distinct nodes, is a classical MDS matrix — a standard result from coding theory (the same property that makes Reed-Solomon codes MDS). CAGOULE's node-derivation step (`_derive_nodes` in `params.py` / `cagoule_params.c`) guarantees distinct nodes via collision-avoidance retries before matrix construction, falling back to a Cauchy construction (also classically MDS) on the rare collision path. So the 16×16 diffusion matrix is MDS **by construction, following a well-known theorem** — not a novel or unverified claim specific to this project. For an MDS matrix of this size, the branch number is `n+1 = 17` by definition. What has **not** been done is an independent, project-specific computational check that produces this as a verified, tooled output — no test or script in this codebase currently computes or asserts it directly. `SECURITY.md` and `ARCHITECTURE.md` describe this as "not yet computed," which is accurate for "verified by this project's own tooling," even though the underlying mathematical property holds by construction.

**The honest current claim:** the outer ChaCha20-Poly1305 layer (default mode) is proven, standard, and does not depend on any of the above. The algebraic layer's confidentiality is conjectured, evidenced by preliminary differential/linear analysis, and not formally proven. It is not ready to stand alone in production, and the experimental mode that removes ChaCha20 (v0x03) exists explicitly to study it in isolation, not to replace the default.

See [SECURITY.md](SECURITY.md) for the complete threat model and known limitations.

---

## Comparison to Related Work

| Cipher | Setting | ZK-friendly | Proof | Speed |
|---|---|---|---|---|
| AES-256 | GF(2⁸) | ❌ Expensive | ✅ Formal (PRP under AES) | ~4 GB/s (AES-NI) |
| ChaCha20 | ARX, Z/2³²Z | ❌ Expensive | ✅ Formal (PRF) | ~500 MB/s |
| MiMC | Z/pZ | ✅ Native | ⚠️ Conjecture | ~10–50 MB/s |
| Poseidon | Z/pZ | ✅ Native | ⚠️ Conjecture | ~10–50 MB/s |
| CAGOULE | Z/pZ | ✅ Native | ⚠️ Open | ~50 MB/s (C), ~22–32 MB/s (Python e2e) |

CAGOULE occupies the same algebraic setting as MiMC and Poseidon (prime-field power maps), with a different construction (Vandermonde diffusion + Feistel S-box + ζ(2n) round keys) and a stronger outer AEAD layer by default.

---

## License

MIT — see [LICENSE](LICENSE).

## Author

Slim Issa (LASS) — CTO, QuantOS, Kairouan, Tunisia

## Contributing

This is a research project. Before contributing:

1. Read [SECURITY.md](SECURITY.md) — especially the IND-CPA status section
2. Read [ARCHITECTURE.md](ARCHITECTURE.md) — algebraic construction details
3. Run the full test suite: `pytest tests/ -q` and `make tests` in `cagoule/c/`
4. Any change to the cryptographic core (matrix, S-box, omega, CTR pipeline) requires regenerating the KAT vectors: `python3 regenerate_kat.py`

Bug reports involving security findings: open a GitHub issue marked `[SECURITY]`. Do not include exploit code in public issues.