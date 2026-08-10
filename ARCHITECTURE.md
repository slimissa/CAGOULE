# CAGOULE v3.1.0 — Architecture

## Data-Flow Diagram

```
                          ┌─────────────────────────────────────────────────────────┐
                          │                   CAGOULE v3.0.0                        │
                          │    Cryptographie Algébrique Géométrique par Ondes       │
                          │                 et Logique Entrelacée                   │
                          └─────────────────────────────────────────────────────────┘

   password ────►  Argon2id KDF  ────►  k_master (64 bytes)
        │              │                        │
        │         (RFC 9106)                    ├──► HKDF("CAGOULE_PRIME_SEL_V25") ──► Mersenne Pool Index ──► p = 2^64 - k
        │                                       │
        │                                       ├──► HKDF("CAGOULE_N") ──► n (block size)
        │                                       │
        │                                       ├──► generate_mu(p) ──► µ ∈ Z/pZ or Fp²
        │                                       │
        │                                       ├──► HKDF("CAGOULE_DELTA") ──► S-Box Feistel (rk0, rk1)
        │                                       │
        │                                       ├──► HKDF("CAGOULE_NODE_*") ──► Vandermonde Nodes
        │                                       │
        │                                       ├──► HKDF("CAGOULE_ENC") ──► k_stream (ChaCha20-Poly1305)
        │                                       │
        │                                       ├──► ζ(2n) → HKDF ──► 64 Round Keys (Z/pZ)
        │                                       │
        │                                       ├──► HKDF("CAGOULE_Z_SHIFT_V25") ──► z_offset[16]
        │                                       │
        │                                       └──► HKDF("CAGOULE_CTR_V30") ──► IV_CTR (8 bytes, v3.0.0)
        │
        ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │                    CBC MODE (v0x01, legacy)                           │
  │                                                                      │
  │  plaintext → PKCS7 Pad → Z-Domain Shift → CBC Add →                  │
  │  Vandermonde → Feistel S-Box → Round Key Add →                       │
  │  ChaCha20-Poly1305 AEAD → CGL1 v0x01                                 │
  └──────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                    CTR MODE (v0x02, v3.0.0)                           │
  │                                                                      │
  │  plaintext (arbitrary length, no padding)                            │
  │     │                                                                │
  │     ▼                                                                │
  │  ┌─────────────────────┐                                             │
  │  │  Z-Domain Shifting   │  byte[i] = (byte[i] + z_offset[i%16]) % 256│
  │  │  (v2.5.1, C-layer)  │                                             │
  │  └─────────┬───────────┘                                             │
  │            │                                                         │
  │            ▼                                                         │
  │  ┌─────────────────────────────────────────────────────────┐        │
  │  │           CTR KEYSTREAM PIPELINE (C + AVX2)             │        │
  │  │                                                          │        │
  │  │  counter_block = IV(8) ‖ bi(8)   (bi = block index)     │        │
  │  │       │                                                  │        │
  │  │       ▼                                                  │        │
  │  │  ┌───────────┐    ┌───────────┐    ┌──────────────┐     │        │
  │  │  │Vandermonde│───►│  Feistel  │───►│ Round Key Add│     │        │
  │  │  │ 16×16 Mul │    │  S-Box    │    │  (mod p)     │     │        │
  │  │  └───────────┘    └───────────┘    └──────┬───────┘     │        │
  │  │                                            │              │        │
  │  │                     keystream[j] = out[j] & 0xFF         │        │
  │  │                                                          │        │
  │  │  ciphertext[j] = (plaintext[j] + zo_byte[j]) ^ ks[j]    │        │
  │  │                                                          │        │
  │  │  Optimizations (v3.0.0):                                 │        │
  │  │  • 4-block simultaneous pipeline (ILP maximal)           │        │
  │  │  • No inter-block dependency (CTR mode)                  │        │
  │  │  • |CT| == |PT| (no PKCS7 padding)                       │        │
  │  │  • encrypt == decrypt (CTR symmetry)                     │        │
  │  └──────────────────────────────────────────────────────────┘        │
  │            │                                                         │
  │            ▼                                                         │
  │  ┌─────────────────────┐                                             │
  │  │  ChaCha20-Poly1305   │  AEAD Encrypt (RFC 8439)                   │
  │  │  (k_stream, nonce)  │                                             │
  │  └─────────┬───────────┘                                             │
  │            │                                                         │
  │            ▼                                                         │
  │  CGL1 Wire Format:  MAGIC | VERSION=0x02 | SALT | NONCE | CT | TAG  │
  └──────────────────────────────────────────────────────────────────────┘

                          ┌─────────────────────────────────────────────────────────┐
                          │                   DECRYPTION PIPELINE                    │
                          │                                                          │
                          │  CGL1 → Parse → AEAD Decrypt →                           │
                          │  VERSION 0x01 → CBC: Inverse S-Box → Inverse Matrix →    │
                          │                  CBC Subtract → Z-Domain Unshift →       │
                          │                  PKCS7 Unpad → plaintext                 │
                          │  VERSION 0x02 → CTR: Keystream gen → XOR+Z-Unshift →    │
                          │                  plaintext (symmetric)                   │
                          └─────────────────────────────────────────────────────────┘
```

---

## Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PYTHON PUBLIC API                         │
│  encrypt() → CTR (v0x02) | encrypt_cbc() → CBC (v0x01)     │
│  decrypt() → auto-dispatch v0x01/v0x02                      │
│  encrypt_bulk() / decrypt_bulk() / migrate_cbc_to_ctr()     │
│  CagouleParams.derive() / CagouleParams.zeroize()           │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  PYTHON CRYPTOGRAPHIC MODULES                │
│  cipher.py · decipher.py · cipher_ctr.py · decipher_ctr.py  │
│  params.py · format.py · omega.py · matrix.py · sbox.py     │
│  mu.py · fp2.py · _binding.py (ctypes) · _buffer_pool.py    │
└────────────────────────┬────────────────────────────────────┘
                         │ ctypes
┌────────────────────────▼────────────────────────────────────┐
│                   C SHARED LIBRARY                           │
│                     libcagoule.so                            │
│                                                              │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌─────────┐  │
│  │  cipher  │  │  matrix   │  │    sbox    │  │  omega  │  │
│  │ CBC pipe │  │ Vandermonde│  │  Feistel   │  │ ζ(2n)→RK│  │
│  │ CTR pipe │  │ + Inverse │  │  AVX2 SBox │  │  HKDF   │  │
│  │ Z-Domain │  │ + Cauchy  │  │            │  │ OpenSSL │  │
│  │ Pipeline4│  │            │  │            │  │         │  │
│  └──────────┘  └───────────┘  └────────────┘  └─────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  math (scalar)  │  math_avx2 (Barrett + Mersenne)   │    │
│  └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

### 1. Mersenne-64 Prime Pool (v3.0.0)

| Prime | k | p = 2^64 - k |
|-------|---|--------------|
| P_M59 | 59 | 18446744073709551557 |
| P_M83 | 83 | 18446744073709551533 |
| P_M95 | 95 | 18446744073709551521 |
| P_M179 | 179 | 18446744073709551437 |
| P_M189 | 189 | 18446744073709551427 |
| P_M257 | 257 | 18446744073709551359 |
| P_M279 | 279 | 18446744073709551337 |
| P_M323 | 323 | 18446744073709551293 |

- **Selection**: HKDF("CAGOULE_PRIME_SEL_V25")[0] % 8
- **Advantage**: `a*b mod p = hi*k + lo` — no division needed
- **Instruction count**: ~13 (Mersenne) vs ~22 (Barrett) per multiplication

### 2. Option A — Dual Accumulator

```
v2.4.0:  acc += M[j] * v[j]   for j = 0..15   → depth 16 chain
v2.5.1:  acc_a += M[j] * v[j]  for j even     → depth 8 chain
         acc_b += M[j] * v[j]  for j odd      → depth 8 chain
         acc = acc_a + acc_b                   → merge at end
```

- **Register budget**: ~13 YMM (Mersenne) vs 16+ YMM (Barrett)
- **CPU ILP**: Two independent chains execute in parallel

### 2a. AVX2 Lazy Reduction (v3.1.0 addendum)

The dual-accumulator design above still called `mulmod_mersenne64x4`
(full modular reduction) on *every* multiply-accumulate — 256 reductions
per 16×16 block, the same count the scalar path used before its own
v2.5.x deferred-reduction optimization. This was a real, non-obvious
performance bug: the AVX2 path was doing 16× more reduction work than
the scalar path for equivalent output, to the point that AVX2 measured
*slower* than scalar on some hardware.

The fix (`cagoule_matrix_mul_avx2_lazy`, `cagoule_matrix_avx2.c`) applies
the same accumulate-raw-then-reduce-once strategy the scalar CTR path
already used, adapted for AVX2's 4-lane `__m256i` registers:

```
for each of 16 columns:
    (prod_lo, prod_hi) = raw 128-bit product, no reduction (_mul128x4)
    lo += prod_lo   ; carry-checked add (uint64 overflow tracked explicitly)
    hi += prod_hi + carry
reduce once: result = (hi * k + lo) mod p   ; two conditional subtracts
```

Two details matter enough to call out explicitly, because getting them
wrong produces silently-wrong ciphertext rather than a crash:

- **Carry propagation between `lo` and `hi` is not optional.** Each raw
  product's low 64 bits can be any value; summing 8 of them can overflow
  64 bits more than once. A naive `lo += prod_lo` without an explicit
  overflow check (`_cmpgt_epu64` after every add, matching the pattern
  `_mul128x4` itself already uses internally) silently drops carries
  that should propagate into `hi`, corrupting the result for whatever
  fraction of blocks happen to hit the overflow.
- **The final reduction needs two conditional subtracts, not one**,
  matching the scalar reference (`reduce128_mersenne`)'s own "second
  subtract for k > 1 edge case" — a single-subtract reduction (sufficient
  in some other contexts in this codebase, like the per-term reduction
  inside `mulmod_mersenne64x4` itself, where the pre-correction magnitude
  is already tightly bounded) is not sufficient here.

### 2b. Split-Function Pattern (scalar and AVX2)

Both the scalar and AVX2 matrix multiplies now follow the same two-function
split, and for the same reason: lazy/deferred reduction is only safe when
inputs are byte-range (0–255), which CTR counter blocks are but CBC's
chained full-field-element inputs are not.

| Layer | Full-reduction (CBC-safe, any input in `[0,p)`) | Lazy/deferred (CTR-only, byte-range input required) |
|---|---|---|
| Scalar | `_matmul16_scalar` | `_matmul16_scalar_lazy` |
| AVX2 | `cagoule_matrix_mul_avx2` | `cagoule_matrix_mul_avx2_lazy` |

CBC continues calling the left column exclusively — this was verified,
not assumed, by grepping every call site of both AVX2 functions before
and after the lazy variant was added. The precondition itself (byte-range
`v[]`) is enforced by a debug `assert()` in both lazy functions (compiled
out under `-DNDEBUG`, i.e. in `make release` builds) — a comment-only
precondition was judged insufficient given this exact bug class (lazy
reduction misapplied to full-field-element input) already produced one
real vulnerability in this codebase's history (the scalar-path two-time-pad).

### 3. CTR Mode (v3.0.0)

- **Counter block**: IV(8 bytes) ‖ block_index(8 bytes, big-endian)
- **Keystream**: counter_block → matrix → sbox → round_key_add → byte_extract
- **4-block pipeline**: 4 independent keystreams computed simultaneously
- **No inter-block dependency**: ILP maximal, streaming-friendly
- **No padding**: |CT| == |PT| exact
- **Symmetric**: encrypt == decrypt at C-layer (only Z-shift direction differs)
- **IV derivation**: `HKDF(k_master, "CAGOULE_CTR_V31" + nonce, 8)` — bound to the per-message ChaCha20 nonce, not `k_master` alone. (An earlier formula, `HKDF(k_master, "CAGOULE_CTR_V30", 8)`, did not include the nonce and produced a shared IV whenever `params` was reused across messages — this was a real vulnerability, tracked as `CAGOULE-2026-001`, fixed in v3.0.1. This section previously described the pre-fix formula as current; corrected here.)

### 4. Z-Domain Shifting

- **Operation**: `byte[i] = (byte[i] + z_offset[i%16] % 256) % 256`
- **Location**: C-layer (pre-encryption) for performance
- **Derivation**: `z_offset = HKDF(k_master, "CAGOULE_Z_SHIFT_V25", 128) % p`
- **Security**: Prevents DDT precomputation attacks on the algebraic layer

### 5. Feistel S-Box Symmetry

- **2-round Feistel** on 32-bit halves
- **Round function**: `f(x, rk) = (x * rk) % P32_PRIME` where `P32_PRIME = 2^32 - 5`
- **Key property**: `decrypt_cost ≈ encrypt_cost` (ratio ≈ 1.0×)
- **v1.x ratio was 7.8×** — the Feistel design eliminated the asymmetry

### 6. Dual-Path Architecture

| Layer | C Backend | Python Fallback |
|-------|-----------|-----------------|
| Matrix | `cagoule_matrix_mul` (AVX2) | `_matmul16_scalar` |
| S-Box | `cagoule_sbox_forward` (Feistel AVX2) | `x^d mod p` |
| Omega | `cagoule_omega_generate_round_keys` | `mpmath.zeta()` |
| CBC | `cagoule_cbc_encrypt` (pipeline4) | `_cbc_encrypt_py` |
| CTR | `cagoule_ctr_encrypt` (4-block SIMD) | `_ctr_encrypt_py` |

---

## Memory Management

```
Allocation:    cagoule_matrix_build() → calloc()
               ↓
Usage:         cagoule_matrix_mul() → AVX2 or scalar
               ↓
Cleanup:       1. free()       — explicit, preferred
               2. __exit__()   — context manager (with statement)
               3. __del__()    — GC fallback (logs errors)
```

- **Double-free guard**: `_freed` flag prevents corruption
- **Buffer pool**: Thread-local `ctypes` buffers reused across calls (P4)
- **Zeroization**: Sensitive buffers zeroed via `ctypes.memset` after use

---

## Thread Safety

| Component | Mechanism |
|-----------|-----------|
| AVX2 detection | `__atomic_load/store` (lock-free lazy init) |
| Buffer pool | `threading.local()` |
| Omega round keys | Stack allocation per call |
| Encryption | GIL release on heavy C calls |

---

## CGL1 Wire Format

```
Offset  Size  Field
─────────────────────
  0      4     MAGIC    = b'CGL1'
  4      1     VERSION  = 0x01 (CBC) or 0x02 (CTR, default)
  5     32     SALT     (Argon2id salt)
 37     12     NONCE    (ChaCha20-Poly1305 nonce)
 49     CT     CIPHERTEXT + TAG (Poly1305 tag = last 16 bytes)
─────────────────────
OVERHEAD = 65 bytes (49 header + 16 tag)

CTR (v0x02): |CT| == |plaintext| (no padding)
CBC (v0x01): |CT| is padded to 16-byte boundary (PKCS7)

VERSION = 0x03 (CTR, experimental, v3.1.0 — no ChaCha20 layer):
Offset  Size  Field
─────────────────────
  0      4     MAGIC    = b'CGL1'
  4      1     VERSION  = 0x03
  5     32     SALT
 37     CT     CIPHERTEXT + TAG (Poly1305 tag = last 16 bytes, no NONCE field)
─────────────────────
OVERHEAD = 53 bytes (37 header + 16 tag) — 12 bytes smaller than v0x02
           because there is no ChaCha20 nonce. AAD = MAGIC|VERSION|SALT.
Requires allow_experimental=True AND CAGOULE_EXPERIMENTAL_NO_AEAD=1 — see
SECURITY.md §5.7 for why this is opt-in only (no IND-CPA proof for the
algebraic layer standing alone).
```

---

## Performance Characteristics

**Updated for this pass — see `SECURITY.md` §6.1/§6.1a/§6.1b for full
methodology, verification details, and caveats.** Figures below
supersede the v3.0.0-era table that previously stood here.

| Operation | Throughput | Notes |
|-----------|-----------|-------|
| CTR encrypt (C, AVX2, production config) | 50.5 MB/s | Z-Domain Shifting active; AVX2 lazy-reduction fix applied |
| CTR encrypt (C, AVX2, best-case single run) | 52.8 MB/s | Same build, favorable measurement |
| CTR encrypt (C, forced scalar) | 45.8 MB/s | For comparison — AVX2 is no longer slower than scalar |
| CTR encrypt (Python e2e) | 26–32 MB/s | Environment-dependent; ctypes overhead confirmed <1%, not the bottleneck |
| CBC encrypt (1 MB) | ~7-9 MB/s | Not in scope for the v3.1.0 performance work — unchanged |
| S-box Feistel | ~70-120 MB/s | AVX2 vectorized |
| vs AES-256-GCM | ~220-240× slower (this pass, single machine) | CAGOULE is a research cipher, software-only by design |

**Methodology caveat:** measured on a single-vCPU virtualized sandbox
with no CPU pinning or governor control. Repeated runs of the identical
build varied by up to 2× across the session. Use `make benchmark`
(repeated runs with warmup, reports mean/min/max) on dedicated, pinned
hardware before citing a specific figure externally.

---

## Test Coverage

| Suite | Assertions | Focus |
|-------|-----------|-------|
| C tests (16 binaries) | 468,857+ | Unit + parity + AVX2/NEON + CTR + streaming + error paths |
| Python tests (pytest) | 722 tests, 12 skipped | Integration + KAT + NIST + CTR |
| `test_mersenne` | 4,000,032 | Mersenne-64 pool |
| `test_ctr` | 468,857 | CTR mode, all 8 primes, production-matching benchmark |
| `test_params_kat` | 17 | `cagoule_params_derive` cross-checked byte-for-byte vs Python (new) |
| `test_stream` | 76 | Streaming API: multi-chunk, reorder/tamper rejection, salt properties, edge-case sizes |
| `test_api_raw` | 364 | Handle API: all 8 primes, zero-length, buffer boundaries |
| `test_error_paths` | 43 | `cagoule_encrypt_v3`/`decrypt_v3` (previously zero coverage), NULL-guard sweeps (new) |
| Valgrind | Not re-verified this pass | Valgrind unavailable in the audit environment — do not assume the 8-binary v2.x figure still covers the current 16-binary suite |
| libFuzzer | 1M+ runs (CBC + CTR); +1.6M adversarial trials specifically for the AVX2 lazy-reduction fix | See `SECURITY.md` §6.1a |

---

## Build System

```
make              → libcagoule.so (AVX2/NEON if available)
make tests        → All 16 C test binaries
make release      → Production build: LTO + NDEBUG + strip
make benchmark    → CTR throughput, repeated runs + warmup, mean/min/max
make test-ctr     → CTR tests
make test-avx2    → AVX2 tests (Mersenne + matrix + S-box)
make valgrind     → Memory leak detection (not re-verified this pass — see Test Coverage above)
make fuzz         → libFuzzer 1M runs (CBC + CTR)
make debug        → ASan + UBSan build
make install      → Copy to Python package
make sysinfo      → Compiler/flags/features summary
```

- **AVX2 detection**: runtime dispatch via `__builtin_cpu_supports("avx2")`, lazy-initialized once via `__atomic` (see Thread Safety below)
- **Per-file AVX2**: only files needing AVX2 intrinsics are compiled with `-mavx2`
- **`make release`** adds `-flto -DNDEBUG` and strips symbols. `NDEBUG` disables the debug `assert()`s added for the lazy-reduction safety precondition (§2a above) — these are internal-invariant checks already guaranteed by every current caller, not a security boundary on attacker-controlled input, so disabling them in release builds does not weaken the cipher's actual guarantees (the MAC/tag check, which *is* the security boundary, is unaffected by `NDEBUG`).

---

## Version History

| Version | Date | Key Features |
|---------|------|-------------|
| v3.1.0 | 2026-07-16 | Unified C API (`cagoule_api.c`), streaming API with per-chunk MAC, ARM NEON backend, experimental v0x03 mode. Post-release audit pass (this document's current state): AVX2 lazy-reduction fix (50.5 MB/s production), 14 security findings fixed, `_find_lib()` hardened, C test suite grown to 16 binaries |
| v3.0.1 | 2026-07-13 | Security patch — CTR IV bound to per-message nonce (fixes `CAGOULE-2026-001`), Python S-box keyed (bit-exact Feistel port), `CagouleParams.__reduce__` blocks pickle exposure of `k_master` |
| v3.0.0 | 2026-05-28 | CTR mode, 4-block SIMD pipeline, CGL1 v0x02, 19.7 MB/s, encrypt/decrypt dispatch |
| v2.5.1 | 2026-05-25 | Mersenne-64 pool, Option A dual accumulator, Z-Domain Shifting (C-layer) |
| v2.4.0 | 2026-05-16 | Pipeline4, encrypt_bulk API, GIL release, thread-local buffer pool |
| v2.3.0 | 2026-05-08 | S-box AVX2, Mersenne-like reduction, cycle-walking AVX2 |
| v2.2.0 | 2026-05-06 | AVX2 Vandermonde matrix multiply |
| v2.1.0 | 2026-05-01 | C port of omega.c, wrong-password detection fix |
| v2.0.0 | — | Feistel S-box (1:1 decrypt/encrypt ratio) |
| v1.x | — | Original x^d S-box (7.8× decrypt/encrypt ratio) |

---

## Author

**Slim Issa** — Kairouan, Tunisia  
Part of the QuantOS platform  
github.com/slimissa/CAGOULE

**License**: MIT
