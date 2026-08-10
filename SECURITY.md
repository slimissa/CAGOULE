# Security Policy — CAGOULE v3.1.0

## Security Advisory — v3.1.0 Patch

v3.0.1 fixes two vulnerabilities present in v3.0.0 that affect confidentiality:

**CAGOULE-2026-001 (Critical): CTR two-time-pad via shared `params=`**
Calling `encrypt_ctr(message, password, params=<shared>)` with the same
`CagouleParams` object for multiple messages produced identical algebraic
keystreams, enabling full plaintext recovery. Fixed in v3.0.1 by binding the
IV to the per-message ChaCha20 nonce rather than `k_master` alone. The outer
ChaCha20-Poly1305 layer masked this from ciphertext observers, but was not
protection against an attacker who obtained the shared `params` object.

**CAGOULE-2026-002 (High): Python fallback S-box unkeyed**
In deployments without `libcagoule.so` (pure-Python mode), `SBoxPython` used
`x³ mod p` regardless of the password-derived `delta` parameter. The nonlinear
algebraic layer contributed zero key material. Fixed by porting the full Feistel
construction to Python, bit-exact against C.

**CAGOULE-2026-003 (Critical): Poly1305 key reuse in VERSION 0x03 (RAW/experimental)**
`_derive_poly_key()` in `cipher_ctr_raw.py`, and the equivalent path in
`cagoule_api.c`'s C handle API, derived the Poly1305 authentication key from
`k_master` alone. Any two messages encrypted under a shared `CagouleParams`
object (Python) or shared `CagouleKeyHandle` (C) — the documented bulk usage
pattern — received an *identical* Poly1305 key. Poly1305 is only a one-time
authenticator: reuse across two or more messages under the same key enables
universal MAC forgery. Reachable via the documented public API
(`encrypt_ctr_raw(msg, pwd, params=shared_params, allow_experimental=True)`
in Python; any two calls to `cagoule_encrypt_with_handle_raw()` on the same
handle in C). Fixed in both languages by binding `poly_key` derivation to the
per-message salt (32 bytes, fresh per call), mirroring the same fix already
applied to the CTR IV for CAGOULE-2026-001. VERSION 0x03 remains
experimental/research-only regardless of this fix — see section 5.7.

Upgrade immediately if you have used `encrypt_ctr_raw()` or the C RAW handle
API with a shared `params`/`handle` object. Ciphertexts produced this way
before the fix should be considered forgeable and re-encrypted.

Upgrade to v3.0.1. v3.0.0 CTR ciphertexts cannot be decrypted by v3.0.1
(IV formula changed). CBC ciphertexts (v0x01) are unaffected.

---

## Table of Contents

1. [Scope and Purpose](#1-scope-and-purpose)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Security Model](#3-security-model)
4. [Threat Model — What CAGOULE Protects Against](#4-threat-model--what-cagoule-protects-against)
5. [Out of Scope — What CAGOULE Does NOT Protect Against](#5-out-of-scope--what-cagoule-does-not-protect-against)
6. [Known Limitations](#6-known-limitations)
7. [Side-Channel Considerations](#7-side-channel-considerations)
8. [Key Material Lifecycle](#8-key-material-lifecycle)
9. [Version Compatibility and Breaking Changes](#9-version-compatibility-and-breaking-changes)
10. [Reporting a Vulnerability](#10-reporting-a-vulnerability)

---

## 1. Scope and Purpose

CAGOULE is a **research-grade symmetric encryption system** designed as part of the QuantOS platform. It is not a production replacement for AES-GCM or ChaCha20-Poly1305. Its primary purpose is to explore a novel algebraic diffusion layer (Vandermonde over Z/pZ, Feistel S-box, ζ(2n)-derived round keys) wrapped by standardized cryptographic primitives.

This document defines the threat model, the security properties CAGOULE provides, and the explicit limitations that any deployer must understand before use.

---

## 2. Cryptographic Primitives

### 2.1 Standardized Primitives

| Primitive | Role | Standard | Implementation |
|---|---|---|---|
| Argon2id | Password-based KDF | RFC 9106 | `argon2-cffi` |
| HKDF-SHA256 | Key derivation and domain separation | RFC 5869 | OpenSSL (C-layer) |
| ChaCha20-Poly1305 | AEAD streaming encryption | RFC 8439 | `cryptography` (Python) |

These primitives are **not modified** and provide their standard security guarantees. Their parameter choices in CAGOULE are:

- **Argon2id (production)**: `t=3, m=64MB, p=1` — OWASP-compliant, ~114ms on a single core
- **Argon2id (multi-core)**: `t=3, m=64MB, p=4` — same security, ~51ms
- **HKDF**: distinct domain labels per derived key material (`"CAGOULE_N"`, `"CAGOULE_DELTA"`, `"CAGOULE_ENC"`, `"CAGOULE_PRIME_SEL_V25"`, `"CAGOULE_Z_SHIFT_V25"`, `"CAGOULE_CTR_V30"`, `"CAGOULE_NODE_*"`)

### 2.2 CAGOULE Algebraic Layer

| Component | Construction | Security Role |
|---|---|---|
| Vandermonde 16×16 matrix | Defined over Z/pZ — Mersenne-64 prime (v2.5.x) | Diffusion — MDS-like structure |
| 2-round Feistel S-box | `f(x, rk) = (x × rk) % P32_PRIME`, P32_PRIME = 2³² − 5 | Confusion |
| Round keys (64) | ζ(2n) → HKDF-SHA256 (see caveat below) | Key schedule |
| Mersenne-64 prime pool | 8 primes of form p = 2⁶⁴ − k (k < 2¹⁰), HKDF-selected | Structural diversity of the field |
| Z-Domain Shifting | `byte[i] = (byte[i] + z_offset[i%16] % 256) % 256` — byte-level whitening | Pre-computation defense |
| CTR Mode (v3.0.0) | Counter mode with 4-block SIMD keystream pipeline | No inter-block dependency, streaming-friendly |

**Important**: the algebraic layer has **not been formally analyzed or peer-reviewed**. Its security properties are claimed by design but not proven. See section 6.

**Caveat on "ζ(2n)-derived round keys"**: `params.n` (the ζ argument selector)
is drawn uniformly from `[4, 65539]`. In double-precision floating point,
`ζ(2n)` rounds to exactly `1.0` for `n ≥ 27`, which is **~99.97% of the
selectable range**. For those keys, the intended Riemann-zeta-derived seed
component (`ak_seed`) collapses to `0` for round-key indices ≥ 2, and key
schedule uniqueness for those rounds falls back entirely to
`salt + round-key-index` mixed via HKDF. This is not a break — HKDF with a
per-message salt and a distinct index per round key remains a sound
construction — but the claim that round keys are meaningfully "ζ(2n)-derived"
is false for nearly the entire practical keyspace. Anyone relying on the
number-theoretic framing (e.g. for the IACR submission) should account for
this before making claims about the round-key construction's novelty or
security contribution.

---

## 3. Security Model

### 3.1 Assumptions

CAGOULE's security rests on the following assumptions, all of which must hold for the system to be secure:

1. **Password strength**: the security of the entire system reduces to the entropy of the user-supplied password after Argon2id. A weak password nullifies all other protections.

2. **Attacker has no access to key material in memory**: CAGOULE does not defend against an attacker who can read process memory at encryption time.

3. **Attacker cannot observe timing below the granularity of a Python function call**: the C-layer arithmetic is constant-time (see section 7), but the Python wrapper is not.

4. **The underlying standardized primitives are secure**: if ChaCha20-Poly1305, Argon2id, or HKDF-SHA256 are broken, CAGOULE provides no additional protection.

5. **The random number generator is secure**: Argon2id salts and ChaCha20 nonces are generated via `os.urandom()`. Any RNG compromise breaks freshness guarantees.

6. **CTR nonce uniqueness** (v3.0.1+): the CTR IV is derived from `k_master`
   and the per-message ChaCha20 nonce via HKDF (`IV = HKDF(k_master,
   b'CAGOULE_CTR_V31' + nonce, 8)`), **not** from the salt alone (see
   CAGOULE-2026-001 above — the salt-based formula was the vulnerability).
   Each `encrypt()` call generates a fresh random 96-bit nonce, guaranteeing
   IV uniqueness independent of whether `params`/salt is shared across calls.

### 3.2 Security Goals

| Goal | Mechanism | Status |
|---|---|---|
| Confidentiality | ChaCha20 encryption of algebraically-transformed plaintext | ✅ Provided |
| Integrity and authenticity | Poly1305 authentication tag (16 bytes) | ✅ Provided |
| Wrong-password detection | AEAD tag verification before plaintext is returned | ✅ Provided |
| Nonce uniqueness | 96-bit random nonce per `encrypt()` call | ✅ Provided |
| Salt uniqueness | 256-bit random salt per `encrypt()` call | ✅ Provided |
| CTR IV uniqueness | HKDF-derived from k_master + per-message nonce (v3.0.1+; salt-based formula in v3.0.0 was CAGOULE-2026-001) | ✅ Provided |
| Forward secrecy | ❌ Not provided — same password re-derives same material |
| Key rotation | ❌ Not built in — application responsibility |

---

## 4. Threat Model — What CAGOULE Protects Against

### 4.1 Passive attacker with ciphertext access

An attacker who can read CGL1-format ciphertexts but does not know the password gains:

- **Nothing about the plaintext**: ChaCha20 stream cipher provides IND-CPA security; the algebraic layer adds diffusion before AEAD encryption.
- **Nothing about the key material**: `k_master`, round keys, Mersenne prime index, `z_offset`, and CTR IV are all derived via HKDF from an Argon2id-hardened password. Brute-forcing the password is the only viable attack path.
- **No field structure information**: the Mersenne prime index is determined by `HKDF(k_master, "CAGOULE_PRIME_SEL_V25")[0] % 8` — unknown to the attacker, preventing field-specific precomputation.
- **No keystream reuse**: CTR mode uses a unique IV derived from `k_master` combined with a random salt per encryption. Keystream blocks are never reused across messages.

### 4.2 DDT precomputation attacks on the algebraic layer

A classical differential cryptanalysis approach requires building the Difference Distribution Table (DDT) of the Vandermonde matrix over a known field Z/pZ. CAGOULE counters this with two complementary mechanisms:

- **Mersenne prime pool** (v2.5.x): the attacker cannot know which of the 8 primes is in use without the password. Precomputing DDTs for all 8 fields simultaneously multiplies the attacker's work by 8.
- **Z-Domain Shifting** (v2.5.x): `z_offset[16]` is derived from `k_master` and applied as byte-level whitening before the algebraic layer. Even with the correct field, the attacker does not know the starting point of the algebraic transformation. This is functionally equivalent to DES-X key whitening.

### 4.3 Ciphertext forgery

The Poly1305 authentication tag prevents any attacker from producing a valid ciphertext for a message they did not encrypt. Any bitflip in the ciphertext or header produces a tag mismatch. CAGOULE rejects forged ciphertexts before decrypting, so no plaintext oracle is available.

### 4.4 Replay attacks at the application level

Each `encrypt()` call generates an independent 256-bit salt and 96-bit nonce. Two encryptions of the same plaintext with the same password produce different ciphertexts. Note: CAGOULE does not implement sequence numbers or replay detection — this is the application's responsibility.

### 4.5 Brute-force attacks on the password

Argon2id with `t=3, m=64MB, p=1` requires approximately 114ms and 64MB of RAM per attempt on the target hardware. This makes GPU/ASIC password cracking expensive. An attacker with a 10,000-GPU cluster would need:

- ~1.14 ms per attempt per GPU (amortized, highly optimized)
- Against a 72-bit entropy password: > 2⁷² / (10⁴ × ~876 attempts/s) ≈ astronomical time

Weak passwords (dictionary words, short PINs) remain vulnerable regardless of Argon2id parameters.

### 4.6 Chunk reordering and replay in the streaming API (`cagoule_stream.c`, v3.1.0)

The streaming API (C-API only, see §6.8) binds each chunk to its position
in the sequence via two independent mechanisms, both verified by dedicated
test coverage added in this audit pass (`tests/test_stream.c`, Suite 5):

- **Per-chunk MAC key**: `HKDF(k_master, "CAGOULE_CHUNK" || chunk_index, 32)`.
  A tag computed for chunk N cannot be replayed as a valid tag for any
  other chunk index — the key itself is different.
- **Sequential chunk-index enforcement**: the decrypting context tracks its
  own expected `chunk_idx` internally and rejects any chunk whose embedded
  index does not match, before any plaintext is written to the output
  buffer. Presenting chunks out of order — including replaying an
  already-consumed chunk, or skipping ahead — is rejected with
  `CAGOULE_STREAM_ERR_*`, not silently accepted.
- **Session binding via AAD**: `MAGIC || VERSION || session_salt ||
  chunk_idx` is authenticated as associated data on the default
  (ChaCha20-Poly1305) mode, binding each chunk to the specific streaming
  session it belongs to — a chunk from one session cannot be spliced into
  another, even if both sessions share a password.

This does **not** provide out-of-order *decryption* (chunks must be
consumed in the order they were produced) — that is a design choice
(roadmap §5.2, RAM-bounded streaming), not a gap. Applications needing
random access to individual chunks must build that on top of this API.

---

## 5. Out of Scope — What CAGOULE Does NOT Protect Against

### 5.1 Compromised endpoint

If the attacker controls the machine running CAGOULE (keylogger, memory dump, process injection), all security guarantees are void. CAGOULE does not implement secure enclaves or TEE protection.

### 5.2 Side-channel attacks via Python layer

The Python wrapper (`cipher.py`, `decipher.py`, `cipher_ctr.py`, `decipher_ctr.py`, `params.py`) is **not constant-time**. Python object construction, ctypes dispatch, and AEAD operations have data-dependent timing at the microsecond scale. An attacker capable of sub-millisecond timing measurements on the Python API may extract information. The C algebraic layer is constant-time (see section 7), but this protection does not extend to the full API.

### 5.3 Key management

CAGOULE encrypts and decrypts data. It does not:
- Store, rotate, or revoke keys
- Implement key agreement protocols
- Provide multi-party encryption
- Support key derivation from hardware tokens

Key management is entirely the application's responsibility.

### 5.4 Metadata

CGL1 format reveals:
- The ciphertext **length** (and therefore approximate plaintext length; for CTR v0x02/RAW v0x03: exact plaintext length since there is no padding)
- The **version byte** (`0x01` CBC, `0x02` CTR/AEAD, `0x03` CTR/RAW — experimental)
- The **magic** (`CGL1`)
- That the data was encrypted with CAGOULE
- **Whether multiple ciphertexts share a key — but this differs by API, see 5.5.**

Traffic analysis, timing of encryption operations, and ciphertext length analysis are not protected.

### 5.5 Bulk encryption: Python and C give OPPOSITE linkability/recovery tradeoffs

This is not a bug in either implementation — it is a real, currently
undocumented-until-now divergence between the two bulk APIs. Anyone
choosing between them should understand which property they are getting.

**Python (`encrypt_bulk_ctr(messages, password, params=shared)`):**
When `params` is shared, every message's header carries `params.salt`
**unchanged** — the real Argon2id derivation salt, identical across the
whole batch. Consequence:
- ❌ Ciphertexts in a batch are **linkable**: an observer can tell they
  share a key, just by comparing header salts.
- ✅ Password-only recovery works: `decrypt_ctr(ct, password)` alone
  (no `params` object needed) correctly re-derives `k_master` from
  `(password, header_salt)`, because the header salt IS the real salt.
- CTR keystream uniqueness (not salt) comes from a fresh 96-bit nonce
  per message — this remains safe regardless of salt reuse.

**C (`cagoule_encrypt_with_handle()` / `cagoule_encrypt_with_handle_raw()`):**
Every message's header carries a **fresh, random `msg_salt`**, unrelated to
the real Argon2id salt used to derive the handle's `k_master`. Consequence:
- ✅ Ciphertexts in a batch are **not linkable** — no way to tell from the
  headers alone that two ciphertexts share a key.
- ❌ Password-only recovery does **not** work: `decrypt_ctr(ct, password)`
  without the original handle/salt will re-derive the *wrong* `k_master`
  from `(password, header_salt)` and fail authentication (safely — this
  fails hard with an auth error, never silent corruption, since both
  VERSION 0x02 and 0x03 are authenticated constructions). You must retain
  the original derivation salt (or keep the live `CagouleKeyHandle`/
  `CagouleParams` in memory) to decrypt C-bulk ciphertexts.

**If your threat model requires both properties simultaneously (unlinkable
AND password-only-recoverable), neither current bulk API provides it.**
Pick based on which property matters more for your use case, or store the
salt out-of-band yourself alongside the ciphertext if you need C's
unlinkability plus recoverability (at that point you've reintroduced
linkability via your own storage, but at least not via the ciphertext
itself).

### 5.6 Forward secrecy

Re-encrypting data with the same password re-derives the same `k_master`, Mersenne prime, and `z_offset`. An attacker who obtains the password retroactively can decrypt all past ciphertexts encrypted with that password. CAGOULE provides no forward secrecy.

### 5.7 Formal cryptanalysis

The CAGOULE algebraic layer (Vandermonde diffusion, Feistel S-box, ζ(2n) round keys) has **not undergone formal peer review or public cryptanalysis**. No proof of security beyond the informal design arguments in ARCHITECTURE.md exists. Users requiring provably secure constructions should use AES-GCM or XChaCha20-Poly1305.

---

## 6. Known Limitations

### 6.1 Performance vs. standard primitives

**Updated in this audit pass (v3.1.0, post AVX2 lazy-reduction fix).** Earlier
figures in this file (~6.9 MB/s CBC, ~19.7 MB/s CTR, ~80–135× slower than
AES-GCM) were measured before a root-cause fix to the AVX2 CTR matrix
multiply and should be treated as superseded, not current.

**What changed:** the AVX2 matrix multiply used in the CTR pipeline was
doing a full modular reduction after every multiply-accumulate (256
reductions per 16×16 block) instead of accumulating raw products and
reducing once (16 reductions per block) — the same deferred-reduction
strategy the scalar path already used. A new function,
`cagoule_matrix_mul_avx2_lazy`, applies this to the CTR-only path (CBC
cannot use it — see the safety note in `cagoule_matrix_avx2.c`, byte-range
input is a hard precondition, enforced by a debug `assert()` per finding
P2-6). Before the fix, AVX2 was measurably *slower* than the scalar
fallback on the hardware used for this pass; after the fix it is faster
than the pre-fix baseline by roughly 1.7–2.5×, depending on the run.

**Measured throughput (final numbers, this pass, single-machine, 1 MB payload):**

| Path | Before this fix | After this fix |
|---|---|---|
| CTR (AVX2, production config — Z-Domain Shifting active) | ~20–31 MB/s | **50.5 MB/s** |
| CTR (AVX2, best-case single run) | ~20–31 MB/s | **52.8 MB/s** |
| CBC (unchanged, not in scope for this fix) | ~7–9 MB/s | ~7–9 MB/s (unchanged) |

The 50.5 vs 52.8 MB/s gap itself is informative: the C benchmark (`bench_ctr()`
in `test_ctr.c`) originally measured throughput with Z-Domain Shifting
disabled (`NULL, 0` passed for `z_offset`), which is not what any real caller
does — Python's `cipher_ctr.py::encrypt_ctr` and the C `cagoule_api.c` layer
both always pass a real, derived `z_offset`. That benchmark has since been
corrected to match production usage; 50.5 MB/s is the honest, apples-to-apples
number, and 52.8 MB/s is retained here only to show the small (~9%), real,
expected cost of Z-Domain Shifting itself — not a discrepancy to chase further.

**Methodology caveat, stated plainly rather than omitted:** these numbers
were measured on a single-vCPU virtualized sandbox with no CPU pinning
(`taskset`) and no CPU-governor control available from inside the guest —
both of which the project's own benchmark methodology (see `make
benchmark`, documented in the Makefile itself) calls for. Repeated runs of
the *same* build on this hardware varied by as much as 2× across the
session. Treat the figures above as a snapshot from one measurement pass,
not as precise, reproducible absolute figures guaranteed on other hardware.
Before citing a specific number in a paper or release notes, re-measure on
dedicated, pinned hardware using `make benchmark` and report the
methodology alongside the number.

**Comparison to AES-256-GCM:** on this same machine (`openssl speed -evp
aes-256-gcm`), OpenSSL's hardware-accelerated (AES-NI) implementation
measured ~11,975 MB/s at a 1 MB block size — roughly **220–240× faster**
than CAGOULE's current CTR throughput. This is a same-machine, same-session
comparison (methodologically fair), but AES-NI throughput varies
significantly across CPU generations, so this ratio should not be assumed
to hold on other hardware. CAGOULE is a software-only construction by
design (see §5, "Out of Scope" — no AES-NI, no GPU); this gap is a known,
accepted research trade-off, not a regression to fix.

### 6.1a Correctness verification of the AVX2 lazy-reduction fix

Because deferred/lazy modular reduction is exactly the bug class that
produced a prior real vulnerability in this codebase (the CBC two-time-pad,
via the *scalar* lazy path being misapplied to full-field-element inputs),
the AVX2 lazy variant added in this pass was verified independently of the
implementation work, not just exercised by the existing test suite:

- Full regression suite (`make tests`, all 16 binaries): pass, 468,857+
  C assertions, no regressions in CBC (which is untouched — confirmed by
  grep of every call site before and after the change).
- A dedicated adversarial fuzz harness (not part of the shipped test
  binaries — see audit notes) ran 1,600,008 trials biased toward the exact
  carry-overflow conditions the new accumulator logic has to handle
  correctly (matrix entries near `p-1`, byte values near 255, plus the
  literal worst case of all-`p-1` / all-255 inputs), across all 8
  production Mersenne primes: 0 mismatches against the always-correct,
  fully-reducing reference implementation.
- The function is scoped to `k_mersenne > 0` only, with a safe fallback to
  the original (correct, slower) implementation for the non-Mersenne
  (Barrett, test-only) case — no new code path was written for a case that
  isn't exercised by production keys.

### 6.1b Python end-to-end throughput and the stale-library incident

Python's end-to-end CTR throughput (`cipher_ctr.py::encrypt_ctr`, full
pipeline including KDF-excluded per-message cost) measures **26–32 MB/s**
in this pass — a wide-looking range that is fully explained by the same
single-vCPU VM variance documented in §6.1, not by anything Python-specific.

This range was reached only after finding and fixing a real, separate bug:
`_binding.py::_find_lib()` checked a copy of `libcagoule.so` sitting
directly in the `cagoule/` package directory *before* the actual build
directory (`cagoule/c/libcagoule.so`). A stale copy — predating this
pass's AVX2 lazy-reduction fix — existed at that first path. Python was
silently loading it for the entire investigation, while every C benchmark
in this document correctly linked against the fresh build. The result was
an apparent ~3.6× Python-vs-C gap that had nothing to do with Python,
ctypes, or the AEAD library call.

Directly measured, not assumed: ctypes argument-marshaling overhead is
**under 1%** of per-message cost, and the `cryptography` library's
ChaCha20-Poly1305 call is under 1% as well. Neither is a meaningful
bottleneck — the earlier README claim of "~28% ctypes overhead" that
motivated the original unified-C-API work (`cagoule_api.c`) does not hold
up under direct measurement and should not be cited as a reason to prefer
that API for throughput. Wiring the CTR pipeline through `cagoule_api.c`
instead of the per-primitive path was evaluated and explicitly not done
in this pass, since the evidence showed it would not move the needle.

**Fix applied:** `_find_lib()` now detects when multiple candidate library
paths exist with *different* content (via direct byte comparison, not just
an mtime check), emits a `RuntimeWarning` naming both paths with their
mtimes and sizes, and loads the newer one automatically instead of
silently preferring path order. Identical copies (the common, healthy
case) produce no warning and no behavior change. Verified against all
three real scenarios (single candidate, identical candidates, genuinely
divergent candidates) — not just written and assumed correct.

### 6.2 Version compatibility

- v2.5.x is **not compatible** with v2.4.x ciphertexts (Mersenne prime pool changed the field Z/pZ).
- v3.0.0 introduces CTR mode (CGL1 v0x02). CBC ciphertexts (v0x01) from v2.5.x remain decryptable in v3.0.0 via automatic VERSION dispatch.
- CTR and CBC ciphertexts are **not interchangeable** — `decrypt()` dispatches automatically based on the VERSION byte.
- A migration utility is provided: `migrate_cbc_to_ctr(ciphertext_cbc, password)`.

### 6.3 Platform support

The AVX2 backend (`mulmod_mersenne64x4`, `cagoule_matrix_avx2`, `cagoule_sbox_avx2`) targets x86-64 with GCC on Linux. As of v3.1.0, an ARM NEON backend (`cagoule_matrix_neon.c`) provides a 2-lane vectorized matrix multiply for AArch64 targets (Apple Silicon, AWS Graviton 2/3, Raspberry Pi 4/5), compiled automatically when `__ARM_NEON` is defined, using the same runtime dispatch mechanism as AVX2. The NEON path has **not** been execution-tested on real ARM hardware in this audit pass — it was cross-compiled and reviewed by hand-tracing the row/lane index mapping against the AVX2 reference layout, but no test binary has actually run on ARM. Treat it as implemented-but-unverified-on-target, not as validated to the same standard as the x86-64 AVX2/scalar paths. Windows is not supported. Python fallbacks are available on any platform but are significantly slower.

### 6.4 ~~Memory allocation in C hot path~~ (RESOLVED in v2.5.4)

~~When Z-Domain Shifting is active, `cagoule_cbc_encrypt` performs a `malloc` for the shifted buffer.~~

**Resolved in v2.5.4**: The malloc was eliminated. Z-Domain Shifting is now applied inline using a stack-allocated `zo_byte[16]` array. No heap allocation occurs in the encryption hot path. This applies to both CBC and CTR modes.

### 6.5 ~~The `malloc` hot-path failure mode~~ (RESOLVED in v2.5.4)

**Resolved**: Since the malloc was eliminated in v2.5.4, this failure mode no longer exists.

### 6.6 2-round Feistel algebraic degree

The S-box uses a 2-round Feistel network with degree-1 round functions. The overall algebraic degree is limited. A 3-round variant is under consideration for future releases to increase the security margin.

---

### 6.7 AAD does not include the nonce

The AEAD authenticated additional data in CGL1 v0x02 is:

```
AAD = MAGIC(4) || VERSION(1) || SALT(32)
```

The ChaCha20-Poly1305 nonce (12 bytes, offset 37-48 in the CGL1 header) is **not**
included in the AAD. It IS included as the ChaCha20-Poly1305 nonce input itself,
so modifying the header nonce bits changes the AEAD keystream and causes
tag verification to fail. This provides incidental authentication of the nonce.

However, this protection relies on the nonce being the AEAD nonce — a property
that does not hold in the streaming chunk-index scheme (v3.1.0 `cagoule_stream.c`,
Feature 4) or in future wire formats where the nonce may be carried separately.

**Mitigation**: In v0x02 (ChaCha20-Poly1305), nonce modification is detected
by AEAD tag failure. In v0x03 (Poly1305-only, experimental), the AAD already
includes `MAGIC || VERSION || SALT` and the VERSION byte prevents cross-mode
confusion.

**Plan**: Add nonce to AAD in v3.2.0:
AAD = MAGIC(4) || VERSION(1) || SALT(32) || NONCE(12)
This will be a wire-format-breaking change and will ship with a VERSION byte bump.

### 6.8 C/Python cross-language compatibility (v3.1.0 C wrapper)

The v3.1.0 C wrapper (`cagoule_derive_key()`, `cagoule_encrypt_with_handle()`,
`cagoule_encrypt_with_handle_raw()` in `cagoule_api.c`) independently
re-derives all key material from `(password, salt)` in C, rather than
receiving pre-derived parameters from Python. Two real divergences between
the C and Python derivation paths were found and fixed in this release:

- The S-box round-key derivation (`delta → rk0/rk1`) used a different
  modular-reduction formula in C than in Python's `derive()`, producing a
  different S-box — and therefore incompatible ciphertexts — for the same
  `k_master`. Fixed to match `derive()` (the path with 40+ existing call
  sites and all committed KATs; the divergent path, `_reconstruct()`, has
  zero callers in the codebase and was fixed to match for consistency, not
  because anything depends on it).
- VERSION 0x03 (RAW)'s CTR IV derivation in C truncated the 32-byte
  per-message salt to 12 bytes before mixing it into the IV's HKDF input
  (an artifact of reusing the AEAD path's 12-byte nonce buffer). Python
  uses the full 32 bytes. This alone was sufficient to make every C-RAW
  ciphertext undecryptable by Python's RAW decoder and vice versa, even
  after the S-box fix above. Fixed with a dedicated RAW-mode IV derivation
  using the full salt.

With both fixed, a ciphertext encrypted by the C handle API using RAW mode
(0x03) round-trips correctly through Python's `decrypt_ctr_raw()` given the
same `(password, salt)`, and vice versa — verified by direct cross-language
test, not just matching intermediate parameters.

**What remains asymmetric by design, not by bug**: the AEAD (0x02) and RAW
(0x03) *bulk* APIs still have opposite salt-handling behavior between C and
Python — see section 5.5. That is a deliberate linkability/recoverability
tradeoff, not something this fix addresses.


## 7. Side-Channel Considerations

### 7.1 Constant-time operations in the C layer

The following operations in `libcagoule.so` are implemented without data-dependent branching:

| Operation | Mechanism | File |
|---|---|---|
| `mulmod_mersenne64x4` | Bitmask reduction, no `DIV`, no `if` on data | `cagoule_math_avx2.h` |
| `addmod64x4` / `submod64x4` | Masked conditional subtract via `_mm256_cmpgt_epi64` + XOR flip | `cagoule_math_avx2.h` |
| CTR keystream generation | Same primitives as CBC, no inter-block branches | `cagoule_ctr.c` |
| Poly1305 tag comparison | `secrets.compare_digest()` in Python | `decipher.py`, `decipher_ctr.py` |
| `mulmod64` (scalar) | No branch on operands | `cagoule_math.c` |

Unsigned comparison in AVX2 is implemented via MSB flip (`XOR 0x8000000000000000`), since `_mm256_cmpgt_epi64` is signed-only:

```c
// Constant-time unsigned a > b detection:
__m256i flip = _mm256_set1_epi64x(0x8000000000000000ULL);
__m256i gt   = _mm256_cmpgt_epi64(
    _mm256_xor_si256(a, flip),
    _mm256_xor_si256(b, flip));
// gt = 0xFF..FF if a > b (unsigned), 0x00..00 otherwise — no branch
```

### 7.2 Operations that are NOT constant-time

- **Argon2id**: memory-hard by design; timing is proportional to `m_cost`. Not a leak of plaintext.
- **PKCS7 unpadding** (CBC only): Python-level byte inspection. Not a padding oracle in isolation, but do not expose error messages that distinguish "bad padding" from "bad tag". CTR mode has no padding, eliminating this concern.
- **Python wrapper**: all Python-level code. Data-dependent timing at microsecond scale.
- **`omega.py` (ζ computation)**: `mpmath` fallback is not constant-time. The C backend (`cagoule_omega_generate_round_keys` via OpenSSL HKDF) is deterministic and cache-friendly.
- **Cycle-walking** in S-box: probability < 2^-54 for Mersenne primes. Statistically undetectable.

### 7.3 Valgrind status

As of the v3.0.0 release, 12 C test binaries (including CTR) passed Valgrind with zero memory errors and zero leaks. Valgrind does not detect timing side-channels — it verifies memory safety only.

**Note (this audit pass):** the test suite has since grown to 16 binaries — `test_params_kat`, `test_stream`, and `test_error_paths` were added or substantially extended in this pass (see §6.1a, §6.1b, and ARCHITECTURE.md's Test Coverage table for current per-binary assertion counts). Valgrind was not available in the environment used for this pass, so none of the new/extended binaries have been Valgrind-verified; they have been verified for functional correctness (all pass, 0 failures) but not for memory safety under Valgrind. Re-run `make valgrind` on a machine with Valgrind installed before treating the "zero errors" claim as covering the current 16-binary suite.

### 7.4 Fuzzing status

The libFuzzer harness has been exercised for 1,000,000 runs on both CBC and CTR code paths with AddressSanitizer and UndefinedBehaviorSanitizer enabled. Zero crashes detected.

---

## 8. Key Material Lifecycle

```
password  ──►  Argon2id  ──►  k_master (64 bytes)
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
  HKDF(k_master)              HKDF(k_master)              HKDF(k_master)
  "CAGOULE_ENC"               "CAGOULE_DELTA"             "CAGOULE_Z_SHIFT_V25"
        │                           │                           │
  k_stream (32B)               rk0, rk1 (S-box)            z_offset[16]
  (ChaCha20 key)                                           (Z-Domain Shift)
        │
  HKDF(k_master)
  "CAGOULE_CTR_V31"     ← v3.1.0
        │
  IV_CTR (8 bytes)

ZEROIZATION
  CagouleParams.zeroize()  →  secure_zeroize(k_master, round_keys, z_offset)
  Context manager (__exit__)  →  automatic zeroize on scope exit
  Destructor (__del__)  →  GC fallback (not reliable — use context manager)
```

**Rules for deployers:**

- Always use `with CagouleParams.derive(password) as p:` to guarantee zeroization.
- Do not cache `CagouleParams` objects beyond their encryption session.
- `encrypt_bulk()` derives per-message params (v3.0.0) and zeroizes at function exit.
- `k_master` is never written to disk or included in the CGL1 ciphertext output.
- The CTR IV is derived from `k_master`, not stored in the ciphertext header.

### 8.1 Error-path zeroization fixes (this audit pass)

Two gaps were found and fixed where the *success* path zeroized sensitive
stack buffers but a nearby *error* path did not — the general pattern this
project already tracks as a recurring risk (see the HKDF stack-cleanse
finding, H3/H5, from the v3.1.0 audit). Neither was independently
exploitable (both are detailed below), but both are now fixed for
consistency with the zeroize-everything discipline this file documents:

- **`cagoule_omega_generate_round_keys`** (`cagoule_omega.c`): on HKDF
  failure inside the per-key derivation loop, the function returned
  immediately without cleansing `key_material` (the Fourier-coefficient
  seed || salt || n) or `rk_bytes` (raw HKDF output, pre-mod-`p`
  reduction) — both left on the stack. Fixed by cleansing on the error
  path too, using `OPENSSL_cleanse` (see §8.2 below for why this replaced
  the pre-existing hand-rolled `volatile` loop). Practical exploitability
  was low: this path only executes if the underlying OpenSSL `HMAC()` call
  itself fails, not on any attacker-reachable input.
- **`cagoule_stream_init_from_salt`** (`cagoule_stream.c`): on
  `cagoule_params_derive` failure, the function called `free(ctx)`
  directly instead of `cagoule_stream_free(ctx)`, skipping the
  `OPENSSL_cleanse` of `ctx->session_salt`. Verified this was not a
  double-free or secret-material leak: `cagoule_params_derive` already
  self-cleans `ctx->params` on every one of its own failure paths (all 8
  return sites checked), and `session_salt` is documented elsewhere in
  this file (§5.4) as non-secret — it's transmitted in the clear as part
  of the wire protocol. The gap was pure inconsistency with the "cleanse
  everything, even non-secrets" convention, not a confidentiality issue.
  Fixed to call `cagoule_stream_free(ctx)`.

### 8.2 Zeroization pattern unified to `OPENSSL_cleanse` (this audit pass)

`cagoule_omega.c` was the one remaining file using hand-rolled `volatile
uint8_t*` zeroing loops instead of `OPENSSL_cleanse`, which every other
file in the C layer (`cagoule_kdf.c`, `cagoule_params.c`,
`cagoule_stream.c`, `cagoule_matrix.c`, `cagoule_api.c`) already uses.
`OPENSSL_cleanse` is more robust against dead-store elimination by
aggressive compiler optimization than a manual `volatile` loop across
compiler versions and flag combinations; unifying on it removes a
per-file inconsistency rather than changing any actual security property
— the `volatile` loops were not proven-broken, just inconsistent with the
project's own stated standard.

---

## 9. Version Compatibility and Breaking Changes

| From | To | Compatible? | Notes |
|---|---|---|---|
| v1.x | v2.x | ❌ No | Feistel S-box replaced x^d — vault incompatibility |
| v2.0–v2.4 | v2.5.x | ❌ No | Mersenne prime pool changed field Z/pZ |
| v2.5.x | v3.0.0 | ✅ Yes* | CBC (v0x01) retained. CTR (v0x02) is new format. |
| v2.5.0 | v2.5.1 | ✅ Yes | AVX2 detection fix only |
| v2.5.1 | v2.5.2 | ✅ Yes | Tests only — no cryptographic change |
| v2.5.2 | v2.5.3 | ✅ Yes | Documentation fixes only |
| v2.5.3 | v2.5.4 | ✅ Yes | Z-Domain malloc eliminated, security hardening |
| v3.0.0 | v3.0.1 | ⚠️ Partial | v0x02 CTR ciphertexts are **incompatible** — IV formula changed (fixes `CAGOULE-2026-001`, a real confidentiality vulnerability, not a cosmetic change). v0x01 CBC unaffected. |
| v3.0.1 | v3.1.0 | ✅ Yes** | v0x02 forward-compatible (IV formula unchanged from v3.0.1). v0x03 is new (opt-in, experimental — see §5.7). Delta-derivation fix (H1/H2, this pass) changed round-key derivation for a subset of `(password, salt)` inputs — see the Breaking Changes note in `CHANGELOG.md`'s v3.1.0 entry for the exact scope. |

*CBC ciphertexts (v0x01) from v2.5.x decrypt correctly in v3.0.0 via automatic VERSION dispatch.
CTR ciphertexts (v0x02) are new in v3.0.0 and cannot be decrypted by earlier versions.
Use `migrate_cbc_to_ctr()` to convert CBC ciphertexts to CTR format.

**v3.0.0 → v3.0.1: this is the one non-trivial break in this table that
isn't just "new format" — existing v3.0.0 CTR ciphertexts must be
re-encrypted, not just re-read, after upgrading. See the advisory at the
top of this document.

The CGL1 wire format (`MAGIC | VERSION | SALT | NONCE | CT | TAG` for
v0x01/v0x02; `MAGIC | VERSION | SALT | CT | TAG`, no NONCE, for v0x03) is
stable. VERSION 0x01 = CBC, VERSION 0x02 = CTR (default), VERSION 0x03 =
CTR without the ChaCha20 layer (experimental, opt-in only, v3.1.0+).
Breaking changes will increment the minor version and will be announced
with migration guidance.

---

## 10. Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately to:

**Slim Issa** — [github.com/slimissa](https://github.com/slimissa)

Please include in your report:

- CAGOULE version affected
- A description of the vulnerability and its security impact
- Steps to reproduce or a proof-of-concept (if applicable)
- Whether you believe the vulnerability is in the algebraic layer, the standardized primitives, the CTR mode, or the Python wrapper

Expected response time: **72 hours**.

### Scope of accepted reports

| Category | In scope |
|---|---|
| Incorrect constant-time implementation in `mulmod_mersenne64x4` or comparison functions | ✅ |
| Memory safety bugs in `libcagoule.so` (buffer overflow, use-after-free) | ✅ |
| Authentication bypass or tag forgery | ✅ |
| Wrong-password acceptance | ✅ |
| Nonce, salt, or CTR IV reuse | ✅ |
| Key material leakage into ciphertext or logs | ✅ |
| Algebraic weaknesses in the Vandermonde / Feistel construction | ✅ |
| CTR keystream prediction or reuse | ✅ (v3.0.0) |
| Slower-than-expected performance | ❌ — not a security issue |
| Incompatibility with non-Linux platforms | ❌ — known limitation |
| Python wrapper timing side-channels | ⚠️ Accepted but lower priority — documented limitation |

---

## Appendix — Quick Security Reference

```
✅ CAGOULE v3.1.0 provides:
   Confidentiality    — ChaCha20 + algebraic diffusion layer (CBC or CTR)
   Integrity          — Poly1305 authentication tag (16 bytes)
   Wrong-password     — AEAD tag check before plaintext return
   Nonce freshness    — 96-bit os.urandom() per encrypt()
   KDF hardening      — Argon2id t=3, m=64MB (OWASP-compliant)
   Field diversity    — 8 Mersenne-64 primes, HKDF-selected
   Whitening          — z_offset[16] byte-level key whitening
   CTR mode           — No padding, streaming-friendly, 4-block SIMD pipeline
   CBC→CTR migration  — migrate_cbc_to_ctr() utility
   Auto-dispatch      — decrypt() handles both v0x01 (CBC) and v0x02 (CTR)

❌ CAGOULE does NOT provide:
   Forward secrecy
   Key management / rotation / revocation
   Protection against compromised endpoints
   Constant-time Python API
   Formal security proof of the algebraic layer
   ARM / Apple Silicon / Windows support
   Metadata concealment (ciphertext length visible)
```

---

*CAGOULE — Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée*
*Slim Issa — Kairouan, Tunisia — Part of the QuantOS platform*
*License: MIT*
