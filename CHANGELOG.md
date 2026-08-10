# CAGOULE Changelog

---

## v3.1.0 — Feature Release + Post-Release Audit (2026-07-16)

v3.1.0 adds the unified C API (`cagoule_api.c`), the streaming API with
per-chunk MAC (`cagoule_stream.c`), the ARM NEON backend, and the
experimental Poly1305-only mode (v0x03). This entry also folds in an
audit pass performed against the tagged v3.1.0 codebase — the fixes,
performance work, and new tests below were verified against this
version, not released separately.

**16 C test binaries, 468,857+ assertions. 722 Python tests, 12 skipped, 0 fail.**

### Security fixes

Findings below are cited by the ID used in their own code comments
(`audit round 2, <ID>`), so anyone reading the corresponding fix in the
source can cross-reference this entry. This list reflects only findings
with verifiable fixes in the code — see the note at the end of this
section on scope.

**C2 (Critical) — Poly1305 key reuse across messages in RAW mode (v0x03)**

`poly_key` was derived once per `CagouleDerivedParams` (shared across
every message under a handle) instead of per-message. Any two RAW-mode
messages encrypted under the same handle shared a Poly1305 key, enabling
cross-message tag forgery. Fixed by binding `poly_key` to each message's
own salt, derived fresh per call. This is also the specific advisory
tracked as `CAGOULE-2026-003` in `SECURITY.md`. Regression test:
`test_api_raw.c` Suite 3 (added as part of finding N4, below), which
captures a tag from one message and confirms it cannot authenticate a
different message under the same handle.

**H1 / H2 — delta derivation formula diverged between C and Python**

`cagoule_params.c`'s delta-to-round-key formula used `delta %= p` (can
be 0), while `params.py::derive()` used `delta = (raw_delta % (p-1)) + 1`
(always in `[1, p-1]`). These produced different round keys for
identical `(password, salt)` inputs — a genuine C/Python interop break,
not just a style inconsistency. Fixed by aligning the C formula to match
Python's (Option B in both fix comments). **This is the breaking change
noted below:** ciphertexts produced by a pre-fix C build are not
guaranteed to decrypt correctly against a post-fix Python installation
using the same password, or vice versa, for the small fraction of
derivations where the two formulas previously disagreed.

**H3 — HKDF intermediate buffers not cleansed on any exit path**

`cagoule_kdf.c`'s `hkdf_sha256`: `t_prev`, `buf`, `t_cur` (HMAC
intermediate output, equivalent to keystream material) were never
zeroized before return on any path. Fixed via a single `done` label
covering success, HMAC-error, and normal-loop exits.

**H5 — companion HKDF stack-cleanse gap in `cagoule_omega.c`**

Same defect class as H3, found separately in
`cagoule_omega_generate_round_keys`: sensitive buffers were cleansed on
the success path but not on the HKDF-failure error path. Fixed by
cleansing `key_material`/`rk_bytes` on the error path too, using
`OPENSSL_cleanse` (this also closed a related consistency gap — this
file was the last one in the codebase still using a hand-rolled
`volatile` zeroize loop instead of `OPENSSL_cleanse`; unified to match
every other file).

**M2 — plaintext left in `out` buffer on a downstream error path**

`cipher_ctr.py`: an error after plaintext had already been written to
`out` left it there instead of zeroizing before returning the error.

**M4 — buffer-pool reentrancy guard had an unsafe check-then-set ordering**

`_buffer_pool.py`: the original ordering allowed a narrow window where
nested reentrant calls (e.g. a logging handler that itself encrypts)
could observe stale guard state. Fixed by correcting the ordering. (A
related, lower-severity refinement — using a depth counter instead of a
boolean flag to correctly handle 2+ levels of nesting — remains open;
noted in Known Issues below.)

**M5 — CBC Z-shift subtraction relied on an unmasked byte value**

`cagoule_cipher.c`: the unsigned-wraparound subtraction trick needed an
explicit `& 0xFF` mask that was missing in one code path.

**M6 — CBC/CTR/RAW pipelines' wire-format assembly consolidated into `format.py`**

Previously, `cipher.py`, `cipher_ctr.py`, and `cipher_ctr_raw.py` each
inlined their own byte concatenation for the CGL1 header. Consolidated
to call `format.py::serialize_from_aead`/`serialize_raw` instead,
tested against real ciphertexts produced by each pipeline. **Note:**
`format.py`'s own header comment was not updated when this consolidation
happened, and still incorrectly claims "no production caller" — see the
Inline Comments fix below; this changelog entry documents the
consolidation, the comment fix documents correcting the record of it.

**M8 — `secure_zeroize` used `ctypes.c_char * n` where a `bytearray`-backed buffer was needed**

`utils.py`: the original implementation could allocate a temporary
all-zero object rather than zeroing the caller's actual backing memory.

**M9 — RAW-mode (v0x03) IV derivation truncated the message salt, breaking C/Python interop**

`cagoule_api.c`'s RAW-mode call sites reused the AEAD-mode `derive_iv()`
helper (typed for a 12-byte nonce) with a 32-byte message salt as input.
Only the first 12 of 32 salt bytes were used; the remaining 20 were
silently dropped. Verified by direct cross-language test: for the same
`(k_master, salt)`, the C-derived IV and Python-derived IV differed —
every RAW-mode ciphertext produced by `cagoule_encrypt_with_handle_raw`
was undecryptable by `cipher_ctr_raw.py`, and vice versa, even with
identical keys (this was independent of, and in addition to, H1/H2).
Fixed by deriving the RAW-mode IV from the full 32-byte salt.

**N3 — `derive_k_master()`'s `fast_mode` parameter did not reach the Argon2id call on one path**

`params.py`: a code path bypassed the `fast_mode` cost-parameter
selection, always using production Argon2id cost even when a caller
explicitly requested the cheaper test-only parameters.

**N5 — `PROFILE_CTR`-only function called unconditionally outside its guard**

`cagoule_ctr_print_profile()` only exists when compiled with
`-DPROFILE_CTR`, but was called from a code path reachable in the
standard (non-profiling) build, which would fail to link. Fixed by
guarding both the declaration and the call site consistently. This
specific bug class (a function whose existence depends on a compile
flag, called from code that doesn't check for that flag) was
re-encountered and deliberately avoided during this pass's own AVX2
profiling instrumentation work — see the discipline described in §6.1a
of `SECURITY.md`.

**N4 — zero C-level test coverage of the `CagouleKeyHandle` API before this pass**

Before `test_api_raw.c` existed, `cagoule_api.c`'s handle-based path
(`cagoule_derive_key` / `*_with_handle` / `*_with_handle_raw`) had no C
test coverage and no Python test exercised the C handle via ctypes
either. This is exactly the blind spot that let C2 go undetected for a
full audit cycle — two prior review passes checked the Python RAW path
without ever testing the C equivalent. `test_api_raw.c` was written
specifically to close this, and has since been extended twice more in
this pass (all 8 Mersenne primes, zero-length plaintext, buffer
boundary edge cases — 337 → 364 assertions).

**Scope note on this list:** earlier internal tracking referenced
additional finding IDs (H4, M16, N1, N2) that do not correspond to any
fix present in this codebase — grepped exhaustively across all C and
Python source and every project doc before writing this entry, with
zero matches. They are not included above because there is nothing to
verify or cite; if they describe real, separate work, it was not merged
into what's being audited here.

### Performance

The AVX2 CTR matrix multiply was doing a full modular reduction after
every multiply-accumulate (256 reductions per 16×16 block) instead of
accumulating raw products and reducing once (16 reductions per block) —
the same deferred-reduction strategy the scalar path already used.
Fixed via a new, CTR-only function (`cagoule_matrix_mul_avx2_lazy`);
CBC is unaffected and continues using the original function, since the
byte-range-input precondition the fix depends on does not hold for
CBC's full-field-element chaining. Verified via the full regression
suite plus 1.6M+ adversarial fuzz trials (0 mismatches) targeting the
exact carry-overflow conditions the new accumulator logic has to
handle correctly.

| Path | Before | After |
|---|---|---|
| CTR (C, AVX2, production config — Z-shift active) | ~20–31 MB/s | **50.5 MB/s** |
| CTR (C, AVX2, best-case single run) | ~20–31 MB/s | **52.8 MB/s** |
| CTR (C, forced scalar) | — | 45.8 MB/s |
| CTR (Python e2e) | — | 26–32 MB/s |

The C benchmark itself (`bench_ctr()` in `test_ctr.c`) was also corrected
in this pass — it previously measured with Z-Domain Shifting disabled
(`NULL, 0`), which no real caller does. It now matches production usage.
Python e2e throughput required a separate, unrelated fix: `_binding.py`
was loading a stale, pre-fix copy of `libcagoule.so` from the package
directory rather than the current build (see `_find_lib()` hardening,
below, and `SECURITY.md` §6.1b for the full account). See `SECURITY.md`
§6.1 for methodology caveats — these numbers come from a single-vCPU,
unpinned virtualized environment with documented ~2× run-to-run variance.

### New tests

- `test_params_kat.c` (new, 17 assertions) — closes a real gap:
  `cagoule_params_derive` had zero test coverage anywhere, despite
  backing both the unified C API and the streaming API. Cross-checked
  byte-for-byte against the Python reference (`CagouleParams.derive`,
  `fast_mode=False` to match C's real Argon2id parameters) for a fixed
  `(password, salt)`: `k_master`, `p`, `k_mersenne`, `n`, `k_stream`, and
  the complete 64-element `round_keys[]` and 16-element `z_offset[]`
  arrays all matched exactly. That cross-checked result is now a
  permanent, self-contained C KAT — no Python needed to run it going forward.
- `test_stream.c` extended (33 → 76 assertions) — added an exact
  3-chunk session test, dedicated session-salt correctness properties
  (freshness across independent sessions, correct round-trip, and a
  negative control confirming the wrong salt fails to decrypt),
  `init_from_salt`'s positive path with a caller-supplied salt (only
  its error paths were tested before), and edge-case chunk sizes
  (1 byte, 16 bytes, 64 KB).
- `test_api_raw.c` extended (337 → 364 assertions) — round-trip
  coverage across all 8 production Mersenne primes (driven through the
  real, intentionally-opaque `cagoule_derive_key` API — `cagoule_params_derive`
  was used only as an offline salt-search tool to find one salt per
  prime, never to peek inside the opaque handle), zero-length plaintext
  for both AEAD and RAW modes, and buffer-boundary edge cases (exact-fit
  vs. off-by-one on both encrypt and decrypt).
- `test_error_paths.c` (new, 43 assertions) — `cagoule_encrypt_v3`/
  `cagoule_decrypt_v3` had zero coverage anywhere before this file:
  round-trip, wrong password, corrupted ciphertext, three distinct
  truncation cases, bad magic/version bytes, full NULL guards. Also
  closes two asymmetries found by reading the source directly:
  `cagoule_ctr_decrypt` had no NULL-guard tests of its own (only
  `cagoule_ctr_encrypt` did), and `cagoule_cbc_decrypt` only had 2 of 6
  possible NULL-checkable arguments tested.

### Breaking changes

- **Delta derivation unified (C and Python now agree) — see H1/H2
  above.** If you have ciphertexts encrypted with a build predating
  this fix, re-derive and verify decryption still works before relying
  on cross-version compatibility; the two formulas only disagreed for a
  subset of derivations, so most existing ciphertexts are unaffected,
  but this was not exhaustively characterized.
- **`_find_lib()` behavior change:** if two different copies of
  `libcagoule.so` exist on a system (e.g. a stale installed copy
  alongside a fresh build), Python will now load the newer one and emit
  a `RuntimeWarning`, instead of silently preferring the first path
  checked. If your deployment relies on a specific stale copy being
  loaded (unlikely, but possible with a pinned `LIBCAGOULE_PATH` this
  does not affect), verify behavior after upgrading.

### Known issues

- **Python e2e throughput (26–32 MB/s) is environment-dependent.**
  Verified this is genuine single-vCPU VM run-to-run variance (confirmed
  by re-measuring the identical build/data multiple times), not a
  regression or a data-dependent bug — see `SECURITY.md` §6.1/§6.1b.
- **IND-CPA for the algebraic layer remains unproven** — conjectured
  only, per the existing roadmap. Unchanged by this pass.
- **S-box algebraic degree is 1** (2-round Feistel, linear round
  function) — known weakness, v3.2.0 plans a high-round power-map
  redesign. Unchanged by this pass.
- **ARM NEON backend is implemented but not execution-tested** on real
  ARM hardware — cross-compiled and hand-traced for logical
  consistency against the AVX2 reference layout only.
- **`_buffer_pool.py`'s reentrancy guard uses a boolean, not a depth
  counter** — correctly handles single-level reentrancy (the realistic
  case) but not 2+ levels of nested reentrant calls. Not fixed in this
  pass; low real-world likelihood, flagged for follow-up.
- **`cagoule_params_derive` KAT covers one fixed `(password, salt)`
  pair.** `test_params_kat.c` closes the "zero coverage" gap but is not
  a property-based/fuzzed cross-check across many inputs.

---

## v3.0.1 — Security Patch (2026-07-13)

This release closes 10 bugs identified during an independent empirical audit
of v3.0.0 + the v3.1.0 feature branch. All fixes are verified by re-running
the original exploit or test scenario, not just by code inspection.

**713 Python tests pass. 7 C test binaries pass (468,857+ assertions). 0 failures.**

### Critical Fixes

**Bug 2 — CTR two-time-pad via shared `params=` (3 iterations to close)**

Root cause: IV was derived from `k_master` alone — shared `params` meant
shared IV across all messages, enabling keystream reuse. Three fix attempts
were required:
- Attempt 1: dual-path (`msg_salt` for bulk, none for single) — single-message
  path untouched; bulk decrypt side never updated.
- Attempt 2: unified `header_salt` formula — correct on the encrypt side but
  broke the CGL1 invariant: fresh `os.urandom()` written to header ≠ `params.salt`
  that produced `k_master`/`k_stream`, making cross-session decryption impossible.
- **Final fix (this release):** IV bound to the ChaCha20 **nonce** (12 bytes,
  already random per message, already in the CGL1 header):
  `IV = HKDF(k_master, b'CAGOULE_CTR_V30' + nonce, 8)`.
  Header salt = `params.salt` in shared mode, preserving the CGL1 invariant
  `(password, header_salt) → k_master/k_stream` fully reproducible cross-session.
  Added `test_cross_session_roundtrip_no_params_object` — the test that would
  have caught every previous broken fix immediately.

**Bug 6 — Python fallback S-box completely unkeyed for production primes**

`SBoxPython.from_delta` silently used `x³ mod p` (ignoring `delta` entirely)
for all primes ≥ `_LARGE_PRIME_THRESHOLD`. In a pure-Python deployment without
`libcagoule.so`, the nonlinear layer contributed zero key material.
Fix: full port of the 2-round Feistel with cycle-walking, bit-exact against C
across all 8 Mersenne-64 primes × 4 deltas × 500 values (16,000 comparisons,
0 mismatches). Two bugs found during porting: XOR (not addition) for half-block
combination, and correct uint32 masking per the C implementation.

### High Severity Fixes

**Bug 3 — `CagouleParams.__reduce__` leaked `k_master` in plaintext via pickle**

`ProcessPoolExecutor` (recommended in the docstring) pickles arguments through
OS IPC pipes. `k_master` appeared verbatim in the pickle blob. Fix: `__reduce__`
now raises `TypeError` with an explicit explanation and the safe alternative.
Companion fix: `cipher.py` docstring updated to stop recommending `ProcessPoolExecutor`.

**Bug 7 — `Fp2Element.sqrt()` wrong formula + deeper structural finding**

Two formula attempts failed (`(p²+1)//4`, `(p²+p)//4`) because `p ≡ 1 mod 4`
for all production primes. The real finding: `Z/pZ[t]/(t²+t+1)` is only a field
when `p ≡ 2 mod 3`. Two of the 8 production primes (k=189, k=279) are not fields
under this construction — `sqrt()` cannot apply. Fix: Tonelli-Shanks generalized
to `Fp²`, with explicit `ArithmeticError` for non-field primes. Confirmed inert
in production (`mu.py` already avoids those 2 primes via strategy A). Test rewritten
to verify against brute-force ground truth (120/120, 0 mismatches) rather than
silently accepting `ArithmeticError` as a pass.

### Medium Severity Fixes

**Bug 1 — `_buffer_pool.py::_get_rk_arr` missing memset on grow path**

The other 3 pool functions (`_get_padded_buf`, `_get_out_buf`, `_get_input_buf`)
zeroize the old buffer before replacing it on a grow request. `_get_rk_arr` did
not, leaving stale round-key material from a previous (possibly different-password)
operation in the unused tail. Currently inert (C layer only reads `nk` explicit
elements), but inconsistent with the file's own declared security model. Fixed.

**Bug 5 — `omega.py` mpmath gate structurally unreachable**

`mpmath` was imported only inside `if not _OMEGA_C_SYMBOLS_OK` — meaning on any
normal build with `libcagoule.so`, `_mpmath_available` stayed `False` permanently,
silently skipping all 8 `TestBitExactCompatibility` tests. These tests verify C↔Python
bit-exact agreement for ζ(2n) round-key derivation — the one place a real
cross-backend divergence would matter. Fix: unconditional import.

### Low Severity / Code Quality Fixes

**Bug 4 — `migrate_cbc_to_ctr()` zeroizes a copy, not the original**

Not fixable without `decrypt_into(buf)` API (deferred to v3.2.0). `bytes` is
immutable in CPython — any zeroize call on `bytearray(plaintext)` touches a copy.
The docstring now documents this limitation honestly rather than implying secure wipe.

**Bug 8 — `_parse_cgl1` rejected version 0x02 with a generic error**

The function should reject 0x02 (it is the CBC-only parser). The bug was the
quality of the rejection: no indication of what went wrong or where to look.
Fix: explicit message "version CTR received in CBC parser — use `decrypt()` or
`decrypt_ctr()`."

**Bug 9 — `mu.py` dead functions with missing collision avoidance**

`generate_vandermonde_nodes` and `generate_cauchy_beta`: both have zero callers,
both lack the deduplication that `params._derive_nodes` and `matrix.py` implement.
Fix: both now raise `NotImplementedError` with documentation of the bug and
redirection to the correct production functions.

**Bug 10 — `sbox_analysis_report` tested the wrong S-box**

The corrected report tested `x³+cx` on small primes (p < 100), not the production
Feistel construction. Fix: report regenerated against `SBoxC` (real C Feistel).
Added explicit statistical detection floor: 50,000 samples has zero power to detect
biases in the `~2⁻⁶⁴` probability regime that matters cryptographically. IND-CPA
status: NON PROVED — formal analysis required.

### Wire Format Compatibility

v3.0.1 CTR ciphertexts (CGL1 v0x02) are **not compatible** with v3.0.0 CTR
ciphertexts. The IV formula changed (now includes the ChaCha20 nonce). CBC
ciphertexts (CGL1 v0x01) are unaffected.

---

## v3.0.0 — CTR Mode Release (2026-05-28)

Initial public release with CTR mode pipeline, AVX2 4x keystream, CGL1 v0x02
format, auto-dispatch decrypt, and Python CTR layer with C backend + fallback.
