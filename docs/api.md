# CAGOULE C API Reference — `cagoule_api.h`

Reference for the unified C wrapper (`libcagoule.so`). This is a
reference, not a tutorial — see `README.md` for usage examples. All
functions declared in `cagoule_api.h`; implementation in `cagoule_api.c`.

For the *why* behind IV/key derivation choices, cross-message-forgery
history, and the AEAD-vs-RAW security tradeoff, see `SECURITY.md` — this
document only covers the calling contract.

## Two usage patterns

1. **Mono-message** (`cagoule_encrypt_v3` / `cagoule_decrypt_v3`): derive,
   encrypt/decrypt, and discard the key in one call. Simplest, but pays
   the full Argon2id cost (~114 ms default params) per message.
2. **Bulk / handle-based** (`cagoule_derive_key` + `*_with_handle*`):
   derive once, amortize the Argon2id cost across N messages sharing the
   same handle. This is the intended pattern for encrypting many messages
   under one password.

Each pattern has two wire variants: **0x02 (AEAD, default)** —
ChaCha20-Poly1305 outer layer — and **0x03 (RAW, experimental)** —
Poly1305-only, no re-encryption. RAW requires an explicit double gate
(see below) and is not recommended for production use; see `SECURITY.md`
§5.7 for why.

---

## Handle lifecycle

### `cagoule_derive_key`
```c
CagouleKeyHandle* cagoule_derive_key(const uint8_t* password, size_t pwd_len,
                                      const uint8_t* salt, size_t salt_len);
```
Runs the full KDF pipeline (Argon2id → matrix → S-box → round keys →
z_offset → k_stream → poly_key) and returns an opaque handle.

- **Cost**: ~Argon2id(64 MiB, t=3) — the expensive part. Amortize this
  over multiple `*_with_handle*` calls rather than re-deriving per message.
- **Returns**: allocated handle, or `NULL` on KDF failure or invalid
  parameters (e.g. wrong `salt_len`).
- **Thread safety**: safe to call concurrently from multiple threads —
  each call derives an independent handle with no shared mutable state.

### `cagoule_key_handle_free`
```c
void cagoule_key_handle_free(CagouleKeyHandle* handle);
```
Frees the handle and zeroizes `k_master`, `k_stream`, `poly_key`,
`round_keys`, and `z_offset` (`OPENSSL_cleanse`, not a plain `free`).
Safe to call with `handle == NULL` (no-op). Do not call while another
thread is still using the same handle for encrypt/decrypt — the caller
is responsible for that synchronization; freeing is not itself atomic
with respect to in-flight calls on the same handle.

---

## Buffer-sizing helpers

Static inline, header-only — call before allocating `out`:

```c
size_t cagoule_api_encrypt_out_len(size_t pt_len);       // 0x02 encrypt: pt_len + 65
size_t cagoule_api_encrypt_raw_out_len(size_t pt_len);    // 0x03 encrypt: pt_len + 53
size_t cagoule_api_decrypt_out_len(size_t ct_len);        // 0x02 decrypt: ct_len - 65, or 0 if ct_len < 65
size_t cagoule_api_decrypt_raw_out_len(size_t ct_len);    // 0x03 decrypt: ct_len - 53, or 0 if ct_len < 53
```

Overhead breakdown: 0x02 = `MAGIC(4) + VERSION(1) + SALT(32) + NONCE(12) +
TAG(16)` = 65 bytes. 0x03 = `MAGIC(4) + VERSION(1) + SALT(32) + TAG(16)` =
53 bytes (no nonce — RAW mode has no ChaCha20 layer).

---

## Bulk / handle-based functions

### `cagoule_encrypt_with_handle` / `cagoule_decrypt_with_handle` (0x02, default)

```c
int cagoule_encrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* pt, size_t pt_len,
                                 uint8_t* out, size_t* out_len);
int cagoule_decrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* ct, size_t ct_len,
                                 uint8_t* out, size_t* out_len);
```

| Param | Meaning |
|---|---|
| `handle` | From `cagoule_derive_key`. Not consumed — reusable across calls. |
| `pt`/`ct` | Input buffer, caller-owned. |
| `out` | Caller-allocated, capacity ≥ `cagoule_api_encrypt_out_len(pt_len)` (encrypt) or ≥ `cagoule_api_decrypt_out_len(ct_len)` (decrypt). |
| `out_len` | **In**: capacity of `out`. **Out**: bytes actually written. |

**Returns**: `CAGOULE_API_OK` (0) on success, or a negative error code
(see table below). On decrypt failure (`CAGOULE_API_ERR_AUTH` or any
other error), `out` is **never written** — the MAC is verified in an
internal buffer before any plaintext reaches the caller's buffer. No
partial/unauthenticated plaintext is ever exposed.

**Thread safety**: safe to call concurrently on the *same* handle from
multiple threads — each call is a pure function of `(handle, input)` with
its own fresh random nonce/salt (`RAND_bytes` per call) and its own output
buffer; no shared mutable state is touched. OpenSSL's own thread-safety
guarantees apply to the underlying EVP/HMAC calls (OpenSSL ≥ 1.1.0 is
thread-safe by default, no explicit locking callback needed).

### `cagoule_encrypt_with_handle_raw` / `cagoule_decrypt_with_handle_raw` (0x03, experimental)

```c
int cagoule_encrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* pt, size_t pt_len,
                                     uint8_t* out, size_t* out_len);
int cagoule_decrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* ct, size_t ct_len,
                                     uint8_t* out, size_t* out_len);
```

Same parameter/return contract as the 0x02 functions above, plus:

- `allow_experimental`: caller's intent to use RAW mode. This is **not**
  sufficient by itself.
- **Double gate**: RAW mode only activates if `allow_experimental != 0`
  **and** the environment variable `CAGOULE_EXPERIMENTAL_NO_AEAD=1` is set
  at call time (checked via `getenv()` on every call, not cached). If the
  gate is closed, returns `CAGOULE_API_ERR_EXPERIMENTAL_DISABLED` (-8)
  without deriving anything.
- **Thread safety caveat**: `getenv()` is read on every call. Reading it
  concurrently from multiple threads is safe; calling `setenv()`/`putenv()`
  from another thread *while* these functions are executing is not
  guaranteed safe by POSIX in general (a libc-level caveat, not specific
  to CAGOULE) — don't mutate the environment concurrently with live calls.

---

## Mono-message functions

```c
int cagoule_encrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* out, size_t* out_len);
int cagoule_decrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* ct, size_t ct_len,
                        uint8_t* out, size_t* out_len);
```

Derive + encrypt/decrypt + free in one call — always VERSION 0x02
(AEAD). No handle to manage. Bit-for-bit compatible with Python's
`encrypt_ctr()`/`decrypt_ctr()` for the same `(password, salt)` — same IV
formula, no bulk-safe salt handling needed since `k_master` is freshly
derived (and freshly salted) on every call.

**Thread safety**: safe to call concurrently — each call derives its own
independent key material, used once, and discarded internally before
returning.

---

## Error codes

| Code | Value | Meaning |
|---|---|---|
| `CAGOULE_API_OK` | 0 | Success |
| `CAGOULE_API_ERR_NULL` | -1 | A required pointer argument was `NULL` |
| `CAGOULE_API_ERR_SIZE` | -2 | `*out_len` (input capacity) too small |
| `CAGOULE_API_ERR_AUTH` | -3 | MAC/tag verification failed — `out` untouched |
| `CAGOULE_API_ERR_FORMAT` | -4 | Bad `MAGIC` or unrecognized `VERSION` byte |
| `CAGOULE_API_ERR_KDF` | -5 | Argon2id or HKDF derivation failed |
| `CAGOULE_API_ERR_CRYPTO` | -6 | Internal OpenSSL EVP call failed |
| `CAGOULE_API_ERR_ALLOC` | -7 | Internal allocation failed |
| `CAGOULE_API_ERR_EXPERIMENTAL_DISABLED` | -8 | RAW mode requested but the double gate is closed |

All error codes are negative; always check `ret != CAGOULE_API_OK` (or
`ret < 0`) rather than assuming a specific nonzero value means a specific
failure unless you need to distinguish cases from the table above.

---

## Wire format (for reference — not something callers construct by hand)

```
0x02 (AEAD, default):  MAGIC(4) VERSION(1) SALT(32) NONCE(12) CT(n) TAG(16)   — 65 bytes overhead
0x03 (RAW, experimental): MAGIC(4) VERSION(1) SALT(32) CT(n) TAG(16)          — 53 bytes overhead
```

`SALT` is fresh per call (`RAND_bytes`), used to re-derive `k_master` on
decrypt via `cagoule_params_derive` — the handle's password is combined
with this per-message salt, not reused verbatim across messages. See
`SECURITY.md` §5.5 for how this differs from the Python bulk API's
salt-reuse tradeoff (they are deliberately opposite, not a bug).
