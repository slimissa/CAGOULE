"""
test_cross_language_kat.py — Known-Answer cross-language interop tests
CAGOULE v3.1.0

Verifies that a ciphertext produced by Python's production CTR pipeline
(cipher_ctr.py::encrypt_ctr, VERSION 0x02) can be decrypted correctly by
the C unified API (cagoule_api.c::cagoule_decrypt_v3), and vice versa.

Why this matters, concretely: this exact class of bug already happened
once in this codebase. The C and Python delta-derivation formulas
diverged for a subset of (password, salt) inputs (findings H1/H2, fixed
in this audit pass) -- meaning a ciphertext produced by one language's
pipeline was silently undecryptable (or worse, decryptable to the wrong
plaintext) by the other, for affected keys. No automated test caught
this before it was found by manual code reading. This file exists so a
future regression in either direction is caught automatically instead.

Scope (deliberately incremental, not exhaustive): starts with a single
direction (Python encrypt -> C decrypt) for VERSION 0x02 (AEAD, the
default/production mode) only. The reverse direction (C encrypt ->
Python decrypt) and other modes (v0x01 CBC, v0x03 RAW, streaming,
bulk/handle) are real, valuable extensions -- intentionally left for a
follow-up pass rather than attempted all at once here. See the TODO
comments below for exactly what's not yet covered.

Uses cagoule._binding.c_decrypt_v3 / c_encrypt_v3 -- ctypes wrappers
around cagoule_api.c's mono-message API, added specifically to make this
kind of test possible. Production Python code does NOT call these C
functions (see SECURITY.md §6.1b: wiring cagoule_api.c into the
production Python pipeline was evaluated and explicitly not done, since
ctypes overhead was measured at <1% and wiring it would not have
improved throughput). This file uses them purely as an independent,
different-code-path oracle to catch C/Python divergence -- exactly the
role a KAT should play.
"""
import pytest

from cagoule.params import CagouleParams
from cagoule.cipher_ctr import encrypt_ctr


def _c_api_available():
    """True only if the loaded libcagoule.so exports cagoule_encrypt_v3/
    decrypt_v3 -- distinct from CAGOULE_C_AVAILABLE, which only means SOME
    C backend is loaded (an older build might lack these specific
    symbols, added for the unified C API in v3.1.0)."""
    try:
        from cagoule._binding import _HAS_API_V3
        return _HAS_API_V3
    except ImportError:
        return False


requires_c_api_v3 = pytest.mark.skipif(
    not _c_api_available(),
    reason="libcagoule.so does not export cagoule_encrypt_v3/decrypt_v3 (older build?)",
)


# ── Python encrypt_ctr -> C cagoule_decrypt_v3 (0x02, AEAD) ─────────────

@requires_c_api_v3
@pytest.mark.parametrize("message", [
    b"",
    b"a",
    b"short message",
    b"exactly sixteen!",              # 17 bytes, crosses one block boundary
    b"x" * 1024,
    b"\x00" * 64,                     # all-zero plaintext -- not a degenerate case for CTR/AEAD
    bytes(range(256)) * 4,            # 1024 bytes, all byte values represented
])
def test_python_encrypt_c_decrypt_roundtrip(message, c_backend_available):
    """Python encrypt_ctr() output must decrypt correctly via the
    independent C cagoule_decrypt_v3() code path -- a real cross-language
    guarantee, not just a same-language round-trip."""
    from cagoule._binding import c_decrypt_v3

    password = b"cross_language_kat_test_password"
    ciphertext = encrypt_ctr(message, password)

    plaintext = c_decrypt_v3(password, ciphertext)

    assert plaintext == message, (
        f"Cross-language mismatch: Python encrypted {message!r}, "
        f"C decrypted to {plaintext!r} -- this is exactly the class of "
        f"bug the H1/H2 delta-derivation fix addressed. If this fails, "
        f"suspect a NEW divergence between the two derivation paths, "
        f"not a fluke."
    )


@requires_c_api_v3
def test_python_encrypt_c_decrypt_wrong_password_rejected(c_backend_available):
    """A cross-language guarantee that matters as much as the happy path:
    the C decrypt path must reject a Python-produced ciphertext under the
    wrong password, not silently accept it or crash."""
    from cagoule._binding import c_decrypt_v3

    ciphertext = encrypt_ctr(b"secret cross-language payload", b"correct_password")

    with pytest.raises(RuntimeError, match="authentication failed|AUTH"):
        c_decrypt_v3(b"wrong_password", ciphertext)


@requires_c_api_v3
def test_python_encrypt_c_decrypt_many_salts(c_backend_available):
    """Repeats the roundtrip across several independently-derived
    (password, salt) pairs -- each Python encrypt_ctr() call generates a
    fresh random salt internally, so this exercises many distinct
    derived keys/primes, not just one lucky case."""
    from cagoule._binding import c_decrypt_v3

    password = b"many_salts_test_password"
    for i in range(10):
        message = f"message number {i} in the salt sweep".encode()
        ciphertext = encrypt_ctr(message, password)
        plaintext = c_decrypt_v3(password, ciphertext)
        assert plaintext == message, f"mismatch on iteration {i}"


# ── TODO: not yet covered by this file (tracked here, not silently omitted) ──
#
# - C cagoule_encrypt_v3 -> Python decrypt_ctr (the reverse direction).
#   cagoule._binding.c_encrypt_v3 already exists and is tested directly
#   against c_decrypt_v3 (pure-C roundtrip) elsewhere, but not yet
#   cross-checked against decrypt_ctr() specifically in this file.
# - VERSION 0x03 (RAW/experimental) cross-language roundtrip.
# - Bulk/handle API cross-language roundtrip (cagoule_derive_key +
#   cagoule_encrypt_with_handle vs. Python's params= reuse pattern).
# - Streaming API cross-language roundtrip (cagoule_stream.c chunks vs.
#   any future Python streaming consumer -- no Python streaming API
#   exists yet, so this has no Python side to test against currently).
