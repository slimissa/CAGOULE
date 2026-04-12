#!/usr/bin/env python3
"""
run_tests.py — Suite de tests CAGOULE sans dépendance externe.
Usage : python3 run_tests.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

_results = []


def test(name, fn):
    t0 = time.perf_counter()
    try:
        fn()
        _results.append(("PASS", name, time.perf_counter() - t0, None))
    except Exception as e:
        _results.append(("FAIL", name, time.perf_counter() - t0, e))


def eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg} → attendu {b!r}, obtenu {a!r}")


def ok(cond, msg="assertion échouée"):
    if not cond:
        raise AssertionError(msg)


def raises(exc_cls, fn):
    try:
        fn()
    except exc_cls:
        return
    raise AssertionError(f"{exc_cls.__name__} non levée")


# ── Imports ──────────────────────────────────────────────────────────────────
from cagoule.fp2 import Fp2Element
from cagoule.mu import generate_mu, _verify_root_fp2, _verify_root_zp, _mu_in_fp2
from cagoule.sbox import SBox
from cagoule.matrix import DiffusionMatrix
from cagoule.format import (
    parse, serialize, serialize_from_aead, inspect as fmt_inspect,
    is_cgl1, OVERHEAD, MAGIC, SALT_SIZE, NONCE_SIZE, TAG_SIZE,
    CGL1FormatError
)
from cagoule.params import CagouleParams
from cagoule.cipher import encrypt, pkcs7_pad, pkcs7_unpad
from cagoule.decipher import decrypt, CagouleAuthError

# ── Paramètres partagés (fast_mode partout pour cohérence KDF) ────────────────
_PWD = b"password_cagoule_2026"
print("Dérivation des paramètres de test (fast_mode=True)...", flush=True)
_P = CagouleParams.derive(_PWD, fast_mode=True)
print(f"  p={_P.p}  n={_P.n}  µ=strat.{_P.mu.strategy}  sbox={'fallback' if _P.sbox.is_fallback() else 'cubique'}\n")

enc = lambda m: encrypt(m, _PWD, params=_P)
dec = lambda c: decrypt(c, _PWD, fast_mode=True)


# ══════════════════════════════════════════════════════════════════════════════
# FORMAT
# ══════════════════════════════════════════════════════════════════════════════
def _pkt(ct=b"hello"):
    return serialize(bytes(range(SALT_SIZE)), bytes(range(NONCE_SIZE)), ct, bytes(range(TAG_SIZE)))


_raw = _pkt(b"data" * 5)

test("format:magic", lambda: ok(_pkt()[:4] == MAGIC))
test("format:version", lambda: ok(_pkt()[4:5] == b"\x01"))
test("format:taille", lambda: ok(len(_pkt(b"X" * 10)) == OVERHEAD + 10))
test("format:parse_ct", lambda: eq(parse(_raw).ciphertext, b"data" * 5))
test("format:to_bytes", lambda: eq(parse(_raw).to_bytes(), _raw))
test("format:aad_magic", lambda: ok(parse(_raw).aad[:4] == MAGIC))
test("format:is_cgl1_vrai", lambda: ok(is_cgl1(_raw)))
test("format:is_cgl1_faux", lambda: ok(not is_cgl1(b"garbage")))
test("format:is_cgl1_vide", lambda: ok(not is_cgl1(b"")))
test("format:inspect_ct_len", lambda: eq(fmt_inspect(_pkt(b"X" * 10))["ciphertext_len"], 10))
test("format:inspect_overhead", lambda: eq(fmt_inspect(_raw)["overhead"], OVERHEAD))
test("format:from_aead", lambda: eq(
    serialize_from_aead(bytes(SALT_SIZE), bytes(NONCE_SIZE), b"ct" + bytes(TAG_SIZE)),
    serialize(bytes(SALT_SIZE), bytes(NONCE_SIZE), b"ct", bytes(TAG_SIZE))
))
test("format:salt_exc", lambda: raises(CGL1FormatError,
                                       lambda: serialize(b"court", bytes(NONCE_SIZE), b"ct", bytes(TAG_SIZE))))
test("format:magic_exc", lambda: raises(CGL1FormatError,
                                        lambda: parse(b"XXXX" + _raw[4:])))
test("format:court_exc", lambda: raises(CGL1FormatError,
                                        lambda: parse(b"CGL1\x01" + b"\x00" * 10)))


# ══════════════════════════════════════════════════════════════════════════════
# PKCS7
# ══════════════════════════════════════════════════════════════════════════════
for n in [0, 1, 15, 16, 17, 31, 32, 63, 64, 100]:
    test(f"pkcs7:aligne_{n}", lambda n=n: ok(len(pkcs7_pad(b"A" * n, 16)) % 16 == 0))
    test(f"pkcs7:roundtrip_{n}", lambda n=n: eq(pkcs7_unpad(pkcs7_pad(b"X" * n, 16), 16), b"X" * n))

test("pkcs7:pad0_exc", lambda: raises(ValueError, lambda: pkcs7_unpad(b"\x00" * 16, 16)))


# ══════════════════════════════════════════════════════════════════════════════
# SBOX (version corrigée utilisant l'API publique)
# ══════════════════════════════════════════════════════════════════════════════
for p in [5, 7, 11, 13, 17, 23, 97]:
    sbox_fallback = SBox(p=p, use_fallback=True)
    vs = [sbox_fallback.forward(x) for x in range(p)]
    test(f"sbox:bijectif_p{p}", lambda vs=vs, p=p: ok(len(set(vs)) == p))
    test(f"sbox:roundtrip_p{p}", lambda sb=sbox_fallback, p=p: ok(
        all(sb.inverse(sb.forward(x)) == x for x in range(p))))

for p in [5, 7, 11, 13, 17, 23]:
    sb = SBox.from_delta(1, p)
    test(f"sbox:fwd_inv_p{p}", lambda sb=sb, p=p: ok(all(sb.inverse(sb.forward(x)) == x for x in range(p))))
    test(f"sbox:block_p{p}", lambda sb=sb, p=p:
    (lambda bl: eq(sb.inverse_block(sb.forward_block(bl)), bl))([i % p for i in range(min(p, 8))]))

test("sbox:repr", lambda: ok("SBox" in repr(SBox.from_delta(1, 7))))


# ══════════════════════════════════════════════════════════════════════════════
# MATRIX
# ══════════════════════════════════════════════════════════════════════════════
def _nodes(n, p):
    seen, res = set(), []
    for i in range(n):
        v = (i * 7 + 3) % p
        while v in seen or v == 0:
            v = (v + 1) % p
        res.append(v)
        seen.add(v)
    return res


for p in [7, 11, 13, 97, 257]:
    dm = DiffusionMatrix.from_nodes(_nodes(4, p), p)
    v = [i % p for i in range(4)]
    test(f"matrix:inv_p{p}", lambda dm=dm: ok(dm.verify_inverse()))
    test(f"matrix:rt_p{p}", lambda dm=dm, v=v: eq(dm.apply_inverse(dm.apply(v)), v))
    test(f"matrix:kind_p{p}", lambda dm=dm: ok(dm.kind in ("vandermonde", "cauchy")))

test("matrix:cauchy_kind", lambda: ok(DiffusionMatrix.from_nodes([1, 1, 2, 3], 97).kind == "cauchy"))
test("matrix:cauchy_inv", lambda: ok(DiffusionMatrix.from_nodes([1, 1, 2, 3], 97).verify_inverse()))


# ══════════════════════════════════════════════════════════════════════════════
# FP2
# ══════════════════════════════════════════════════════════════════════════════
for p in [5, 7, 11, 13, 17, 19, 23]:
    t = Fp2Element.t_generator(p)
    un, z = Fp2Element(1, 0, p), Fp2Element(0, 0, p)
    test(f"fp2:t2t1_p{p}", lambda t=t, un=un, z=z: eq(t * t + t + un, z))
    test(f"fp2:t3_un_p{p}", lambda t=t, un=un: eq(t ** 3, un))
    test(f"fp2:x4x2_1_p{p}", lambda t=t, un=un, z=z: eq(t ** 4 + t ** 2 + un, z))
    test(f"fp2:comm_p{p}", lambda p=p: eq(Fp2Element(2, 3, p) + Fp2Element(4, 1, p),
                                          Fp2Element(4, 1, p) + Fp2Element(2, 3, p)))
    test(f"fp2:neutre_p{p}", lambda p=p: eq(Fp2Element(3, 4, p) * Fp2Element(1, 0, p), Fp2Element(3, 4, p)))
    test(f"fp2:neg_p{p}", lambda p=p: eq(Fp2Element(3, 4, p) + (-Fp2Element(3, 4, p)), Fp2Element(0, 0, p)))
    test(f"fp2:pow0_p{p}", lambda p=p: eq(Fp2Element(2, 3, p) ** 0, Fp2Element(1, 0, p)))
    test(f"fp2:fermat_p{p}", lambda p=p: eq(Fp2Element(2, 1, p) ** (p * p - 1), Fp2Element(1, 0, p)))
    test(f"fp2:pow_1_p{p}", lambda p=p: eq(Fp2Element(1, 2, p) ** -1, Fp2Element(1, 2, p).inverse()))
    test(f"fp2:sqrt_p{p}", lambda p=p: (lambda x: ok((x * x).sqrt() * (x * x).sqrt() == x * x))(
        Fp2Element(1, 2, p)))

# Inversion exhaustive — exclure diviseurs de zéro (norme = a²-ab+b² ≡ 0 mod p)
for p in [5, 7, 11, 13]:
    def _inv(p=p):
        one = Fp2Element(1, 0, p)
        for a in range(p):
            for b in range(p):
                x = Fp2Element(a, b, p)
                if x.is_zero() or (a * a - a * b + b * b) % p == 0:
                    continue
                eq(x * x.inverse(), one, f"({a},{b}) mod {p}")

    test(f"fp2:inv_exhaustif_p{p}", _inv)

test("fp2:inv_zero_exc", lambda: raises(ZeroDivisionError, lambda: Fp2Element(0, 0, 7).inverse()))
test("fp2:diff_field_exc", lambda: raises(ValueError, lambda: Fp2Element(1, 2, 7) + Fp2Element(1, 2, 11)))
test("fp2:from_int", lambda: eq(Fp2Element.from_int(5, 7).to_int(), 5))
test("fp2:to_int_exc", lambda: raises(ValueError, lambda: Fp2Element(1, 2, 7).to_int()))
test("fp2:is_zero", lambda: ok(Fp2Element(0, 0, 7).is_zero() and not Fp2Element(1, 0, 7).is_zero()))
test("fp2:is_one", lambda: ok(Fp2Element(1, 0, 7).is_one() and not Fp2Element(0, 1, 7).is_one()))


# ══════════════════════════════════════════════════════════════════════════════
# MU — Stratégie A (p≡1 mod 3) et C (p≡2 mod 3)
# ══════════════════════════════════════════════════════════════════════════════
_PRIMES_C = [5, 11, 17, 23, 29, 41, 47]  # p≡2 mod 3 → Stratégie C garantie
_PRIMES_A = [7, 13, 19, 31, 37, 43, 61]  # p≡1 mod 3 → Stratégie A attendue

print("Génération de µ pour tous les premiers de test...", flush=True)
_mu = {p: generate_mu(p) for p in _PRIMES_C + _PRIMES_A + [2, 3]}
print(f"  {len(_mu)} premiers traités\n")

for p in _PRIMES_C:
    r = _mu[p]
    test(f"mu:C_strat_p{p}", lambda r=r, p=p: ok(r.strategy == "C", f"p={p} → {r.strategy}"))
    test(f"mu:C_verify_p{p}", lambda r=r, p=p: ok(_verify_root_fp2(r.mu, p)))
    test(f"mu:C_t3_un_p{p}", lambda r=r, p=p: eq(r.as_fp2() ** 3, Fp2Element(1, 0, p)))
    test(f"mu:C_as_int_exc_p{p}", lambda r=r: raises(TypeError, lambda: r.as_int()))
    test(f"mu:C_as_fp2_ok_p{p}", lambda r=r, p=p: ok(isinstance(r.as_fp2(), Fp2Element)))

for p in _PRIMES_A:
    r = _mu[p]
    test(f"mu:A_strat_p{p}", lambda r=r: ok(r.strategy in ("A", "C")))
    if r.strategy == "A":
        test(f"mu:A_verify_p{p}", lambda r=r, p=p: ok(_verify_root_zp(r.as_int(), p)))
        test(f"mu:A_range_p{p}", lambda r=r, p=p: ok(0 <= r.as_int() < p))

test("mu:p2_ok", lambda: ok(_mu[2] is not None))
test("mu:p3_ok", lambda: ok(_mu[3] is not None))
test("mu:repr", lambda: ok("MuResult" in repr(_mu[7])))

for p in [5, 11, 17]:
    test(f"mu:direct_fp2_p{p}", lambda p=p: ok(_verify_root_fp2(_mu_in_fp2(p), p)))


# ══════════════════════════════════════════════════════════════════════════════
# CIPHER / DECIPHER
# ══════════════════════════════════════════════════════════════════════════════
test("cipher:roundtrip", lambda: eq(dec(enc(b"Hello, World!")), b"Hello, World!"))
test("cipher:vide", lambda: eq(dec(enc(b"")), b""))
test("cipher:str", lambda: eq(decrypt(encrypt("Bonjour", _PWD, params=_P), _PWD, fast_mode=True), b"Bonjour"))
test("cipher:binaire", lambda: eq(dec(enc(bytes(range(256)))), bytes(range(256))))
test("cipher:1ko", lambda: (lambda m: eq(dec(enc(m)), m))(os.urandom(1024)))
test("cipher:utf8", lambda: (lambda m: eq(dec(enc(m)), m))("مرحبا 🔐".encode()))

for sz in [1, 15, 16, 17, 63, 64, 65, 127, 128, 255, 256, 512]:
    test(f"cipher:sz_{sz}", lambda sz=sz: (lambda m: eq(dec(enc(m)), m))(os.urandom(sz)))

test("cipher:auth_error", lambda: raises(CagouleAuthError,
                                         lambda: decrypt(enc(b"secret"), b"mauvais", fast_mode=True)))


def _alteration():
    ct = bytearray(enc(b"message"))
    ct[55] ^= 0xFF
    raises(CagouleAuthError, lambda: dec(bytes(ct)))


test("cipher:alteration", _alteration)

test("cipher:nonces_diff", lambda: ok(enc(b"x") != enc(b"x")))
test("cipher:magic", lambda: ok(enc(b"x")[:4] == b"CGL1"))
test("cipher:version", lambda: ok(enc(b"x")[4:5] == b"\x01"))
test("cipher:overhead", lambda: ok(len(enc(b"")) >= OVERHEAD))
test("cipher:fmt_exc", lambda: raises(Exception,
                                      lambda: decrypt(b"ce n est pas un paquet cgl1 valide du tout", _PWD,
                                                      fast_mode=True)))


# ══════════════════════════════════════════════════════════════════════════════
# RAPPORT
# ══════════════════════════════════════════════════════════════════════════════
passed = sum(1 for r in _results if r[0] == "PASS")
failed = sum(1 for r in _results if r[0] == "FAIL")
elapsed = sum(r[2] for r in _results)

print(f"\n{'═' * 65}")
print(f"  CAGOULE v1.5.0 — Résultats des tests")
print(f"{'═' * 65}")

if failed:
    print(f"\n  ❌ Échecs ({failed}) :")
    for s, name, t, err in _results:
        if s == "FAIL":
            print(f"    ✗  {name}")
            print(f"       {type(err).__name__}: {str(err)[:100]}")

print(f"\n  ✅ {passed} passés   ❌ {failed} échoués   Total : {len(_results)}   ⏱ {elapsed:.1f}s")
print(f"{'═' * 65}\n")
sys.exit(0 if failed == 0 else 1)