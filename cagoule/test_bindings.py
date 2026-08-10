"""
test_bindings.py — Validation des bindings Python → libcagoule.so — CAGOULE v3.1.0

Lancement des tests :
    python3 test_bindings.py
"""

import sys
import os as _os
import warnings
import time
from pathlib import Path

# ============================================================
# Configuration des chemins
# ============================================================

# Ajouter le dossier parent au PYTHONPATH pour les imports absolus
SCRIPT_DIR = Path(__file__).resolve().parent
PARENT_DIR = SCRIPT_DIR.parent

if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

# Configuration de la bibliothèque C
_os.environ["LIBCAGOULE_PATH"] = str(SCRIPT_DIR / "c" / "libcagoule.so")

# ============================================================
# Tests
# ============================================================

passed, failed = 0, 0

def check(cond, msg):
    global passed, failed
    if cond:
        print(f"  ✓ {msg}")
        passed += 1
    else:
        print(f"  ✗ FAIL: {msg}")
        failed += 1

print("══════════════════════════════════════════")
print("  Bindings Python → libcagoule.so — v3.1.0")
print("══════════════════════════════════════════")

# ── Import et disponibilité ─────────────────────────────────────────────
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cagoule.matrix import DiffusionMatrix
    from cagoule.sbox import SBox
    from cagoule._binding import CAGOULE_C_AVAILABLE, cagoule_p_bytes

    # v3.0.0: utiliser __backend__ (double underscore)
    try:
        from cagoule import __backend__ as backend_str
    except ImportError:
        backend_str = "C (libcagoule.so)" if CAGOULE_C_AVAILABLE else "Python pur (fallback)"

print(f"\n  libcagoule.so disponible : {CAGOULE_C_AVAILABLE}")
check(CAGOULE_C_AVAILABLE, "libcagoule.so chargé avec succès")
print(f"  Backend actif : {backend_str}")
check(CAGOULE_C_AVAILABLE, "Backend C actif (basé sur CAGOULE_C_AVAILABLE)")

# ── Constantes ──────────────────────────────────────────────────────────
P = 10441487724840939323  # Premier du benchmark
DELTA = 123456789

# ── Test SBox ────────────────────────────────────────────────────────────
print("\n[SBox Feistel C]")
s = SBox.from_delta(DELTA, P)

check(not s.is_fallback(), "use_feistel=1 pour P≈2^64")

repr_str = repr(s)
check("Feistel" in repr_str or "C" in repr_str, f"repr SBox : {repr_str[:60]}...")

# Roundtrip 10000 valeurs
N = 10000
ok = True
for i in range(N):
    x = (i * 1234567891011) % P
    y = s.forward(x)
    x2 = s.inverse(y)
    if x2 != x:
        ok = False
        print(f"    FAIL x={x} y={y} x2={x2}")
        break
check(ok, f"roundtrip forward/inverse ({N} valeurs)")

# Test bloc
block = [(i * 999999999937) % P for i in range(16)]
enc = s.forward_block(block)
dec = s.inverse_block(enc)
check(dec == block, "forward_block / inverse_block roundtrip (n=16)")
check(enc != block, "enc != plaintext (S-box non triviale)")

# Test zeroize
print("\n[SBox zeroize]")
s2 = SBox.from_delta(DELTA, P)
try:
    s2.zeroize()
    check(True, "zeroize() exécuté sans erreur")
except Exception as e:
    check(False, f"zeroize() a échoué: {e}")

# ── Test DiffusionMatrix ─────────────────────────────────────────────────
print("\n[DiffusionMatrix C]")

def gen_nodes(p, n=16):
    """Génère des nœuds distincts de manière déterministe."""
    nodes, seen = [], set()
    max_attempts = 10000
    for i in range(n):
        v = (i * 7 + 3) % p
        attempts = 0
        while v in seen and attempts < max_attempts:
            v = (v + 1) % p
            attempts += 1
        if v in seen:
            raise RuntimeError(
                f"Impossible de générer un nœud distinct après {max_attempts} tentatives"
            )
        nodes.append(v)
        seen.add(v)
    return nodes

nodes = gen_nodes(P)
m = DiffusionMatrix.from_nodes(nodes, P)

repr_str = repr(m)
check("C" in repr_str or "Matrix" in repr_str, f"repr Matrix : {repr_str[:60]}...")
check(m.verify_inverse(), "P × P⁻¹ = I")

v = [(i * 1000000007) % P for i in range(16)]
fwd = m.apply(v)
back = m.apply_inverse(fwd)
check(back == v, "apply_inverse(apply(v)) == v")
check(fwd != v, "apply(v) != v (matrice non triviale)")

# Cauchy fallback (nœuds dupliqués)
nodes_dup = list(nodes)
nodes_dup[3] = nodes_dup[1]
m2 = DiffusionMatrix.from_nodes(nodes_dup, P)
check(m2.kind == "cauchy", "Cauchy fallback avec collision")
check(m2.verify_inverse(), "Cauchy P × P⁻¹ = I")

# ── v3.0.0: Backend Info ─────────────────────────────────────────────────
print("\n[v3.0.0 — Backend Info]")

# Test get_backend_info() depuis _binding
try:
    from cagoule._binding import get_backend_info
    info = get_backend_info()
    check("matrix_backend" in info, "get_backend_info() contient 'matrix_backend'")
    check("omega_backend" in info, "get_backend_info() contient 'omega_backend'")
    check(info["matrix_backend"] in ("avx2", "scalar", "python"),
          f"matrix_backend = {info['matrix_backend']}")
    print(f"  Backend info: {info}")
except Exception as e:
    check(False, f"get_backend_info() a échoué: {e}")

# Test backend_info depuis __init__.py
try:
    from cagoule import backend_info
    check("matrix_backend" in backend_info,
          "backend_info depuis __init__ contient 'matrix_backend'")
    print(f"  backend_info: {backend_info}")
except ImportError:
    check(False, "backend_info non exporté depuis __init__.py")

# Test matrix.backend_info property
try:
    bi = m.backend_info
    check(bi in ("avx2", "scalar", "python"),
          f"matrix.backend_info = {bi}")
except Exception as e:
    check(False, f"matrix.backend_info a échoué: {e}")

# ── v3.0.0: CTR Backend Info ─────────────────────────────────────────────
print("\n[v3.0.0 — CTR Backend]")
try:
    from cagoule._binding import get_backend_info_v300, _HAS_CTR_API
    info_v300 = get_backend_info_v300()
    check("ctr_backend" in info_v300, "get_backend_info_v300() contient 'ctr_backend'")
    check(info_v300["ctr_backend"] in ("C", "scalar", "python"),
          f"ctr_backend = {info_v300['ctr_backend']}")
    check("ctr_4x_available" in info_v300, "get_backend_info_v300() contient 'ctr_4x_available'")
    print(f"  Backend info v3.0.0: {info_v300}")
except Exception as e:
    check(False, f"get_backend_info_v300() a échoué: {e}")

# Test get_backend_info_v230() (v2.3.0)
try:
    from cagoule._binding import get_backend_info_v230
    info_v230 = get_backend_info_v230()
    check("sbox_backend" in info_v230, 
          "get_backend_info_v230() contient 'sbox_backend'")
    check(info_v230["sbox_backend"] in ("avx2", "scalar", "python"),
          f"sbox_backend = {info_v230['sbox_backend']}")
    print(f"  Backend info v2.3.0: {info_v230}")
except Exception as e:
    check(False, f"get_backend_info_v230() a échoué: {e}")

# ── v3.0.0: VERSION Dispatch ─────────────────────────────────────────────
print("\n[v3.0.0 — VERSION Dispatch]")
try:
    from cagoule import encrypt, decrypt, encrypt_cbc, decrypt_cbc
    
    test_msg = b"Hello CTR v3.0.0!"
    test_pwd = b"test_password_v3"
    
    # CTR (default)
    ct = encrypt(test_msg, test_pwd, fast_mode=True)
    check(ct[4:5] == b'\x02', "encrypt() produit VERSION 0x02 (CTR)")
    pt = decrypt(ct, test_pwd, fast_mode=True)
    check(pt == test_msg, "decrypt() roundtrip CTR v0x02")
    
    # CBC (explicit)
    ct_cbc = encrypt_cbc(test_msg, test_pwd, fast_mode=True)
    check(ct_cbc[4:5] == b'\x01', "encrypt_cbc() produit VERSION 0x01 (CBC)")
    pt_cbc = decrypt(ct_cbc, test_pwd, fast_mode=True)
    check(pt_cbc == test_msg, "decrypt() dispatch CBC v0x01")
    
    # decrypt() dispatch: CBC ciphertext works with decrypt()
    pt_dispatch = decrypt(ct_cbc, test_pwd, fast_mode=True)
    check(pt_dispatch == test_msg, "decrypt() auto-dispatch CBC → correct")
    
    # decrypt() dispatch: CTR ciphertext works with decrypt()
    pt_dispatch_ctr = decrypt(ct, test_pwd, fast_mode=True)
    check(pt_dispatch_ctr == test_msg, "decrypt() auto-dispatch CTR → correct")

except Exception as e:
    check(False, f"VERSION dispatch a échoué: {e}")

# ── v3.0.0: CTR Bulk ─────────────────────────────────────────────────────
print("\n[v3.0.0 — CTR Bulk]")
try:
    from cagoule import encrypt_bulk, decrypt_bulk
    
    messages = [b"msg1", b"msg2", b"msg3"]
    cts = encrypt_bulk(messages, test_pwd, fast_mode=True)
    check(len(cts) == 3, "encrypt_bulk retourne 3 ciphertexts")
    for i, ct_bulk in enumerate(cts):
        check(ct_bulk[4:5] == b'\x02', f"encrypt_bulk[{i}] VERSION 0x02")
    
    pts = decrypt_bulk(cts, test_pwd, fast_mode=True)
    check(pts == messages, "decrypt_bulk roundtrip CTR")
except Exception as e:
    check(False, f"CTR Bulk a échoué: {e}")

# ── v3.0.0: Migration CBC → CTR ──────────────────────────────────────────
print("\n[v3.0.0 — Migration CBC → CTR]")
try:
    from cagoule import migrate_cbc_to_ctr
    
    # Create a CBC ciphertext
    ct_cbc_migrate = encrypt_cbc(b"Migrate me!", test_pwd, fast_mode=True)
    check(ct_cbc_migrate[4:5] == b'\x01', "Source: VERSION 0x01 (CBC)")
    
    # Migrate to CTR
    ct_ctr_migrated = migrate_cbc_to_ctr(ct_cbc_migrate, test_pwd, fast_mode=True)
    check(ct_ctr_migrated[4:5] == b'\x02', "Migrated: VERSION 0x02 (CTR)")
    
    # Verify roundtrip
    pt_migrated = decrypt(ct_ctr_migrated, test_pwd, fast_mode=True)
    check(pt_migrated == b"Migrate me!", "Migration roundtrip OK")
except Exception as e:
    check(False, f"Migration a échoué: {e}")

# ── free() et context manager ────────────────────────────────────────────
print("\n[v3.0.0 — free() et context manager]")

# Test free() avec guard double-free
m3 = DiffusionMatrix.from_nodes(nodes, P)
try:
    m3.free()
    check(True, "free() exécuté sans erreur")
    # Double-free doit lever RuntimeError
    try:
        m3.free()
        check(False, "Double-free aurait dû lever RuntimeError")
    except RuntimeError:
        check(True, "Double-free lève RuntimeError")
except Exception as e:
    check(False, f"free() a échoué: {e}")

# Test context manager
try:
    with DiffusionMatrix.from_nodes(nodes, P) as m4:
        check(m4.verify_inverse(), "Context manager: matrice valide")
        _ = m4.apply(v)
    # Après __exit__, _freed est True
    check(m4._freed, "Context manager: _freed après __exit__")
except Exception as e:
    check(False, f"Context manager a échoué: {e}")

# ── Benchmark ────────────────────────────────────────────────────────────
print("\n[Benchmark — 65 536 blocs × 16 éléments (≡ 1 MB)]")
N_BLOCKS = 65536

# Matrix forward
m_bench = DiffusionMatrix.from_nodes(nodes, P)
t0 = time.perf_counter()
for _ in range(N_BLOCKS):
    fwd = m_bench.apply(v)
fwd_ms = (time.perf_counter() - t0) * 1000

# Matrix inverse
t0 = time.perf_counter()
for _ in range(N_BLOCKS):
    back = m_bench.apply_inverse(v)
inv_ms = (time.perf_counter() - t0) * 1000

print(f"  Matrix forward  65 536 blocs : {fwd_ms:.1f} ms")
print(f"  Matrix inverse  65 536 blocs : {inv_ms:.1f} ms")
if fwd_ms > 0:
    print(f"  Ratio inv/fwd               : {inv_ms/fwd_ms:.2f}×")
print(f"  [Référence Python v1.x      : ~8 000 ms]")
if fwd_ms > 0:
    print(f"  Gain                        : ×{8000/fwd_ms:.0f}")

# SBox forward
t0 = time.perf_counter()
for i in range(N_BLOCKS):
    x = i % P
    s.forward(x)
sbox_ms = (time.perf_counter() - t0) * 1000
print(f"  SBox forward    65 536 appels : {sbox_ms:.1f} ms")

# Vérifications de performance (sautées sous Valgrind)
_under_valgrind = _os.environ.get("RUNNING_ON_VALGRIND") is not None
if not _under_valgrind:
    check(fwd_ms < 1000, f"Matrix forward < 1s ({fwd_ms:.0f}ms)")
    check(inv_ms < 1000, f"Matrix inverse < 1s ({inv_ms:.0f}ms)")
    if fwd_ms > 0 and inv_ms > 0:
        ratio = inv_ms / fwd_ms
        check(ratio < 2.0, f"Ratio inv/fwd < 2× ({ratio:.2f})")
    check(sbox_ms < 500, f"SBox forward < 500ms ({sbox_ms:.0f}ms)")
else:
    print("  (seuils de performance ignorés sous Valgrind)")

# Test analyze_sbox (for small p only)
from cagoule.utils import analyze_sbox, sbox_report
s_small = SBox.from_delta(DELTA, 97)
analysis = analyze_sbox(s_small, 97)
check(analysis["is_bijective"], "SBox analysis: bijective for p=97")
report = sbox_report(analysis)
check("S-box Analysis" in report, "sbox_report generates report")

# ── Test p_bytes (fonction utilitaire) ────────────────────────────────────
print("\n[p_bytes]")
p_small = 65537
p_large = P
check(cagoule_p_bytes(p_small) == 4, 
      f"p_bytes({p_small}) = {cagoule_p_bytes(p_small)} (attendu 4)")
check(cagoule_p_bytes(p_large) == 8, 
      f"p_bytes({p_large}) = {cagoule_p_bytes(p_large)} (attendu 8)")

# ── Test layout des structs ctypes (silencieux si mismatch -- critique) ──
print("\n[Layout des structs ctypes vs C]")
try:
    from cagoule._binding import (
        CagouleMatrixC, CagouleSBox64C,
        _EXPECTED_MATRIX_LAYOUT, _EXPECTED_SBOX_LAYOUT, _verify_struct_layout,
    )
    import ctypes as _ctypes

    check(_ctypes.sizeof(CagouleMatrixC) == _EXPECTED_MATRIX_LAYOUT["_sizeof_"],
          f"sizeof(CagouleMatrixC) == {_EXPECTED_MATRIX_LAYOUT['_sizeof_']}")
    check(_ctypes.sizeof(CagouleSBox64C) == _EXPECTED_SBOX_LAYOUT["_sizeof_"],
          f"sizeof(CagouleSBox64C) == {_EXPECTED_SBOX_LAYOUT['_sizeof_']}")

    for field_name, expected_offset in _EXPECTED_MATRIX_LAYOUT.items():
        if field_name == "_sizeof_":
            continue
        actual = getattr(CagouleMatrixC, field_name).offset
        check(actual == expected_offset,
              f"CagouleMatrixC.{field_name}.offset == {expected_offset} (got {actual})")

    for field_name, expected_offset in _EXPECTED_SBOX_LAYOUT.items():
        if field_name == "_sizeof_":
            continue
        actual = getattr(CagouleSBox64C, field_name).offset
        check(actual == expected_offset,
              f"CagouleSBox64C.{field_name}.offset == {expected_offset} (got {actual})")

    # Confirme que la fonction de vérification détecte réellement un
    # mismatch délibéré, plutôt que de simplement supposer qu'elle marche
    # parce que les valeurs correctes correspondent (un test qui ne peut
    # jamais échouer ne teste rien).
    _bad = dict(_EXPECTED_MATRIX_LAYOUT)
    _bad["_sizeof_"] = _bad["_sizeof_"] + 8
    _errors = _verify_struct_layout(CagouleMatrixC, _bad)
    check(len(_errors) >= 1, "_verify_struct_layout détecte un sizeof corrompu délibérément")

except ImportError as e:
    check(False, f"Vérification de layout des structs non disponible: {e}")

# ── Test codes d'erreur ──────────────────────────────────────────────────
print("\n[Codes d'erreur]")
try:
    from cagoule._binding import CAGOULE_OK, CAGOULE_ERR_NULL, CAGOULE_ERR_SIZE, CAGOULE_ERR_CORRUPT
    check(CAGOULE_OK == 0, "CAGOULE_OK == 0")
    check(CAGOULE_ERR_NULL == -1, "CAGOULE_ERR_NULL == -1")
    check(CAGOULE_ERR_SIZE == -2, "CAGOULE_ERR_SIZE == -2")
    check(CAGOULE_ERR_CORRUPT == -3, "CAGOULE_ERR_CORRUPT == -3")
except ImportError as e:
    check(False, f"Codes d'erreur non disponibles: {e}")

# ── Test fallback Python ─────────────────────────────────────────────────
print("\n[Fallback Python (simulation)]")
try:
    from cagoule.sbox import SBoxPython
    check(True, "SBoxPython disponible pour fallback")
except ImportError:
    check(False, "SBoxPython non disponible")

# ── Résumé ──────────────────────────────────────────────────────────────
print(f"\n──────────────────────────────────────────")
print(f"  ✅ {passed} passés  ❌ {failed} échoués")
print(f"══════════════════════════════════════════")

sys.exit(0 if failed == 0 else 1)