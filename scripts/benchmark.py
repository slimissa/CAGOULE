#!/usr/bin/env python3
"""
benchmark.py — Benchmark complet CAGOULE v1.5

Métriques :
  - KDF (Argon2id / Scrypt fast)
  - Chiffrement / Déchiffrement par taille
  - Débit en MB/s
  - Effet avalanche (~50% de bits changés)
  - Analyse S-box (uniformité diff., non-linéarité)

Usage :
    python3 scripts/benchmark.py
    python3 scripts/benchmark.py --quick   (tailles réduites)
    python3 scripts/benchmark.py --sbox    (analyse S-box exhaustive)
"""

import argparse
import math
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cagoule.cipher  import encrypt
from cagoule.decipher import decrypt
from cagoule.params  import CagouleParams
from cagoule.utils   import analyze_sbox, sbox_report


# ─── Helpers ─────────────────────────────────────────────────────────────────

def hsize(n: int) -> str:
    for unit in ["o", "Ko", "Mo", "Go"]:
        if n < 1024: return f"{n} {unit}"
        n //= 1024
    return f"{n} To"

def htime(ms: float) -> str:
    if ms < 1:    return f"{ms*1000:.1f} µs"
    if ms < 1000: return f"{ms:.1f} ms"
    return f"{ms/1000:.2f} s"

def sep(char="─", n=65): print(char * n)


# ─── 1. KDF ──────────────────────────────────────────────────────────────────

def bench_kdf(n_iter: int = 3) -> None:
    print("\n📊  1. Dérivation de clé (KDF)")
    sep()

    password = b"BenchmarkPassword_CAGOULE_2026"

    # Argon2id ou Scrypt (fast_mode=False)
    times = []
    kdf_type = "Argon2id"
    for i in range(n_iter):
        t0 = time.perf_counter()
        p = CagouleParams.derive(password, fast_mode=False)
        times.append((time.perf_counter() - t0) * 1000)
        p.zeroize()
        print(f"  KDF produit ({kdf_type}) iter {i+1}: {htime(times[-1])}")

    avg = sum(times) / n_iter
    print(f"\n  → Moyenne : {htime(avg)}   (cible < 500 ms)")
    print(f"  → Type    : {kdf_type}")

    # fast_mode
    times_fast = []
    for i in range(n_iter):
        t0 = time.perf_counter()
        p = CagouleParams.derive(password, fast_mode=True)
        times_fast.append((time.perf_counter() - t0) * 1000)
        p.zeroize()

    avg_fast = sum(times_fast) / n_iter
    print(f"  → Fast mode (Scrypt n=2¹⁴) : {htime(avg_fast)}   (cible < 100 ms)")


# ─── 2. Chiffrement / Déchiffrement ─────────────────────────────────────────

def bench_cipher(sizes: list[int], n_iter: int = 3) -> None:
    print("\n📊  2. Chiffrement / Déchiffrement")
    sep()
    print(f"  {'Taille':>8}  {'CT taille':>10}  {'Chiffrement':>12}  {'Déchiffrement':>14}  {'Débit':>10}")
    sep("·")

    password = b"BenchmarkPassword_CAGOULE_2026"
    params = CagouleParams.derive(password, fast_mode=True)

    for size in sizes:
        msg = os.urandom(size)

        enc_times = []
        ct = None
        for _ in range(n_iter):
            t0 = time.perf_counter()
            ct = encrypt(msg, password, params=params)
            enc_times.append((time.perf_counter() - t0) * 1000)
        avg_enc = sum(enc_times) / n_iter

        dec_times = []
        for _ in range(n_iter):
            t0 = time.perf_counter()
            # ⚠️ CRITICAL : utiliser params pré-calculés pour éviter re-KDF
            decrypt(ct, password, fast_mode=True, params=params)
            dec_times.append((time.perf_counter() - t0) * 1000)
        avg_dec = sum(dec_times) / n_iter

        throughput = (size / (avg_enc / 1000)) / (1024 * 1024)
        status_enc = "✓" if avg_enc < 100 else "⚠"
        status_dec = "✓" if avg_dec < 100 else "⚠"

        print(f"  {hsize(size):>8}  {hsize(len(ct)):>10}  "
              f"{status_enc} {htime(avg_enc):>10}  "
              f"{status_dec} {htime(avg_dec):>12}  "
              f"{throughput:>8.2f} MB/s")

    params.zeroize()


# ─── 3. Effet avalanche ──────────────────────────────────────────────────────

def bench_avalanche(n_samples: int = 50) -> None:
    print("\n📊  3. Effet avalanche")
    sep()

    password = b"BenchmarkPassword_CAGOULE_2026"
    params = CagouleParams.derive(password, fast_mode=True)
    msg = b"CAGOULE Avalanche Test Message 2026"

    ct_ref = encrypt(msg, password, params=params)
    ct_bytes = len(ct_ref[49:-16])  # payload uniquement

    total_diff = 0
    for _ in range(n_samples):
        # Modifier 1 bit aléatoire dans le plaintext
        pos = os.urandom(1)[0] % len(msg)
        msg_mod = bytearray(msg)
        msg_mod[pos] ^= 1 << (os.urandom(1)[0] % 8)

        ct_mod = encrypt(bytes(msg_mod), password, params=params)

        # Compter les bits différents dans le payload
        diff = sum(
            bin(a ^ b).count("1")
            for a, b in zip(ct_ref[49:-16], ct_mod[49:-16])
        )
        total_diff += diff

    avg_diff = total_diff / n_samples
    total_bits = ct_bytes * 8
    pct = 100 * avg_diff / total_bits

    params.zeroize()

    status = "✓" if 40 <= pct <= 60 else "⚠"
    print(f"  Bits modifiés en moyenne : {avg_diff:.1f} / {total_bits}")
    print(f"  Taux de diffusion       : {status} {pct:.1f}%   (cible : ~50%)")
    print(f"  Échantillons            : {n_samples}")

    if not (40 <= pct <= 60):
        print(f"  ⚠ Attention : taux hors cible (peut indiquer un problème de diffusion)")


# ─── 4. Analyse S-box ────────────────────────────────────────────────────────

def bench_sbox(p_values: list[int] = None) -> None:
    print("\n📊  4. Analyse cryptographique de la S-box")
    sep()

    if p_values is None:
        p_values = [7, 11, 13, 17, 23, 97]

    from cagoule.sbox import SBox

    print(f"  {'p':>6}  {'Type':>14}  {'δ (diff)':>10}  {'Bias lin.':>12}  {'Bjectif':>8}")
    sep("·")

    for p in p_values:
        sbox = SBox.from_delta(1, p)
        try:
            t0 = time.perf_counter()
            analysis = analyze_sbox(sbox, p)
            elapsed = (time.perf_counter() - t0) * 1000

            delta = analysis["differential"]["delta"]
            bias  = analysis["linear"]["max_bias"]
            bij   = "✓" if analysis["is_bijective"] else "✗"
            typ   = analysis["type"][:13]

            # δ idéal = 1 (impossible sur Z/pZ en général), bon si < p//4
            delta_ok = "✓" if delta <= max(p // 4, 2) else "⚠"

            print(f"  {p:>6}  {typ:>14}  {delta_ok} {delta:>8}  {bias:>12.6f}  {bij:>8}")
        except ValueError as e:
            print(f"  {p:>6}  {'—':>14}  {'—':>10}  {'—':>12}  {'—':>8}  ({e})")

    print()
    print("  Note : δ=1 est idéal (AES-like). Pour x³+cx sur Z/pZ :")
    print("         δ > 1 est attendu — usage académique exclusivement.")


# ─── 5. Analyse mémoire (approximation) ──────────────────────────────────────

def bench_memory() -> None:
    print("\n📊  5. Usage mémoire (estimation)")
    sep()

    try:
        import tracemalloc
        tracemalloc.start()

        password = b"BenchmarkPassword_CAGOULE_2026"
        msg = os.urandom(100 * 1024)

        snapshot_before = tracemalloc.take_snapshot()
        params = CagouleParams.derive(password, fast_mode=True)
        ct = encrypt(msg, password, params=params)
        decrypt(ct, password, fast_mode=True, params=params)
        snapshot_after = tracemalloc.take_snapshot()

        top_stats = snapshot_after.compare_to(snapshot_before, "lineno")
        total_diff = sum(s.size_diff for s in top_stats)

        tracemalloc.stop()
        params.zeroize()

        status = "✓" if total_diff < 256 * 1024 * 1024 else "⚠"
        print(f"  Mémoire allouée (chiffr. 100Ko) : {status} {hsize(max(0, total_diff))}")
        print(f"  (cible < 256 Mo)")

    except Exception as e:
        print(f"  tracemalloc non disponible : {e}")


# ─── 6. Overhead CGL1 (bonus) ────────────────────────────────────────────────

def bench_overhead() -> None:
    """Mesure l'overhead du format CGL1."""
    print("\n📊  6. Overhead CGL1")
    sep()

    password = b"BenchmarkPassword_CAGOULE_2026"
    params = CagouleParams.derive(password, fast_mode=True)

    print(f"  {'Plaintext':>12}  {'CGL1':>12}  {'Overhead':>10}  {'Ratio':>8}")
    sep("·")

    for size in [0, 16, 64, 256, 1024, 10240, 102400]:
        msg = os.urandom(size)
        ct = encrypt(msg, password, params=params)
        overhead = len(ct) - size
        ratio = len(ct) / size if size > 0 else 0
        print(f"  {hsize(size):>12}  {hsize(len(ct)):>12}  {overhead:>10}  {ratio:>7.2f}x")

    params.zeroize()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark CAGOULE v1.5",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--quick",  action="store_true", help="Tailles réduites (plus rapide)")
    parser.add_argument("--sbox",   action="store_true", help="Analyse S-box exhaustive")
    parser.add_argument("--iter",   type=int, default=3, help="Nombre d'itérations (défaut: 3)")
    parser.add_argument("--no-kdf", action="store_true", help="Passer le bench KDF (lent)")
    parser.add_argument("--overhead", action="store_true", help="Afficher l'overhead CGL1")
    args = parser.parse_args()

    print("=" * 65)
    print("  CAGOULE v1.5 — Benchmark de performance et sécurité")
    print("=" * 65)

    sizes = [1024, 10*1024, 100*1024] if args.quick else [1024, 10*1024, 100*1024, 1024*1024]

    if not args.no_kdf:
        bench_kdf(n_iter=args.iter)

    bench_cipher(sizes, n_iter=args.iter)
    bench_avalanche()

    if args.sbox:
        bench_sbox([7, 11, 13, 17, 23, 97, 257])
    else:
        bench_sbox([7, 11, 13, 23])

    bench_memory()

    if args.overhead:
        bench_overhead()

    print("\n" + "=" * 65)
    print("  Benchmark terminé.")
    print("=" * 65)


if __name__ == "__main__":
    main()