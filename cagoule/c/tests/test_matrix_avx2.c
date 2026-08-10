/**
 * test_matrix_avx2.c — Tests cagoule_matrix_mul_avx2 / mul_inv_avx2
 *                       CAGOULE v3.1.0
 *
 * Tests :
 *   1. Roundtrip P×P⁻¹=I (vecteurs standards) — chemin AVX2
 *   2. Parité AVX2 vs scalaire : 100 messages aléatoires
 *   3. Symétrie
 *   3b. Mersenne pool parity (8 primes × 100 vectors × 32)
 *   3c. Mersenne pool roundtrip P×P⁻¹=I (8 primes × 256) chiffrement/déchiffrement (même résultat)
 *   4. Bench comparatif AVX2 vs scalaire (65 536 blocs ≡ 1 MB)
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cagoule_math.h"
#include "cagoule_matrix.h"

/* ── Helpers ──────────────────────────────────────────────────────── */
static int _pass = 0, _fail = 0;

#define ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL  " msg "\n", ##__VA_ARGS__); \
        _fail++; \
    } else { \
        _pass++; \
    } \
} while(0)

static uint64_t _rng = 0xcafe0123dead4567;
static uint64_t rng64(void) {
    _rng ^= _rng << 13; _rng ^= _rng >> 7; _rng ^= _rng << 17;
    return _rng;
}

/* Même premier de benchmark que test_matrix.py */
static const uint64_t P_BENCH = 10441487724840939323ULL;

/* Génère CAGOULE_N nœuds distincts dans [1, p) */
static void make_nodes(uint64_t nodes[CAGOULE_N], uint64_t p) {
    uint64_t seen[CAGOULE_N];
    int n_seen = 0;
    for (int i = 0; i < CAGOULE_N; i++) {
        uint64_t v = (uint64_t)(i * 7 + 3) % p;
        if (v == 0) v = 1;
        int dup;
        do {
            dup = 0;
            for (int j = 0; j < n_seen; j++) {
                if (seen[j] == v) { v = (v + 1) % p; if (v==0) v=1; dup=1; break; }
            }
        } while (dup);
        nodes[i] = v;
        seen[n_seen++] = v;
    }
}

/* ── Test 1 : roundtrip P×P⁻¹=I via chemin AVX2 ────────────────── */
static void test_roundtrip_avx2(void) {
    printf("  [1] Roundtrip P×P⁻¹=I (16 vecteurs standards)...\n");

    uint64_t nodes[CAGOULE_N];
    make_nodes(nodes, P_BENCH);
    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_BENCH);
    ASSERT(m != NULL, "cagoule_matrix_build a échoué");
    if (!m) return;

    /* cagoule_matrix_mul dispatch AVX2 si dispo */
    for (int i = 0; i < CAGOULE_N; i++) {
        uint64_t v[CAGOULE_N] = {0};
        v[i] = 1;
        uint64_t fwd[CAGOULE_N], back[CAGOULE_N];
        cagoule_matrix_mul(m, v, fwd);
        cagoule_matrix_mul_inv(m, fwd, back);
        ASSERT(back[i] == 1,
               "Roundtrip échoué : back[%d]=%llu (attendu 1)", i,
               (unsigned long long)back[i]);
        for (int j = 0; j < CAGOULE_N; j++) {
            if (j != i) {
                ASSERT(back[j] == 0,
                       "Roundtrip échoué : back[%d]=%llu (attendu 0) pour i=%d",
                       j, (unsigned long long)back[j], i);
            }
        }
    }
    cagoule_matrix_free(m);
}

/* ── Test 2 : parité AVX2 vs scalaire ───────────────────────────── */
static void test_parity_avx2_vs_scalar(void) {
    printf("  [2] Parité AVX2 vs scalaire (100 vecteurs aléatoires)...\n");

    uint64_t nodes[CAGOULE_N];
    make_nodes(nodes, P_BENCH);
    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_BENCH);
    ASSERT(m != NULL, "cagoule_matrix_build a échoué");
    if (!m) return;

    for (int t = 0; t < 100; t++) {
        uint64_t v[CAGOULE_N];
        for (int j = 0; j < CAGOULE_N; j++)
            v[j] = rng64() % P_BENCH;

        uint64_t out_scalar[CAGOULE_N], out_avx2[CAGOULE_N];
        cagoule_matrix_mul_scalar(m, v, out_scalar);
        cagoule_matrix_mul(m, v, out_avx2);

        for (int j = 0; j < CAGOULE_N; j++) {
            ASSERT(out_scalar[j] == out_avx2[j],
                   "Parité forward j=%d t=%d scalar=%llu avx2=%llu",
                   j, t,
                   (unsigned long long)out_scalar[j],
                   (unsigned long long)out_avx2[j]);
        }

        uint64_t inv_scalar[CAGOULE_N], inv_avx2[CAGOULE_N];
        cagoule_matrix_mul_inv_scalar(m, v, inv_scalar);
        cagoule_matrix_mul_inv(m, v, inv_avx2);

        for (int j = 0; j < CAGOULE_N; j++) {
            ASSERT(inv_scalar[j] == inv_avx2[j],
                   "Parité inverse j=%d t=%d scalar=%llu avx2=%llu",
                   j, t,
                   (unsigned long long)inv_scalar[j],
                   (unsigned long long)inv_avx2[j]);
        }
    }
    cagoule_matrix_free(m);
}

/* ── Test 3 : symétrie chiffrement/déchiffrement ────────────────── */
static void test_symmetry(void) {
    printf("  [3] Symétrie encrypt/decrypt (50 messages aléatoires)...\n");

    uint64_t nodes[CAGOULE_N];
    make_nodes(nodes, P_BENCH);
    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_BENCH);
    ASSERT(m != NULL, "cagoule_matrix_build a échoué");
    if (!m) return;

    for (int t = 0; t < 50; t++) {
        uint64_t orig[CAGOULE_N], enc[CAGOULE_N], dec[CAGOULE_N];
        for (int j = 0; j < CAGOULE_N; j++)
            orig[j] = rng64() % P_BENCH;

        cagoule_matrix_mul(m, orig, enc);
        cagoule_matrix_mul_inv(m, enc, dec);

        for (int j = 0; j < CAGOULE_N; j++) {
            ASSERT(dec[j] == orig[j],
                   "Symétrie échouée j=%d orig=%llu dec=%llu",
                   j, (unsigned long long)orig[j], (unsigned long long)dec[j]);
        }
    }
    cagoule_matrix_free(m);
}


/* ── Test 3b : Mersenne pool parity — AVX2 vs scalaire (v2.5.2) ─── */
static void test_mersenne_parity(void) {
    printf("  [3b] Mersenne pool parity (8 primes × 100 vectors)...\n");

    extern const uint64_t CAGOULE_MERSENNE_P[8];

    for (int pi = 0; pi < 8; pi++) {
        uint64_t p = CAGOULE_MERSENNE_P[pi];
        uint64_t nodes[CAGOULE_N];
        make_nodes(nodes, p);
        CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, p);
        if (!m) {
            fprintf(stderr, "  FAIL  build failed for Mersenne prime[%d] p=%llu\n",
                    pi, (unsigned long long)p);
            _fail++;
            continue;
        }

        /* Verify k_mersenne is set */
        ASSERT(m->k_mersenne > 0,
               "k_mersenne set for Mersenne prime[%d]", pi);

        /* Parity: 100 random vectors, forward + inverse */
        for (int t = 0; t < 100; t++) {
            uint64_t v[CAGOULE_N];
            for (int j = 0; j < CAGOULE_N; j++)
                v[j] = rng64() % p;

            uint64_t out_scalar[CAGOULE_N], out_avx2[CAGOULE_N];
            cagoule_matrix_mul_scalar(m, v, out_scalar);
            cagoule_matrix_mul(m, v, out_avx2);

            for (int j = 0; j < CAGOULE_N; j++) {
                ASSERT(out_scalar[j] == out_avx2[j],
                       "Mersenne fwd prime[%d] j=%d t=%d scalar=%llu avx2=%llu",
                       pi, j, t,
                       (unsigned long long)out_scalar[j],
                       (unsigned long long)out_avx2[j]);
            }

            uint64_t inv_scalar[CAGOULE_N], inv_avx2[CAGOULE_N];
            cagoule_matrix_mul_inv_scalar(m, v, inv_scalar);
            cagoule_matrix_mul_inv(m, v, inv_avx2);

            for (int j = 0; j < CAGOULE_N; j++) {
                ASSERT(inv_scalar[j] == inv_avx2[j],
                       "Mersenne inv prime[%d] j=%d t=%d scalar=%llu avx2=%llu",
                       pi, j, t,
                       (unsigned long long)inv_scalar[j],
                       (unsigned long long)inv_avx2[j]);
            }
        }
        cagoule_matrix_free(m);
    }
}

/* ── Test 3c : Mersenne pool roundtrip P×P⁻¹=I (v2.5.2) ─────────── */
static void test_mersenne_roundtrip(void) {
    printf("  [3c] Mersenne pool roundtrip P×P⁻¹=I (8 primes)...\n");

    extern const uint64_t CAGOULE_MERSENNE_P[8];

    for (int pi = 0; pi < 8; pi++) {
        uint64_t p = CAGOULE_MERSENNE_P[pi];
        uint64_t nodes[CAGOULE_N];
        make_nodes(nodes, p);
        CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, p);
        if (!m) {
            _fail++;
            continue;
        }

        /* Verify P×P⁻¹=I for all basis vectors */
        for (int i = 0; i < CAGOULE_N; i++) {
            uint64_t v[CAGOULE_N] = {0};
            v[i] = 1;
            uint64_t fwd[CAGOULE_N], back[CAGOULE_N];
            cagoule_matrix_mul(m, v, fwd);
            cagoule_matrix_mul_inv(m, fwd, back);
            ASSERT(back[i] == 1,
                   "Mersenne R/T prime[%d] back[%d]=%llu (attendu 1)",
                   pi, i, (unsigned long long)back[i]);
            for (int j = 0; j < CAGOULE_N; j++) {
                if (j != i) {
                    ASSERT(back[j] == 0,
                           "Mersenne R/T prime[%d] back[%d]=%llu (attendu 0) i=%d",
                           pi, j, (unsigned long long)back[j], i);
                }
            }
        }
        cagoule_matrix_free(m);
    }
}

/* ── Test 4 : bench comparatif 65 536 blocs ─────────────────────── */
static void bench_65k_blocks(void) {
    printf("  [4] Bench 65 536 blocs (≡ 1 MB) — AVX2 vs scalaire...\n");

    uint64_t nodes[CAGOULE_N];
    make_nodes(nodes, P_BENCH);
    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_BENCH);
    if (!m) { printf("      SKIP — matrix build failed\n"); return; }

    uint64_t v[CAGOULE_N];
    for (int j = 0; j < CAGOULE_N; j++) v[j] = (j * 999999937ULL) % P_BENCH;
    uint64_t out[CAGOULE_N];
    int N = 65536;

    /* Scalaire */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        cagoule_matrix_mul_scalar(m, v, out);
        /* keep state alive */
        v[0] = out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double scalar_ms = (t1.tv_sec - t0.tv_sec)*1000.0
                     + (t1.tv_nsec - t0.tv_nsec)/1e6;

    /* Réinitialiser */
    for (int j = 0; j < CAGOULE_N; j++) v[j] = (j * 999999937ULL) % P_BENCH;

    /* AVX2 / dispatch */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N; i++) {
        cagoule_matrix_mul(m, v, out);
        v[0] = out[0];
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double avx2_ms = (t1.tv_sec - t0.tv_sec)*1000.0
                   + (t1.tv_nsec - t0.tv_nsec)/1e6;

    int is_avx2 = cagoule_matrix_backend_is_avx2();
    printf("      Backend actif : %s\n", is_avx2 ? "AVX2" : "scalaire");
    printf("      Scalaire      : %.2f ms (%.1f MB/s)\n",
           scalar_ms, 1.0 / (scalar_ms / 1000.0));
    printf("      Dispatch      : %.2f ms (%.1f MB/s)\n",
           avx2_ms,  1.0 / (avx2_ms  / 1000.0));
    if (avx2_ms > 0.001)
        printf("      Gain          : ×%.2f\n", scalar_ms / avx2_ms);
    
    ASSERT(out[0] < P_BENCH, "Final output < p");
    _pass++;
    cagoule_matrix_free(m);
}

/* ── main ────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════════════\n");
    printf("  test_matrix_avx2 — CAGOULE v3.1.0\n");
    printf("══════════════════════════════════════════════════\n");
    printf("  Backend AVX2 actif : %s\n",
           cagoule_matrix_backend_is_avx2() ? "✓ OUI" : "✗ NON (fallback scalaire)");

    test_roundtrip_avx2();
    test_parity_avx2_vs_scalar();
    test_symmetry();
    test_mersenne_parity();
    test_mersenne_roundtrip();
    bench_65k_blocks();

    printf("══════════════════════════════════════════════════\n");
    printf("  Résultat : %d passés, %d échoués\n", _pass, _fail);
    printf("══════════════════════════════════════════════════\n");
    return _fail == 0 ? 0 : 1;
}
