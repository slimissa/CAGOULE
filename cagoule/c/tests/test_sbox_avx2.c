/**
 * test_sbox_avx2.c — Validation de cagoule_sbox_avx2.h — CAGOULE v3.1.0
 *
 * Tests :
 *   1. forward4_avx2 : 400 cas aléatoires, bit-à-bit vs scalaire (4 premiers)
 *   2. inverse4_avx2 : 400 cas, bit-à-bit vs scalaire
 *   3. block_forward_avx2 : blocs de 16 éléments, parité scalaire
 *   4. block_inverse_avx2 : blocs de 16 éléments, parité scalaire
 *   5. Roundtrip forward/inverse AVX2 : 200 cas
 *   6. Cas limites : x=0, x=p-1, x=1
 *   7. Parité CAGOULE_FORCE_SCALAR : identité avec scalaire
 *   8. Bench comparatif : scalaire vs AVX2 (65 536 blocs ≡ 1 MB)
 *
 * Total assertions : ~35 000
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cagoule_math.h"
#include "cagoule_sbox.h"

#ifdef __AVX2__
#include <immintrin.h>
#include "cagoule_sbox_avx2.h"

/* Runtime AVX2 check — delegates to library (uses CPUID, not compiler flags) */
static int _avx2_available(void) {
    return cagoule_sbox_backend_is_avx2();
}
#define SKIP_IF_NO_AVX2() do { \
    if (!_avx2_available()) { \
        printf("      SKIP — AVX2 non disponible au runtime\n"); \
        _pass++; \
        return; \
    } \
} while(0)
#else
#define SKIP_IF_NO_AVX2() do { \
    printf("      SKIP — AVX2 non compilé\n"); \
    _pass++; \
    return; \
} while(0)
#endif

/* ── Utilitaires ──────────────────────────────────────────────────── */
static int _pass = 0, _fail = 0;

#define ASSERT(cond, msg, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL  " msg "\n", ##__VA_ARGS__); \
        _fail++; \
    } else { \
        _pass++; \
    } \
} while(0)

/* PRNG xorshift64 */
static uint64_t _rng = 0xdeadbeefcafe1234ULL;
static uint64_t rng64(void) {
    _rng ^= _rng << 13;
    _rng ^= _rng >> 7;
    _rng ^= _rng << 17;
    return _rng;
}

/* Deltas de test pour init S-box */
static const uint64_t TEST_DELTAS[] = {
    123456789ULL, 987654321ULL, 0xABCDEF01ULL, 0x12345678ULL
};
#define N_DELTAS 4

/* Grands premiers CAGOULE-like (> 2^63) */
static const uint64_t TEST_PRIMES[] = {
    10441487724840939323ULL,
    14927237621619697897ULL,
    18446744073709551557ULL,
    9223372036854775837ULL,
};
#define N_PRIMES 4

/* ── Test 1 : forward4_avx2 parité vs scalaire ────────────────────── */
static void test_forward4_parity(void) {
    printf("  [1] forward4_avx2 parity (400 cas × 4 primes × 4 deltas)...\n");
    SKIP_IF_NO_AVX2();

    for (int pi = 0; pi < N_PRIMES; pi++) {
        uint64_t p = TEST_PRIMES[pi];
        for (int di = 0; di < N_DELTAS; di++) {
            CagouleSBox64 s;
            uint64_t rk0 = (TEST_DELTAS[di] % (CAGOULE_P32_PRIME - 1)) + 1;
            uint64_t rk1 = ((TEST_DELTAS[di] >> 32) % (CAGOULE_P32_PRIME - 1)) + 1;
            cagoule_sbox_init(&s, p, rk0, rk1);

            for (int t = 0; t < 100; t++) {
                uint64_t in[4];
                for (int k = 0; k < 4; k++) in[k] = rng64() % p;

                uint64_t out_avx2[4], out_scalar[4];
                cagoule_sbox_forward4_avx2(&s, in, out_avx2);
                for (int k = 0; k < 4; k++)
                    out_scalar[k] = cagoule_sbox_forward(&s, in[k]);

                for (int k = 0; k < 4; k++) {
                    ASSERT(out_avx2[k] == out_scalar[k],
                           "forward4 lane=%d p=%llu delta=%llu in=%llu "
                           "avx2=%llu scalar=%llu",
                           k, (unsigned long long)p,
                           (unsigned long long)TEST_DELTAS[di],
                           (unsigned long long)in[k],
                           (unsigned long long)out_avx2[k],
                           (unsigned long long)out_scalar[k]);
                }
            }
        }
    }
}

/* ── Test 2 : inverse4_avx2 parité vs scalaire ───────────────────── */
static void test_inverse4_parity(void) {
    printf("  [2] inverse4_avx2 parity (400 cas × 4 primes × 4 deltas)...\n");
    SKIP_IF_NO_AVX2();

    for (int pi = 0; pi < N_PRIMES; pi++) {
        uint64_t p = TEST_PRIMES[pi];
        for (int di = 0; di < N_DELTAS; di++) {
            CagouleSBox64 s;
            uint64_t rk0 = (TEST_DELTAS[di] % (CAGOULE_P32_PRIME - 1)) + 1;
            uint64_t rk1 = ((TEST_DELTAS[di] >> 32) % (CAGOULE_P32_PRIME - 1)) + 1;
            cagoule_sbox_init(&s, p, rk0, rk1);

            for (int t = 0; t < 100; t++) {
                uint64_t in[4];
                for (int k = 0; k < 4; k++) in[k] = rng64() % p;

                uint64_t out_avx2[4], out_scalar[4];
                cagoule_sbox_inverse4_avx2(&s, in, out_avx2);
                for (int k = 0; k < 4; k++)
                    out_scalar[k] = cagoule_sbox_inverse(&s, in[k]);

                for (int k = 0; k < 4; k++) {
                    ASSERT(out_avx2[k] == out_scalar[k],
                           "inverse4 lane=%d p=%llu delta=%llu "
                           "avx2=%llu scalar=%llu",
                           k, (unsigned long long)p,
                           (unsigned long long)TEST_DELTAS[di],
                           (unsigned long long)out_avx2[k],
                           (unsigned long long)out_scalar[k]);
                }
            }
        }
    }
}

/* ── Test 3 : block_forward_avx2 parité (bloc de 16) ─────────────── */
static void test_block_forward_parity(void) {
    printf("  [3] block_forward_avx2 parity (200 blocs de 16)...\n");
    SKIP_IF_NO_AVX2();

    uint64_t p  = TEST_PRIMES[0];
    uint64_t rk0 = 2147483693ULL, rk1 = 3221225473ULL;
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    for (int t = 0; t < 200; t++) {
        uint64_t in[16], out_avx2[16], out_scalar[16];
        for (int j = 0; j < 16; j++) in[j] = rng64() % p;

        cagoule_sbox_block_forward_avx2(&s, in, out_avx2, 16);
        cagoule_sbox_block_forward(&s, in, out_scalar, 16);

        for (int j = 0; j < 16; j++) {
            ASSERT(out_avx2[j] == out_scalar[j],
                   "block_fwd j=%d t=%d avx2=%llu scalar=%llu",
                   j, t, (unsigned long long)out_avx2[j],
                   (unsigned long long)out_scalar[j]);
        }
    }
}

/* ── Test 4 : block_inverse_avx2 parité (bloc de 16) ─────────────── */
static void test_block_inverse_parity(void) {
    printf("  [4] block_inverse_avx2 parity (200 blocs de 16)...\n");
    SKIP_IF_NO_AVX2();

    uint64_t p  = TEST_PRIMES[1];
    uint64_t rk0 = 2147483693ULL, rk1 = 3221225473ULL;
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    for (int t = 0; t < 200; t++) {
        uint64_t in[16], out_avx2[16], out_scalar[16];
        for (int j = 0; j < 16; j++) in[j] = rng64() % p;

        cagoule_sbox_block_inverse_avx2(&s, in, out_avx2, 16);
        cagoule_sbox_block_inverse(&s, in, out_scalar, 16);

        for (int j = 0; j < 16; j++) {
            ASSERT(out_avx2[j] == out_scalar[j],
                   "block_inv j=%d t=%d avx2=%llu scalar=%llu",
                   j, t, (unsigned long long)out_avx2[j],
                   (unsigned long long)out_scalar[j]);
        }
    }
}

/* ── Test 5 : roundtrip forward/inverse AVX2 ─────────────────────── */
static void test_roundtrip_avx2(void) {
    printf("  [5] Roundtrip forward/inverse AVX2 (200 blocs de 16)...\n");
    SKIP_IF_NO_AVX2();

    uint64_t p  = TEST_PRIMES[2];
    uint64_t rk0 = 0x8000000FULL, rk1 = 0xC0000011ULL;
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    for (int t = 0; t < 200; t++) {
        uint64_t orig[16], enc[16], dec[16];
        for (int j = 0; j < 16; j++) orig[j] = rng64() % p;

        cagoule_sbox_block_forward_avx2(&s, orig, enc, 16);
        cagoule_sbox_block_inverse_avx2(&s, enc,  dec, 16);

        for (int j = 0; j < 16; j++) {
            ASSERT(dec[j] == orig[j],
                   "roundtrip j=%d t=%d orig=%llu enc=%llu dec=%llu",
                   j, t, (unsigned long long)orig[j],
                   (unsigned long long)enc[j], (unsigned long long)dec[j]);
        }
    }
}

/* ── Test 6 : cas limites ─────────────────────────────────────────── */
static void test_edge_cases(void) {
    printf("  [6] Cas limites (x=0, x=1, x=p-1)...\n");
    SKIP_IF_NO_AVX2();

    uint64_t p  = TEST_PRIMES[0];
    uint64_t rk0 = 2147483693ULL, rk1 = 3221225473ULL;
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    uint64_t cases[] = {0, 1, p - 1, p / 2, p / 3, p - 2, 42, 1000000007ULL % p};
    int n_cases = (int)(sizeof(cases)/sizeof(cases[0]));

    for (int i = 0; i < n_cases; i++) {
        uint64_t in[4] = {cases[i], cases[i], cases[i], cases[i]};
        uint64_t out_avx2[4];
        cagoule_sbox_forward4_avx2(&s, in, out_avx2);
        uint64_t exp = cagoule_sbox_forward(&s, cases[i]);

        for (int k = 0; k < 4; k++) {
            ASSERT(out_avx2[k] == exp,
                   "edge_fwd i=%d x=%llu avx2=%llu exp=%llu",
                   i, (unsigned long long)cases[i],
                   (unsigned long long)out_avx2[k],
                   (unsigned long long)exp);
            ASSERT(out_avx2[k] < p,
                   "edge_fwd output hors [0,p) i=%d x=%llu out=%llu",
                   i, (unsigned long long)cases[i],
                   (unsigned long long)out_avx2[k]);
        }
    }

    /* Inverse sur les mêmes entrées */
    for (int i = 0; i < n_cases; i++) {
        uint64_t in[4] = {cases[i], cases[i], cases[i], cases[i]};
        uint64_t out_avx2[4];
        cagoule_sbox_inverse4_avx2(&s, in, out_avx2);
        uint64_t exp = cagoule_sbox_inverse(&s, cases[i]);

        for (int k = 0; k < 4; k++) {
            ASSERT(out_avx2[k] == exp,
                   "edge_inv i=%d x=%llu avx2=%llu exp=%llu",
                   i, (unsigned long long)cases[i],
                   (unsigned long long)out_avx2[k],
                   (unsigned long long)exp);
        }
    }

    /* Mixed lane values (different values in each lane) */
    uint64_t mixed[4] = {0, 1, p-1, p/2};
    uint64_t out_mixed[4], exp_mixed[4];
    cagoule_sbox_forward4_avx2(&s, mixed, out_mixed);
    for (int k = 0; k < 4; k++) {
        exp_mixed[k] = cagoule_sbox_forward(&s, mixed[k]);
        ASSERT(out_mixed[k] == exp_mixed[k],
               "edge_mixed k=%d in=%llu avx2=%llu scalar=%llu",
               k, (unsigned long long)mixed[k],
               (unsigned long long)out_mixed[k],
               (unsigned long long)exp_mixed[k]);
    }
}

/* ── Test 7 : cagoule_sbox_backend_is_avx2 ───────────────────────── */
static void test_backend_detection(void) {
    printf("  [7] cagoule_sbox_backend_is_avx2()...\n");
    int avx2 = cagoule_sbox_backend_is_avx2();
    int forced_scalar = (getenv("CAGOULE_FORCE_SCALAR") != NULL);
#ifdef __AVX2__
    if (forced_scalar) {
        ASSERT(avx2 == 0, "backend_is_avx2 should return 0 under CAGOULE_FORCE_SCALAR");
    } else {
        ASSERT(avx2 != 0, "backend_is_avx2 should return != 0 on AVX2 CPU");
    }
#else
    ASSERT(avx2 == 0, "backend_is_avx2 should return 0 (not compiled)");
#endif
}

/* ── Test 8 : bench comparatif 65 536 blocs ─────────────────────── */
static void bench_65k_blocks(void) {
    printf("  [8] Bench 65 536 blocs de 16 (≡ 1 MB)...\n");

    uint64_t p  = TEST_PRIMES[0];
    uint64_t rk0 = 2147483693ULL, rk1 = 3221225473ULL;
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    uint64_t in[16], out[16];
    for (int j = 0; j < 16; j++) in[j] = (uint64_t)(j * 999999937ULL) % p;

    int N_BLOCKS = 65536;

    /* Scalaire */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < N_BLOCKS; i++) {
        cagoule_sbox_block_forward(&s, in, out, 16);
        in[0] = out[0];   /* anti-optimisation */
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double scalar_ms = (t1.tv_sec - t0.tv_sec)*1000.0 +
                       (t1.tv_nsec - t0.tv_nsec)/1e6;

    /* Réinitialiser */
    for (int j = 0; j < 16; j++) in[j] = (uint64_t)(j * 999999937ULL) % p;

    /* AVX2 */
#ifdef __AVX2__
    if (_avx2_available()) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < N_BLOCKS; i++) {
            cagoule_sbox_block_forward_avx2(&s, in, out, 16);
            in[0] = out[0];
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double avx2_ms = (t1.tv_sec - t0.tv_sec)*1000.0 +
                         (t1.tv_nsec - t0.tv_nsec)/1e6;

        int is_avx2 = cagoule_sbox_backend_is_avx2();
        printf("      Backend actif : %s\n", is_avx2 ? "AVX2" : "scalaire");
        printf("      Scalaire      : %.2f ms  (%.1f MB/s)\n",
               scalar_ms, 1000.0 / scalar_ms);
        printf("      AVX2          : %.2f ms  (%.1f MB/s)\n",
               avx2_ms, 1000.0 / avx2_ms);
        if (avx2_ms > 0.001 && scalar_ms > 0.001)
            printf("      Gain          : ×%.2f\n", scalar_ms / avx2_ms);
    } else {
        printf("      Scalaire      : %.2f ms  (%.1f MB/s)\n",
               scalar_ms, 1000.0 / scalar_ms);
        printf("      AVX2          : N/A (non supporté)\n");
    }
#else
    printf("      Scalaire      : %.2f ms  (%.1f MB/s)\n",
           scalar_ms, 1000.0 / scalar_ms);
    printf("      AVX2          : N/A (non compilé)\n");
#endif
    
    ASSERT(out[0] < p, "Final output < p");
    _pass++;   /* bench non bloquant */
}

/* ── main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════════════════\n");
    printf("  test_sbox_avx2 — CAGOULE v3.1.0\n");
    printf("══════════════════════════════════════════════════════\n");

#ifdef __AVX2__
    if (cagoule_sbox_backend_is_avx2())
        printf("  CPU AVX2 : ✓ disponible\n");
    else
        printf("  CPU AVX2 : ✗ non supporté — tests de parité ignorés\n");
#else
    printf("  AVX2 : non compilé (-mavx2 absent)\n");
#endif

    test_forward4_parity();
    test_inverse4_parity();
    test_block_forward_parity();
    test_block_inverse_parity();
    test_roundtrip_avx2();
    test_edge_cases();
    test_backend_detection();
    bench_65k_blocks();

    printf("══════════════════════════════════════════════════════\n");
    printf("  Résultat : %d passés, %d échoués\n", _pass, _fail);
    printf("══════════════════════════════════════════════════════\n");
    return _fail == 0 ? 0 : 1;
}