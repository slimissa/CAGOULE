    /**
     * test_math_avx2.c — Validation de cagoule_math_avx2.h
     *                     CAGOULE v3.1.0
     *
     * Tests :
     *   1. mulmod64x4 : 512 cas aléatoires, bit-à-bit vs mulmod64 scalaire
     *   2. addmod64x4 : 256 cas aléatoires
     *   3. submod64x4 : 256 cas aléatoires
     *   4. Cas limites : a=0, b=0, a=p-1, b=p-1, a=b=p/2
     *   5. Barrett µ
     *   5b. mulmod_mersenne64x4 parity (512×8 primes×4 lanes)
     *   5c. Mersenne edge cases (8 primes×5 edges×4 lanes) : vérification de la formule floor(2^127/p)
     *   6. Bench comparatif : AVX2 vs scalaire (cycles estimés)
     *
     * Usage :
     *   gcc -O2 -std=c99 -mavx2 -Iinclude tests/test_math_avx2.c \
     *       -o test_math_avx2 && ./test_math_avx2
     */


    #include <stdio.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <time.h>

    #include "cagoule_math.h"

    #ifdef __AVX2__
    #include "cagoule_math_avx2.h"
    #include <immintrin.h>

    /* Runtime AVX2 check — returns 1 if CPU supports AVX2 */
    static int _avx2_available(void) {
        return __builtin_cpu_supports("avx2");
    }
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

    /* PRNG simple (xorshift64) pour éviter toute dépendance */
    static uint64_t _rng = 0xdeadbeefcafebabe;
    static uint64_t rng64(void) {
        _rng ^= _rng << 13;
        _rng ^= _rng >> 7;
        _rng ^= _rng << 17;
        return _rng;
    }

    /* Premiers CAGOULE-like (≥ 2^63, premiers) pour les tests */
    static const uint64_t TEST_PRIMES[] = {
        10441487724840939323ULL,   /* 64-bit premier > 2^63 */
        14927237621619697897ULL,   /* autre premier */
        18446744073709551557ULL,   /* plus grand premier < 2^64 */
        9223372036854775837ULL,    /* 2^63 + 45 (premier) */
    };
    #define N_PRIMES 4

    /* ── Helpers pour extraire les 4 lanes d'un __m256i ──────────────── */
    #ifdef __AVX2__
    static void m256i_to_u64(const __m256i v, uint64_t out[4]) {
        _mm256_storeu_si256((__m256i*)out, v);  /* unaligned store (safe) */
    }
    #endif

    /* ── Test 1 : mulmod64x4 bit-exact vs scalaire ───────────────────── */
    static void test_mulmod_parity(void) {
        printf("  [1] mulmod64x4 parity (512 random cases × 4 primes)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        for (int pi = 0; pi < N_PRIMES; pi++) {
            uint64_t p = TEST_PRIMES[pi];
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
            uint64_t mu = cagoule_barrett_mu(p);

            for (int i = 0; i < 512; i++) {
                uint64_t a[4], b[4];
                for (int k = 0; k < 4; k++) {
                    a[k] = rng64() % p;
                    b[k] = rng64() % p;
                }
                __m256i va = _mm256_set_epi64x(
                    (int64_t)a[3], (int64_t)a[2], (int64_t)a[1], (int64_t)a[0]);
                __m256i vb = _mm256_set_epi64x(
                    (int64_t)b[3], (int64_t)b[2], (int64_t)b[1], (int64_t)b[0]);

                __m256i res = mulmod64x4(va, vb, p_vec, mu);
                uint64_t got[4];
                m256i_to_u64(res, got);

                for (int k = 0; k < 4; k++) {
                    uint64_t expected = mulmod64(a[k], b[k], p);
                    if (got[k] != expected) {
                        fprintf(stderr, "  FAIL  mulmod64x4 lane=%d a=%llu b=%llu p=%llu "
                                "got=%llu expected=%llu\n",
                                k, (unsigned long long)a[k], (unsigned long long)b[k],
                                (unsigned long long)p, (unsigned long long)got[k],
                                (unsigned long long)expected);
                        _fail++;
                    } else {
                        _pass++;
                    }
                }
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 2 : addmod64x4 ─────────────────────────────────────────── */
    static void test_addmod_parity(void) {
        printf("  [2] addmod64x4 parity (256 cases × 4 primes)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        for (int pi = 0; pi < N_PRIMES; pi++) {
            uint64_t p = TEST_PRIMES[pi];
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);

            for (int i = 0; i < 256; i++) {
                uint64_t a[4], b[4];
                for (int k = 0; k < 4; k++) {
                    a[k] = rng64() % p;
                    b[k] = rng64() % p;
                }
                __m256i va = _mm256_set_epi64x(
                    (int64_t)a[3], (int64_t)a[2], (int64_t)a[1], (int64_t)a[0]);
                __m256i vb = _mm256_set_epi64x(
                    (int64_t)b[3], (int64_t)b[2], (int64_t)b[1], (int64_t)b[0]);

                __m256i res = addmod64x4(va, vb, p_vec);
                uint64_t got[4];
                m256i_to_u64(res, got);

                for (int k = 0; k < 4; k++) {
                    uint64_t expected = addmod64(a[k], b[k], p);
                    if (got[k] != expected) {
                        fprintf(stderr, "  FAIL  addmod64x4 lane=%d a=%llu b=%llu p=%llu "
                                "got=%llu exp=%llu\n",
                                k, (unsigned long long)a[k], (unsigned long long)b[k],
                                (unsigned long long)p, (unsigned long long)got[k],
                                (unsigned long long)expected);
                        _fail++;
                    } else {
                        _pass++;
                    }
                }
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 3 : submod64x4 ─────────────────────────────────────────── */
    static void test_submod_parity(void) {
        printf("  [3] submod64x4 parity (256 cases × 4 primes)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        for (int pi = 0; pi < N_PRIMES; pi++) {
            uint64_t p = TEST_PRIMES[pi];
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);

            for (int i = 0; i < 256; i++) {
                uint64_t a[4], b[4];
                for (int k = 0; k < 4; k++) {
                    a[k] = rng64() % p;
                    b[k] = rng64() % p;
                }
                __m256i va = _mm256_set_epi64x(
                    (int64_t)a[3], (int64_t)a[2], (int64_t)a[1], (int64_t)a[0]);
                __m256i vb = _mm256_set_epi64x(
                    (int64_t)b[3], (int64_t)b[2], (int64_t)b[1], (int64_t)b[0]);

                __m256i res = submod64x4(va, vb, p_vec);
                uint64_t got[4];
                m256i_to_u64(res, got);

                for (int k = 0; k < 4; k++) {
                    uint64_t expected = submod64(a[k], b[k], p);
                    if (got[k] != expected) {
                        fprintf(stderr, "  FAIL  submod64x4 lane=%d a=%llu b=%llu p=%llu "
                                "got=%llu exp=%llu\n",
                                k, (unsigned long long)a[k], (unsigned long long)b[k],
                                (unsigned long long)p, (unsigned long long)got[k],
                                (unsigned long long)expected);
                        _fail++;
                    } else {
                        _pass++;
                    }
                }
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 4 : cas limites ────────────────────────────────────────── */
    static void test_edge_cases(void) {
        printf("  [4] Edge cases (a=0, b=0, a=p-1, b=p-1, a=b=p/2)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        uint64_t p = TEST_PRIMES[0];
        __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
        uint64_t mu = cagoule_barrett_mu(p);

        struct { uint64_t a, b; } cases[] = {
            {0, 0}, {0, p-1}, {p-1, 0}, {p-1, p-1},
            {1, p-1}, {p-1, 1}, {p/2, p/2}, {1, 1},
        };
        int n = sizeof(cases) / sizeof(cases[0]);

        for (int i = 0; i < n; i++) {
            uint64_t a = cases[i].a, b = cases[i].b;
            __m256i va = _mm256_set1_epi64x((int64_t)a);
            __m256i vb = _mm256_set1_epi64x((int64_t)b);

            /* mulmod */
            uint64_t got[4];
            m256i_to_u64(mulmod64x4(va, vb, p_vec, mu), got);
            uint64_t exp = mulmod64(a, b, p);
            for (int k = 0; k < 4; k++) {
                ASSERT(got[k] == exp,
                    "edge mulmod a=%llu b=%llu lane=%d got=%llu exp=%llu",
                    (unsigned long long)a, (unsigned long long)b, k,
                    (unsigned long long)got[k], (unsigned long long)exp);
            }

            /* addmod */
            m256i_to_u64(addmod64x4(va, vb, p_vec), got);
            exp = addmod64(a, b, p);
            for (int k = 0; k < 4; k++) {
                ASSERT(got[k] == exp,
                    "edge addmod a=%llu b=%llu lane=%d got=%llu exp=%llu",
                    (unsigned long long)a, (unsigned long long)b, k,
                    (unsigned long long)got[k], (unsigned long long)exp);
            }

            /* submod */
            m256i_to_u64(submod64x4(va, vb, p_vec), got);
            exp = submod64(a, b, p);
            for (int k = 0; k < 4; k++) {
                ASSERT(got[k] == exp,
                    "edge submod a=%llu b=%llu lane=%d got=%llu exp=%llu",
                    (unsigned long long)a, (unsigned long long)b, k,
                    (unsigned long long)got[k], (unsigned long long)exp);
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 5 : Barrett µ ──────────────────────────────────────────── */
    static void test_barrett_mu(void) {
        printf("  [5] Barrett µ = floor(2^127 / p)...\n");
        for (int pi = 0; pi < N_PRIMES; pi++) {
            uint64_t p = TEST_PRIMES[pi];
            uint64_t mu = cagoule_barrett_mu(p);
            /* Vérification : mu * p ≤ 2^127 < (mu+1) * p */
            __uint128_t mu128  = (__uint128_t)mu;
            __uint128_t p128   = (__uint128_t)p;
            __uint128_t two127 = (__uint128_t)1 << 127;
            ASSERT(mu128 * p128 <= two127,
                "Barrett µ lower bound failed p=%llu", (unsigned long long)p);
            ASSERT((mu128 + 1) * p128 > two127,
                "Barrett µ upper bound failed p=%llu", (unsigned long long)p);
        }
    }


    /* ── Test 5b : mulmod_mersenne64x4 parity vs scalaire (v2.5.2) ────── */
    static void test_mersenne_parity(void) {
        printf("  [5b] mulmod_mersenne64x4 parity (512 cases × 8 Mersenne primes)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        /* Use the Mersenne pool from cagoule_math.h */
        extern const uint64_t CAGOULE_MERSENNE_K[8];
        extern const uint64_t CAGOULE_MERSENNE_P[8];

        for (int pi = 0; pi < 8; pi++) {
            uint64_t p = CAGOULE_MERSENNE_P[pi];
            uint64_t k = CAGOULE_MERSENNE_K[pi];
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
            __m256i k_vec = _mm256_set1_epi64x((int64_t)k);

            int ok = 0;
            for (int i = 0; i < 512; i++) {
                uint64_t a[4], b[4];
                for (int j = 0; j < 4; j++) {
                    a[j] = rng64() % p;
                    b[j] = rng64() % p;
                }
                __m256i va = _mm256_set_epi64x(
                    (int64_t)a[3], (int64_t)a[2], (int64_t)a[1], (int64_t)a[0]);
                __m256i vb = _mm256_set_epi64x(
                    (int64_t)b[3], (int64_t)b[2], (int64_t)b[1], (int64_t)b[0]);

                __m256i res = mulmod_mersenne64x4(va, vb, p_vec, k_vec);
                uint64_t got[4];
                m256i_to_u64(res, got);

                for (int j = 0; j < 4; j++) {
                    uint64_t expected = mulmod64(a[j], b[j], p);
                    if (got[j] == expected && got[j] < p) {
                        _pass++;
                        ok++;
                    } else {
                        _fail++;
                        if (_fail <= 4) {
                            fprintf(stderr, "  FAIL  mersenne parity prime[%d] k=%llu "
                                    "lane=%d a=%llu b=%llu got=%llu exp=%llu\n",
                                    pi, (unsigned long long)k, j,
                                    (unsigned long long)a[j], (unsigned long long)b[j],
                                    (unsigned long long)got[j], (unsigned long long)expected);
                        }
                    }
                }
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 5c : Mersenne edge cases (v2.5.2) ──────────────────────── */
    static void test_mersenne_edge_cases(void) {
        printf("  [5c] Mersenne edge cases (a=0, b=0, a=p-1, b=p-1)...\n");
    #ifdef __AVX2__
        if (!_avx2_available()) {
            printf("      SKIP — AVX2 non disponible au runtime\n");
            _pass++;
            return;
        }

        extern const uint64_t CAGOULE_MERSENNE_K[8];
        extern const uint64_t CAGOULE_MERSENNE_P[8];

        for (int pi = 0; pi < 8; pi++) {
            uint64_t p = CAGOULE_MERSENNE_P[pi];
            uint64_t k = CAGOULE_MERSENNE_K[pi];
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
            __m256i k_vec = _mm256_set1_epi64x((int64_t)k);

            /* Test critical edge values for each prime */
            uint64_t edges[] = {0, 1, p-1, p/2, p-2};
            for (int ei = 0; ei < 5; ei++) {
                uint64_t a = edges[ei];
                uint64_t b = edges[(ei + 1) % 5];
                __m256i va = _mm256_set1_epi64x((int64_t)a);
                __m256i vb = _mm256_set1_epi64x((int64_t)b);
                __m256i res = mulmod_mersenne64x4(va, vb, p_vec, k_vec);
                uint64_t got[4];
                m256i_to_u64(res, got);
                uint64_t exp = mulmod64(a, b, p);
                for (int j = 0; j < 4; j++) {
                    ASSERT(got[j] == exp && got[j] < p,
                        "mersenne edge prime[%d] k=%llu a=%llu b=%llu got=%llu exp=%llu",
                        pi, (unsigned long long)k,
                        (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)got[j], (unsigned long long)exp);
                }
            }
        }
    #else
        printf("      SKIP — AVX2 non compilé\n");
        _pass++;
    #endif
    }

    /* ── Test 6 : bench comparatif ───────────────────────────────────── */
    static void bench_comparison(void) {
        printf("  [6] Bench mulmod scalaire vs AVX2 (1M iterations chacun)...\n");
        uint64_t p = TEST_PRIMES[0];
        int N = 1000000;

        /* Scalaire */
        uint64_t a = p - 12345, b = 67890;
        volatile uint64_t acc_scalar = 0;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        for (int i = 0; i < N; i++) {
            acc_scalar = mulmod64(acc_scalar + a, b, p);
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double scalar_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                        (t1.tv_nsec - t0.tv_nsec) / 1e6;

    #ifdef __AVX2__
        if (_avx2_available()) {
            __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
            uint64_t mu   = cagoule_barrett_mu(p);
            __m256i va = _mm256_set_epi64x((int64_t)(p-1), (int64_t)(p-2),
                                            (int64_t)(p-3), (int64_t)(p-4));
            __m256i vb = _mm256_set1_epi64x((int64_t)b);
            volatile uint64_t acc_avx2[4] = {0, 0, 0, 0};

            clock_gettime(CLOCK_MONOTONIC, &t0);
            for (int i = 0; i < N/4; i++) {
                __m256i r = mulmod64x4(va, vb, p_vec, mu);
                va = r;
            }
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double avx2_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                            (t1.tv_nsec - t0.tv_nsec) / 1e6;
            (void)acc_avx2;

            printf("      Scalaire : %.2f ms  |  AVX2 (×4 lanes) : %.2f ms"
                "  |  Ratio : ×%.2f\n",
                scalar_ms, avx2_ms,
                scalar_ms / (avx2_ms > 0.001 ? avx2_ms : 0.001));
        } else {
            printf("      Scalaire : %.2f ms  |  AVX2 : N/A (non supporté)\n", scalar_ms);
        }
        _pass++;
    #else
        printf("      Scalaire : %.2f ms  |  AVX2 : N/A (non compilé)\n", scalar_ms);
        _pass++;
    #endif
    }

    /* ── main ─────────────────────────────────────────────────────────── */
    int main(void) {
        printf("══════════════════════════════════════════════════\n");
        printf("  test_math_avx2 — CAGOULE v3.1.0\n");
        printf("══════════════════════════════════════════════════\n");

    #ifdef __AVX2__
        if (__builtin_cpu_supports("avx2")) {
            printf("  CPU AVX2 : ✓ disponible\n");
        } else {
            printf("  CPU AVX2 : ✗ non supporté — tests de parité skippés\n");
        }
    #else
        printf("  AVX2 : non compilé (-mavx2 absent)\n");
    #endif

        test_mulmod_parity();
        test_addmod_parity();
        test_submod_parity();
        test_edge_cases();
        test_barrett_mu();
        test_mersenne_parity();
        test_mersenne_edge_cases();
        bench_comparison();

        printf("══════════════════════════════════════════════════\n");
        printf("  Résultat : %d passés, %d échoués\n", _pass, _fail);
        printf("══════════════════════════════════════════════════\n");
        return _fail == 0 ? 0 : 1;
    }