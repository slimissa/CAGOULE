/**
 * test_math.c — Tests unitaires pour cagoule_math.h
 *
 * Usage : gcc -std=c99 -Iinclude tests/test_math.c -o test_math && ./test_math
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "cagoule_math.h"

static int _passed = 0, _failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { printf("  ✓ %s\n", msg); _passed++; } \
    else      { printf("  ✗ FAIL: %s (line %d)\n", msg, __LINE__); _failed++; } \
} while(0)

/* Nombre premier de référence pour les tests */
static const uint64_t P = 10441487724840939323ULL;
static const uint64_t P_SMALL = 97;

/* ── Tests mulmod64 ────────────────────────────────────────────────── */
static void test_mulmod64(void) {
    printf("\n[mulmod64]\n");

    CHECK(mulmod64(0, 12345, P) == 0,      "0 * x = 0");
    CHECK(mulmod64(1, 12345, P) == 12345,  "1 * x = x");
    CHECK(mulmod64(2, 3, 7) == 6,          "2 * 3 mod 7 = 6");
    CHECK(mulmod64(5, 5, 7) == 4,          "5 * 5 mod 7 = 4");

    uint64_t big = P - 1;
    uint64_t r = mulmod64(big, big, P);
    CHECK(r < P, "mulmod64(P-1, P-1, P) < P");

    uint64_t a = 123456789ULL, b = 987654321ULL;
    CHECK(mulmod64(a, b, P) == mulmod64(b, a, P), "mulmod64 commutatif");
}

/* ── Tests addmod64 / submod64 (version optimisée) ─────────────────── */
static void test_addmod(void) {
    printf("\n[addmod64 / submod64]\n");

    CHECK(addmod64(3, 4, 7) == 0,          "3 + 4 mod 7 = 0");
    CHECK(addmod64(0, 0, P) == 0,          "0 + 0 = 0");
    CHECK(addmod64(P-1, 1, P) == 0,        "(P-1) + 1 mod P = 0");
    CHECK(submod64(4, 3, 7) == 1,          "4 - 3 mod 7 = 1");
    CHECK(submod64(3, 4, 7) == 6,          "3 - 4 mod 7 = 6 (wrap)");
    CHECK(submod64(0, 1, P) == P - 1,      "0 - 1 mod P = P-1");
    CHECK(addmod64(5, submod64(5, 3, 7), 7) == 0, "add(5, sub(5,3)) mod 7 = 0");

    CHECK(negmod64(0, P) == 0, "neg(0) = 0");
    CHECK(negmod64(1, P) == P - 1, "neg(1) = P-1");
}

/* ── Tests powmod64 ─────────────────────────────────────────────────── */
static void test_powmod64(void) {
    printf("\n[powmod64]\n");

    CHECK(powmod64(2, 0, P) == 1,          "2^0 = 1");
    CHECK(powmod64(2, 1, P) == 2,          "2^1 = 2");
    CHECK(powmod64(2, 10, 1025) == 1024,   "2^10 = 1024");
    CHECK(powmod64(3, 3, 7) == 6,          "3^3 mod 7 = 6");

    CHECK(powmod64(42, P_SMALL - 1, P_SMALL) == 1, "Fermat: a^(p-1)≡1 mod 97");
}

/* ── Tests invmod64 ─────────────────────────────────────────────────── */
static void test_invmod64(void) {
    printf("\n[invmod64]\n");

    for (uint64_t a = 1; a <= 96; a++) {
        uint64_t inv = invmod64(a, P_SMALL);
        CHECK(mulmod64(a, inv, P_SMALL) == 1, "a * a^-1 = 1 (p=97)");
    }

    uint64_t a = 123456789012345ULL % P + 1;
    uint64_t inv_a = invmod64(a, P);
    CHECK(mulmod64(a, inv_a, P) == 1, "invmod64 sur grand P");
}


/* ── Tests Mersenne-64 Pool (v2.5.1) ──────────────────────────────── */
static void test_mersenne_pool(void) {
    printf("\n[Mersenne-64 Pool]\n");

    /* Verify each pool prime returns correct k */
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
        uint64_t p = CAGOULE_MERSENNE_P[i];
        uint64_t k = CAGOULE_MERSENNE_K[i];
        uint64_t k_lookup = cagoule_mersenne_k(p);
        char msg[80];
        snprintf(msg, sizeof(msg), "cagoule_mersenne_k(2^64-%llu)=%llu",
                 (unsigned long long)k, (unsigned long long)k);
        CHECK(k_lookup == k, msg);
    }

    /* Non-Mersenne primes return 0 */
    CHECK(cagoule_mersenne_k(P) == 0, "non-Mersenne prime P_bench → k=0");
    CHECK(cagoule_mersenne_k(97) == 0, "small prime 97 → k=0");
    CHECK(cagoule_mersenne_k(2) == 0, "p=2 → k=0");
    CHECK(cagoule_mersenne_k(3) == 0, "p=3 → k=0");
    CHECK(cagoule_mersenne_k(65537) == 0, "p=65537 → k=0");

    /* Verify all pool primes are valid (p = 2^64 - k) */
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
        uint64_t p = CAGOULE_MERSENNE_P[i];
        uint64_t k = CAGOULE_MERSENNE_K[i];
        char msg[80];
        snprintf(msg, sizeof(msg), "pool[%d] 2^64-%llu < 2^64", i, (unsigned long long)k);
        CHECK(p == 18446744073709551615ULL - k + 1, msg);
    }

    /* Verify k values are in valid range (k < 2^10) */
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
        uint64_t k = CAGOULE_MERSENNE_K[i];
        char msg[80];
        snprintf(msg, sizeof(msg), "pool[%d] k=%llu < 1024", i, (unsigned long long)k);
        CHECK(k < 1024, msg);
    }

    /* Verify all pool primes are distinct */
    int distinct = 1;
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
        for (int j = i + 1; j < CAGOULE_MERSENNE_POOL_SIZE; j++) {
            if (CAGOULE_MERSENNE_P[i] == CAGOULE_MERSENNE_P[j]) {
                distinct = 0;
                break;
            }
        }
    }
    CHECK(distinct, "all Mersenne pool primes are distinct");
}

/* ── Benchmark corrigé (ns/op précis) ─────────────────────────────── */
static void bench_mulmod(void) {
    printf("\n[bench mulmod64 — 10M itérations]\n");
    volatile uint64_t r = 1;
    clock_t t0 = clock();
    for (int i = 0; i < 10000000; i++)
        r = mulmod64(r + 1, r + 2, P);
    double ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;
    double ns_per_op = (ms * 1000000.0) / 10000000.0;
    printf("  10M mulmod64 : %.2f ms  (%.1f ns/op)\n", ms, ns_per_op);
    printf("  [Cible : < 10 ns/op sur x86_64 moderne]\n");
    
    /* Vérification de performance (optionnelle) */
    if (ns_per_op > 50.0) {
        printf("  ⚠️  Performance faible (>50 ns/op)\n");
    } else {
        printf("  ✓ Performance acceptable\n");
    }
    (void)r;
    /* Ne pas incrémenter _passed automatiquement pour un bench */
}

/* ── Main ───────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════\n");
    printf("  CAGOULE v3.0.0 — test_math.c\n");
    printf("══════════════════════════════════════════\n");

    test_mulmod64();
    test_addmod();
    test_powmod64();
    test_invmod64();
    test_mersenne_pool();
    bench_mulmod();

    printf("\n──────────────────────────────────────────\n");
    printf("  ✅ %d passés  ❌ %d échoués\n", _passed, _failed);
    printf("══════════════════════════════════════════\n");
    return _failed == 0 ? 0 : 1;
}