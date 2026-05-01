/**
 * test_sbox.c — Tests unitaires pour cagoule_sbox.c
 *
 * Usage : gcc -std=c99 -O2 -Iinclude src/cagoule_sbox.c
 *               tests/test_sbox.c -o test_sbox && ./test_sbox
 */

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "cagoule_math.h"
#include "cagoule_sbox.h"

static int _passed = 0, _failed = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ✓ %s\n", msg); _passed++; } \
    else      { printf("  ✗ FAIL: %s (line %d)\n", msg, __LINE__); _failed++; } \
} while(0)

static const uint64_t P_BENCH = 10441487724840939323ULL;
static const uint64_t RK0     = 2147483693ULL;
static const uint64_t RK1     = 3221225473ULL;

/* ── Bijectivité pour petits p ────────────────────────────────────── */
static void test_bijective_small(uint64_t p, uint64_t rk0, uint64_t rk1) {
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    uint8_t seen[256] = {0};
    int ok = 1;
    for (uint64_t x = 0; x < p && x < 256; x++) {
        uint64_t y = cagoule_sbox_forward(&s, x);
        if (y >= p || seen[y]) { ok = 0; break; }
        seen[y] = 1;
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "bijectif (p=%llu, type=%s)",
             (unsigned long long)p, s.use_feistel ? "Feistel" : "x^d");
    CHECK(ok, msg);
}

/* ── Roundtrip forward/inverse ────────────────────────────────────── */
static void test_roundtrip(uint64_t p, uint64_t rk0, uint64_t rk1,
                            int n_samples, const char* label)
{
    CagouleSBox64 s;
    cagoule_sbox_init(&s, p, rk0, rk1);

    int ok = 1;
    for (int i = 0; i < n_samples; i++) {
        uint64_t x = (uint64_t)((i * 1234567891011ULL + 42) % p);
        uint64_t y = cagoule_sbox_forward(&s, x);
        uint64_t x2 = cagoule_sbox_inverse(&s, y);
        if (x2 != x) { ok = 0; break; }
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "roundtrip inv(fwd(x))==x (%s)", label);
    CHECK(ok, msg);
}

/* ── Test symétrie (CORRIGÉ : plus de double comptage) ────────────── */
static void test_feistel_symmetry(void) {
    printf("\n[Feistel : coût forward ≈ inverse]\n");

    CagouleSBox64 s;
    cagoule_sbox_init(&s, P_BENCH, RK0, RK1);
    CHECK(s.use_feistel == 1, "use_feistel=1 pour P_bench");

    int N = 1048576;  /* 1M d'éléments */

    clock_t t0 = clock();
    volatile uint64_t r = 0;
    for (int i = 0; i < N; i++)
        r = cagoule_sbox_forward(&s, (uint64_t)i % P_BENCH);
    double fwd_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;

    t0 = clock();
    for (int i = 0; i < N; i++)
        r = cagoule_sbox_inverse(&s, (uint64_t)i % P_BENCH);
    double inv_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;
    (void)r;

    printf("  Forward  1M appels : %.2f ms\n", fwd_ms);
    printf("  Inverse  1M appels : %.2f ms\n", inv_ms);
    if (fwd_ms > 0.5)
        printf("  Ratio inv/fwd      : %.2f×\n", inv_ms / fwd_ms);
    else
        printf("  Ratio inv/fwd      : N/A (forward rapide)\n");
    printf("  [Objectif v2.0.0   : ratio < 3×]\n");

    int ratio_ok = (fwd_ms < 0.5) || (inv_ms / fwd_ms < 5.0);
    CHECK(ratio_ok, "ratio inv/fwd raisonnable (< 5× ou fwd rapide)");
    /* SUPPRESSION du _passed++ ici (déjà fait par CHECK) */
}

/* ── Test bloc ────────────────────────────────────────────────────── */
static void test_block(void) {
    printf("\n[Block operations]\n");
    CagouleSBox64 s;
    cagoule_sbox_init(&s, P_BENCH, RK0, RK1);

    uint64_t block[16], enc[16], dec[16];
    for (int i = 0; i < 16; i++)
        block[i] = (uint64_t)(i * 1000000007ULL % P_BENCH);

    cagoule_sbox_block_forward(&s, block, enc, 16);
    cagoule_sbox_block_inverse(&s, enc, dec, 16);

    int ok = 1;
    for (int i = 0; i < 16; i++)
        if (dec[i] != block[i]) { ok = 0; break; }
    CHECK(ok, "block forward/inverse roundtrip (n=16)");

    int changed = 0;
    for (int i = 0; i < 16; i++)
        if (enc[i] != block[i]) { changed = 1; break; }
    CHECK(changed, "forward(block) != block (S-box non triviale)");
}

/* ── Fallback x^d pour petits p ───────────────────────────────────── */
static void test_small_prime_fallback(void) {
    printf("\n[Fallback x^d pour petits premiers]\n");
    uint64_t small_primes[] = {5, 7, 11, 13, 17, 23, 97};
    int n = sizeof(small_primes) / sizeof(small_primes[0]);
    for (int i = 0; i < n; i++) {
        uint64_t p = small_primes[i];
        CagouleSBox64 s;
        cagoule_sbox_init(&s, p, RK0, RK1);
        char msg[64];
        snprintf(msg, sizeof(msg), "use_feistel=0 (p=%llu)", (unsigned long long)p);
        CHECK(s.use_feistel == 0, msg);
        test_bijective_small(p, RK0, RK1);
        test_roundtrip(p, RK0, RK1, (int)p, msg);
    }
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════\n");
    printf("  CAGOULE v2.0.0 — test_sbox.c\n");
    printf("══════════════════════════════════════════\n");

    test_small_prime_fallback();

    printf("\n[Feistel — grand premier (p≈2^64)]\n");
    test_roundtrip(P_BENCH, RK0, RK1, 100000, "P_bench 100K samples");
    test_roundtrip(65537,   RK0, RK1, 65537,  "p=65537 exhaustif");

    test_block();
    test_feistel_symmetry();

    printf("\n──────────────────────────────────────────\n");
    printf("  ✅ %d passés  ❌ %d échoués\n", _passed, _failed);
    printf("══════════════════════════════════════════\n");
    return _failed == 0 ? 0 : 1;
}