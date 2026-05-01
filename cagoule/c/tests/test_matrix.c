/**
 * test_matrix.c — Tests unitaires pour cagoule_matrix.c
 *
 * Usage : gcc -std=c99 -O2 -Iinclude src/cagoule_matrix.c
 *               tests/test_matrix.c -o test_matrix && ./test_matrix
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"

static int _passed = 0, _failed = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ✓ %s\n", msg); _passed++; } \
    else      { printf("  ✗ FAIL: %s (line %d)\n", msg, __LINE__); _failed++; } \
} while(0)

static const uint64_t P_BENCH = 10441487724840939323ULL;
static const uint64_t P_SMALL = 65537;

static void gen_nodes(uint64_t* nodes, uint64_t p, int n) {
    for (int i = 0; i < n; i++) {
        nodes[i] = (uint64_t)(((uint64_t)(i + 1) * 7 + 3) % p);
        for (int j = 0; j < i; j++) {
            while (nodes[i] == nodes[j])
                nodes[i] = (nodes[i] + 1) % p;
        }
    }
}

/* ── Test roundtrip P × P^-1 = I ─────────────────────────────────── */
static void test_roundtrip(uint64_t p, const char* label) {
    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, p, CAGOULE_N);

    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, p);
    if (!m) {
        printf("  ✗ FAIL: build NULL (p=%s)\n", label);
        _failed++;
        return;
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "matrix_verify (p=%s)", label);
    CHECK(cagoule_matrix_verify(m) == 1, msg);

    uint64_t v[CAGOULE_N], fwd[CAGOULE_N], back[CAGOULE_N];
    for (int i = 0; i < CAGOULE_N; i++)
        v[i] = (uint64_t)((i * 123456789ULL + 987654321ULL) % p);

    cagoule_matrix_mul(m, v, fwd);
    cagoule_matrix_mul_inv(m, fwd, back);

    int eq = 1;
    for (int i = 0; i < CAGOULE_N; i++)
        if (back[i] != v[i]) { eq = 0; break; }

    snprintf(msg, sizeof(msg), "inv(fwd(v)) == v (p=%s)", label);
    CHECK(eq, msg);

    int changed = 0;
    for (int i = 0; i < CAGOULE_N; i++)
        if (fwd[i] != v[i]) { changed = 1; break; }
    snprintf(msg, sizeof(msg), "fwd(v) != v (matrice non triviale, p=%s)", label);
    CHECK(changed, msg);

    cagoule_matrix_free(m);
}

/* ── Test fallback Cauchy ─────────────────────────────────────────── */
static void test_cauchy_fallback(void) {
    printf("\n[Cauchy fallback — nœuds non distincts]\n");
    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, P_SMALL, CAGOULE_N);
    nodes[3] = nodes[1];

    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_SMALL);
    CHECK(m != NULL, "build avec collision → fallback Cauchy OK");
    if (m) {
        CHECK(m->kind == CAGOULE_MATRIX_CAUCHY, "kind == Cauchy");
        CHECK(cagoule_matrix_verify(m) == 1, "Cauchy verify OK");
        cagoule_matrix_free(m);
    }
}

/* ── Benchmark avec entrée variable (évite optimisation compilateur) ─ */
static void bench_matmul(void) {
    printf("\n[bench cagoule_matrix_mul — 65 536 blocs (≡ 1 MB)]\n");

    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, P_BENCH, CAGOULE_N);
    CagouleMatrix* m = cagoule_matrix_build(nodes, CAGOULE_N, P_BENCH);
    if (!m) { printf("  ✗ build failed\n"); _failed++; return; }

    uint64_t v[CAGOULE_N], out[CAGOULE_N];
    int N_BLOCKS = 65536;

    /* Forward avec donnée variable */
    clock_t t0 = clock();
    for (int b = 0; b < N_BLOCKS; b++) {
        for (int i = 0; i < CAGOULE_N; i++)
            v[i] = (uint64_t)((b * 7919 + i * 101) % P_BENCH);
        cagoule_matrix_mul(m, v, out);
    }
    double fwd_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;

    /* Inverse avec donnée variable */
    t0 = clock();
    for (int b = 0; b < N_BLOCKS; b++) {
        for (int i = 0; i < CAGOULE_N; i++)
            v[i] = (uint64_t)((b * 7919 + i * 101) % P_BENCH);
        cagoule_matrix_mul_inv(m, v, out);
    }
    double inv_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;

    printf("  Forward  (65 536 blocs) : %.2f ms\n", fwd_ms);
    printf("  Inverse  (65 536 blocs) : %.2f ms\n", inv_ms);
    printf("  Ratio inv/fwd           : %.2f×\n", inv_ms / fwd_ms);
    printf("  [Référence Python v1.x  : ~8 000 ms]\n");
    printf("  Gain estimé             : ×%.0f\n", 8000.0 / fwd_ms);
    
    CHECK(fwd_ms < 500.0, "forward matrix 65k blocs < 500ms");
    CHECK(inv_ms < 500.0, "inverse matrix 65k blocs < 500ms");
    CHECK(inv_ms / fwd_ms < 2.0, "ratio inv/fwd < 2x");

    cagoule_matrix_free(m);
}

/* ── Test paramètres invalides ────────────────────────────────────── */
static void test_invalid_params(void) {
    printf("\n[Paramètres invalides]\n");
    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, P_BENCH, CAGOULE_N);
    
    CagouleMatrix* m = cagoule_matrix_build(NULL, CAGOULE_N, P_BENCH);
    CHECK(m == NULL, "NULL nodes → NULL");
    
    m = cagoule_matrix_build(nodes, 0, P_BENCH);
    CHECK(m == NULL, "n=0 → NULL");
    
    m = cagoule_matrix_build(nodes, CAGOULE_N, 1);
    CHECK(m == NULL, "p=1 → NULL");
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════\n");
    printf("  CAGOULE v2.0.0 — test_matrix.c\n");
    printf("══════════════════════════════════════════\n");

    printf("\n[Roundtrip P × P^-1 = I]\n");
    test_roundtrip(P_BENCH, "P_bench≈2^64");
    test_roundtrip(P_SMALL, "P_small=65537");
    test_roundtrip(97,      "p=97");

    test_cauchy_fallback();
    test_invalid_params();
    bench_matmul();

    printf("\n──────────────────────────────────────────\n");
    printf("  ✅ %d passés  ❌ %d échoués\n", _passed, _failed);
    printf("══════════════════════════════════════════\n");
    return _failed == 0 ? 0 : 1;
}