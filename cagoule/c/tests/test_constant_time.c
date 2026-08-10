/**
 * test_constant_time.c — dudect-style constant-time validation
 *                         CAGOULE v3.1.0
 *
 * v3.0.0: Added CTR keystream generation constant-time test
 *         Batched rdtsc measurements for Mersenne/Barrett to reduce noise
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "cagoule_math.h"

#ifdef __AVX2__
#include "cagoule_math_avx2.h"
#include "cagoule_sbox_avx2.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"
#include "cagoule_ctr.h"
#include <immintrin.h>

/* ── Batch size for fast primitives (Mersenne/Barrett) ───────────── */
#define DUDECT_BATCH 100

static int g_pass = 0, g_fail = 0;
#define CHECK_CT(name, tval) do { \
    if (fabs(tval) < 5.0) { \
        printf("    ✓ %s (t=%.2f)\n", name, tval); g_pass++; \
    } else { \
        printf("    ✗ LEAK: %s (t=%.2f)\n", name, tval); g_fail++; \
    } \
} while(0)

static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double t_test(double *a, double *b, int n) {
    double mean_a = 0, mean_b = 0, var_a = 0, var_b = 0;
    for (int i = 0; i < n; i++) { mean_a += a[i]; mean_b += b[i]; }
    mean_a /= n; mean_b /= n;
    for (int i = 0; i < n; i++) {
        double da = a[i] - mean_a, db = b[i] - mean_b;
        var_a += da * da; var_b += db * db;
    }
    var_a /= (n - 1); var_b /= (n - 1);
    return (mean_a - mean_b) / sqrt(var_a/n + var_b/n);
}


/* noinline wrappers to prevent -O3 from treating fixed/random differently */
__attribute__((noinline))
static __m256i _ct_mulmod_mersenne(__m256i a, __m256i b, __m256i p, __m256i k) {
    return mulmod_mersenne64x4(a, b, p, k);
}
__attribute__((noinline))
static __m256i _ct_mulmod_barrett(__m256i a, __m256i b, __m256i p, uint64_t mu) {
    return mulmod64x4(a, b, p, mu);
}

static void test_mersenne_ct(void) {
    printf("  [1] mulmod_mersenne64x4 (batched ×%d)...\n", DUDECT_BATCH);
    extern const uint64_t CAGOULE_MERSENNE_P[8];
    extern const uint64_t CAGOULE_MERSENNE_K[8];
    int N = 50000;
    
    /* CPU warmup: stabilize frequency */
    volatile uint64_t w = 0;
    for (int i = 0; i < 1000000; i++) w += i;

    for (int pi = 0; pi < 8; pi++) {
        uint64_t p = CAGOULE_MERSENNE_P[pi], k = CAGOULE_MERSENNE_K[pi];
        __m256i pv = _mm256_set1_epi64x((int64_t)p);
        __m256i kv = _mm256_set1_epi64x((int64_t)k);
        double *fa = malloc(N * sizeof(double));
        double *fb = malloc(N * sizeof(double));
        __m256i af = _mm256_set1_epi64x((int64_t)(p/2));
        __m256i bf = _mm256_set1_epi64x((int64_t)(p/3));
        for (int i = 0; i < N; i++) {
            uint64_t t0 = rdtsc();
            __m256i r;
            for (int b = 0; b < DUDECT_BATCH; b++)
                r = _ct_mulmod_mersenne(af, bf, pv, kv);
            fa[i] = (double)(rdtsc() - t0) / DUDECT_BATCH;
            volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
        }
        for (int i = 0; i < N; i++) {
            uint64_t ra = ((uint64_t)rand()<<32)|rand(), rb = ((uint64_t)rand()<<32)|rand();
            __m256i ar = _mm256_set1_epi64x((int64_t)(ra%p));
            __m256i br = _mm256_set1_epi64x((int64_t)(rb%p));
            uint64_t t0 = rdtsc();
            __m256i r;
            for (int b = 0; b < DUDECT_BATCH; b++)
                r = _ct_mulmod_mersenne(ar, br, pv, kv);
            fb[i] = (double)(rdtsc() - t0) / DUDECT_BATCH;
            volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
        }
        char nm[32]; snprintf(nm,sizeof(nm),"mersenne k=%llu",(unsigned long long)k);
        CHECK_CT(nm, t_test(fa,fb,N));
        free(fa); free(fb);
    }
}

static void test_barrett_ct(void) {
    printf("  [2] mulmod64x4 Barrett (batched ×%d)...\n", DUDECT_BATCH);
    uint64_t pr[4]={10441487724840939323ULL,14927237621619697897ULL,18446744073709551557ULL,9223372036854775837ULL};
    int N=30000;
    for(int pi=0;pi<4;pi++){
        uint64_t p=pr[pi];
        __m256i pv=_mm256_set1_epi64x((int64_t)p);
        uint64_t mu=cagoule_barrett_mu(p);
        double*fa=malloc(N*sizeof(double)),*fb=malloc(N*sizeof(double));
        __m256i af=_mm256_set1_epi64x((int64_t)(p/2)),bf=_mm256_set1_epi64x((int64_t)(p/3));
        for(int i=0;i<N;i++){
            uint64_t t0=rdtsc();
            __m256i r;
            for(int b=0;b<DUDECT_BATCH;b++)
                r=_ct_mulmod_barrett(af,bf,pv,mu);
            fa[i]=(double)(rdtsc()-t0)/DUDECT_BATCH;
            volatile uint64_t s;_mm256_storeu_si256((__m256i*)&s,r);
        }
        for(int i=0;i<N;i++){
            uint64_t ra=((uint64_t)rand()<<32)|rand(),rb=((uint64_t)rand()<<32)|rand();
            __m256i ar=_mm256_set1_epi64x((int64_t)(ra%p)),br=_mm256_set1_epi64x((int64_t)(rb%p));
            uint64_t t0=rdtsc();
            __m256i r;
            for(int b=0;b<DUDECT_BATCH;b++)
                r=_ct_mulmod_barrett(ar,br,pv,mu);
            fb[i]=(double)(rdtsc()-t0)/DUDECT_BATCH;
            volatile uint64_t s;_mm256_storeu_si256((__m256i*)&s,r);
        }
        char nm[32];snprintf(nm,sizeof(nm),"barrett p[%d]",pi);
        CHECK_CT(nm,t_test(fa,fb,N));
        free(fa);free(fb);
    }
}

/* ── v3.0.0: CTR keystream constant-time validation ───────────────── */
__attribute__((noinline))
static int _ct_ctr_keystream(const uint8_t iv[8], size_t start_bi,
                              const CagouleMatrix* mat, const CagouleSBox64* sbox,
                              const uint64_t* rk, size_t nk, uint64_t p,
                              uint8_t* out, size_t n_blocks) {
    return cagoule_ctr_keystream(iv, start_bi, mat, sbox, rk, nk, p, out, n_blocks);
}

static void test_ctr_keystream_ct(void) {
    printf("  [3] CTR keystream generation (v3.0.0)...\n");
    
    extern const uint64_t CAGOULE_MERSENNE_P[8];
    int N = 30000;
    
    volatile uint64_t w = 0;
    for (int i = 0; i < 1000000; i++) w += i;
    
    for (int pi = 0; pi < 4; pi++) {
        uint64_t p = CAGOULE_MERSENNE_P[pi];
        
        uint64_t nodes[16];
        for (int i = 0; i < 16; i++)
            nodes[i] = (uint64_t)(2 + i * 1000000007ULL + pi * 17ULL);
        CagouleMatrix* mat = cagoule_matrix_build(nodes, 16, p);
        if (!mat) { printf("    SKIP prime[%d] — build failed\n", pi); continue; }
        
        CagouleSBox64 sbox;
        uint64_t rk0 = 0x123456789ABCDEF0ULL % 4294967291ULL;
        uint64_t rk1 = 0xFEDCBA9876543210ULL % 4294967291ULL;
        if (rk0 == 0) rk0 = 1;
        if (rk1 == 0) rk1 = 1;
        cagoule_sbox_init(&sbox, p, rk0, rk1);
        
        uint64_t rk[64];
        for (int i = 0; i < 64; i++)
            rk[i] = (uint64_t)((i + 1) * 0xABCDEF0123456789ULL) % p;
        
        uint8_t iv[8];
        for (int i = 0; i < 8; i++)
            iv[i] = (uint8_t)(0x30 + pi * 7 + i * 13);
        
        double *fa = malloc(N * sizeof(double));
        double *fb = malloc(N * sizeof(double));
        
        /* FIXED n_blocks = 1 for BOTH classes — equal work, interleaved */
        uint8_t ks[16];
        
        for (int i = 0; i < N; i++) {
            /* Class A: fixed start_bi = 0 */
            uint64_t t0 = rdtsc();
            _ct_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, ks, 1);
            fa[i] = (double)(rdtsc() - t0);
            volatile uint8_t sink_a = ks[0]; (void)sink_a;
            
            /* Class B: random start_bi — interleaved to cancel drift */
            size_t start_bi = (size_t)(rand() % 1000);
            t0 = rdtsc();
            _ct_ctr_keystream(iv, start_bi, mat, &sbox, rk, 64, p, ks, 1);
            fb[i] = (double)(rdtsc() - t0);
            volatile uint8_t sink_b = ks[0]; (void)sink_b;
        }
        
        char nm[32];
        snprintf(nm, sizeof(nm), "CTR keystream p[%d]", pi);
        CHECK_CT(nm, t_test(fa, fb, N));
        
        free(fa); free(fb);
        cagoule_matrix_free(mat);
    }
}

/* Calibration: known constant-time (XOR) */
static void test_calibrate_ct(void) {
    printf("  [0] Calibration...\n");
    int N = 50000;
    double *fa = malloc(N * sizeof(double));
    double *fb = malloc(N * sizeof(double));
    __m256i a = _mm256_set1_epi64x(0x1234);
    __m256i b = _mm256_set1_epi64x(0x5678);
    for (int i = 0; i < N; i++) {
        uint64_t t0 = rdtsc();
        __m256i r = _mm256_xor_si256(a, b);
        fa[i] = (double)(rdtsc() - t0);
        volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
    }
    for (int i = 0; i < N; i++) {
        __m256i ar = _mm256_set1_epi64x((int64_t)rand());
        __m256i br = _mm256_set1_epi64x((int64_t)rand());
        uint64_t t0 = rdtsc();
        __m256i r = _mm256_xor_si256(ar, br);
        fb[i] = (double)(rdtsc() - t0);
        volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
    }
    double t = t_test(fa, fb, N);
    printf("    XOR (known CT): t=%.2f %s\n", t,
           fabs(t) < 5.0 ? "✓ (measurement noise OK)" : "✗ (noise too high, results unreliable)");
    free(fa); free(fb);
}

int main(void){
    printf("══════════════════════════════════════════════════\n");
    printf("  test_constant_time — CAGOULE v3.1.0\n");
    printf("══════════════════════════════════════════════════\n\n");
    srand(0xCAFEBABE);
    test_calibrate_ct();
    test_mersenne_ct();
    test_barrett_ct();
    test_ctr_keystream_ct();
    printf("\n  ✅ %d constant-time  ❌ %d leaks\n",g_pass,g_fail);
    return g_fail==0?0:1;
}
#else

static void test_calibrate_ct(void) {
    printf("  [0] Calibration...\n");
    int N = 50000;
    double *fa = malloc(N * sizeof(double));
    double *fb = malloc(N * sizeof(double));
    __m256i a = _mm256_set1_epi64x(0x1234);
    __m256i b = _mm256_set1_epi64x(0x5678);
    for (int i = 0; i < N; i++) {
        uint64_t t0 = rdtsc();
        __m256i r = _mm256_xor_si256(a, b);
        fa[i] = (double)(rdtsc() - t0);
        volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
    }
    for (int i = 0; i < N; i++) {
        __m256i ar = _mm256_set1_epi64x((int64_t)rand());
        __m256i br = _mm256_set1_epi64x((int64_t)rand());
        uint64_t t0 = rdtsc();
        __m256i r = _mm256_xor_si256(ar, br);
        fb[i] = (double)(rdtsc() - t0);
        volatile uint64_t s; _mm256_storeu_si256((__m256i*)&s, r);
    }
    double t = t_test(fa, fb, N);
    printf("    XOR (known CT): t=%.2f %s\n", t,
           fabs(t) < 5.0 ? "✓ (measurement noise OK)" : "✗ (noise too high, results unreliable)");
    free(fa); free(fb);
}

int main(void){printf("SKIP - AVX2 not compiled\n");return 0;}
#endif