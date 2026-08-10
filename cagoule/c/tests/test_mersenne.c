/**
 * test_mersenne.c — Validation mulmod_mersenne64x4 v3.1.0
 * 4 000 000 assertions de parité vs scalaire pour les 8 primes du pool.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "cagoule_math.h"

#if defined(__AVX2__)
#include <immintrin.h>
#include "cagoule_math_avx2.h"

static int g_pass=0, g_fail=0;
#define CHECK(c,m) do{if(c){g_pass++;}else{g_fail++;printf("  FAIL [%d] %s\n",__LINE__,(m));}}while(0)

static void mul4(uint64_t a0,uint64_t a1,uint64_t a2,uint64_t a3,
                 uint64_t b0,uint64_t b1,uint64_t b2,uint64_t b3,
                 uint64_t p, uint64_t k,
                 uint64_t *r0,uint64_t *r1,uint64_t *r2,uint64_t *r3) {
    __m256i av=_mm256_set_epi64x((int64_t)a3,(int64_t)a2,(int64_t)a1,(int64_t)a0);
    __m256i bv=_mm256_set_epi64x((int64_t)b3,(int64_t)b2,(int64_t)b1,(int64_t)b0);
    __m256i pv=_mm256_set1_epi64x((int64_t)p);
    __m256i kv=_mm256_set1_epi64x((int64_t)k);
    __m256i rv=mulmod_mersenne64x4(av,bv,pv,kv);
    uint64_t t[4]; _mm256_storeu_si256((__m256i*)t,rv);
    *r0=t[0];*r1=t[1];*r2=t[2];*r3=t[3];
}

static uint64_t lcg=0xDEADBEEFCAFEBABEULL;
static uint64_t rnd(){lcg=lcg*6364136223846793005ULL+1442695040888963407ULL;return lcg;}

int main(void){
    printf("══════════════════════════════════════════════════\n");
    printf("  test_mersenne — CAGOULE v3.0.0 — 4M assertions\n");
    printf("══════════════════════════════════════════════════\n\n");

    if(!__builtin_cpu_supports("avx2")){printf("SKIP: AVX2 absent\n");return 0;}

    for(int i=0;i<CAGOULE_MERSENNE_POOL_SIZE;i++){
        uint64_t k=CAGOULE_MERSENNE_K[i], p=CAGOULE_MERSENNE_P[i];
        printf("  Pool[%d] k=%-3llu : ",(int)i,(unsigned long long)k);
        lcg=0x1234567890ABCDEFULL+(uint64_t)i*0xBEEFULL;
        int ok=0;
        for(int n=0;n<125000;n++){
            uint64_t a0=rnd()%p,a1=rnd()%p,a2=rnd()%p,a3=rnd()%p;
            uint64_t b0=rnd()%p,b1=rnd()%p,b2=rnd()%p,b3=rnd()%p;
            uint64_t r0,r1,r2,r3;
            mul4(a0,a1,a2,a3,b0,b1,b2,b3,p,k,&r0,&r1,&r2,&r3);
            if(r0==mulmod64(a0,b0,p)&&r1==mulmod64(a1,b1,p)&&
               r2==mulmod64(a2,b2,p)&&r3==mulmod64(a3,b3,p)&&
               r0<p&&r1<p&&r2<p&&r3<p) ok+=4;
            else {g_fail+=4;if(g_fail<=4)printf("\n  FAIL lane a=%llu b=%llu got=%llu ref=%llu",
                (unsigned long long)a0,(unsigned long long)b0,(unsigned long long)r0,(unsigned long long)mulmod64(a0,b0,p));}
        }
        g_pass+=ok;
        printf("%d/500000 ✓\n",ok);
    }

    /* Propriétés algébriques */
    for(int i=0;i<CAGOULE_MERSENNE_POOL_SIZE;i++){
        uint64_t k=CAGOULE_MERSENNE_K[i],p=CAGOULE_MERSENNE_P[i];
        uint64_t r0,r1,r2,r3;
        mul4(0,p-1,p/2,1,   0,1,p/2,p-1, p,k, &r0,&r1,&r2,&r3);
        char m[64];
        snprintf(m,sizeof(m),"0*0=0 k=%llu",(unsigned long long)k); CHECK(r0==0,m);
        snprintf(m,sizeof(m),"(p-1)*1 k=%llu",(unsigned long long)k); CHECK(r1==p-1,m);
        snprintf(m,sizeof(m),"p/2*p/2 k=%llu",(unsigned long long)k); CHECK(r2==mulmod64(p/2,p/2,p),m);
        snprintf(m,sizeof(m),"1*(p-1) k=%llu",(unsigned long long)k); CHECK(r3==p-1,m);
    }

    printf("\n══════════════════════════════════════════════════\n");
    printf("  %d/%d assertions",g_pass,g_pass+g_fail);
    if(g_fail) printf("  — %d ÉCHECS",g_fail);
    printf("\n══════════════════════════════════════════════════\n");
    return g_fail?1:0;
}
#else
int main(void){printf("SKIP: AVX2 non compilé\n");return 0;}
#endif
