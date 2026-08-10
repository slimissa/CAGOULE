/**
 * cagoule_matrix_avx2.c — Multiplication Vandermonde vectorisée AVX2
 *                          CAGOULE v3.1.0
 *
 * Nouveautés v2.5.0 :
 *
 *   A. Mersenne dispatch :
 *      Si CagouleMatrix.k_mersenne > 0 → mulmod_mersenne64x4.
 *      Sinon → mulmod64x4 Barrett (compatibilité tests scalaires).
 *      Gain Mersenne : ~13 instructions/mul vs ~22 Barrett (−41%).
 *
 *   B. Option A — Double accumulateur indépendant :
 *      Passe A : j pair   (0,2,4,...,14) → acc0a..acc3a, profondeur 8.
 *      Passe B : j impair (1,3,5,...,15) → acc0b..acc3b, profondeur 8.
 *      Merge   : result = addmod(accXa, accXb).
 *      Budget registres : 4 acc actifs + p,k,FLIP (3 consts) + ~6 temps Mersenne
 *                       = ~13 YMM dans les 16 disponibles. Zéro spill critique.
 *
 *   Résultats bit-à-bit identiques au scalaire — validés par test_matrix_avx2.c.
 *
 * Nouveauté v3.1.0 (audit performance) :
 *
 *   C. cagoule_matrix_mul_avx2_lazy — réduction différée, CTR UNIQUEMENT :
 *
 *      Bug trouvé : cagoule_matrix_mul_avx2 (ci-dessus, A+B) applique une
 *      réduction modulaire COMPLÈTE (mulmod_mersenne64x4, puis addmod64x4)
 *      à CHAQUE multiplication-accumulation -- 256 réductions par bloc
 *      16×16, alors que le chemin scalaire utilisait déjà depuis v2.5.x
 *      une stratégie "accumuler en brut, réduire une seule fois à la fin"
 *      (16 réductions par bloc). L'AVX2 faisait donc 16× plus de travail
 *      de réduction que le scalaire pour un résultat équivalent -- au
 *      point que l'AVX2 mesurait PLUS LENT que le scalaire sur certaines
 *      machines avant ce correctif.
 *
 *      Fonction séparée, pas une modification de la fonction ci-dessus :
 *      la réduction différée n'est SÛRE que si les éléments de v[] sont
 *      octet-range (0-255), ce qui est garanti pour les blocs compteur
 *      CTR mais PAS pour les entrées CBC (éléments de corps entier après
 *      chaînage _cbc_add). cagoule_matrix_mul_avx2 (A+B, ci-dessus) reste
 *      la seule fonction appelée par cagoule_cipher.c (CBC) -- vérifié
 *      par grep de tous les points d'appel avant et après ce correctif,
 *      pas seulement supposé. Un assert() de precondition (v[i] < 256,
 *      désactivé sous NDEBUG / make release) protège contre un mauvais
 *      câblage futur de cette fonction sur le chemin CBC.
 *
 *      Deux pièges corrigés dans l'implémentation (voir ACCUM_LAZY /
 *      REDUCE_LAZY plus bas) qui produiraient un chiffrement FAUX de
 *      façon silencieuse, pas un crash, s'ils étaient oubliés :
 *        - Propagation de carry entre lo/hi pendant l'accumulation : un
 *          simple _mm256_add_epi64 sans vérification de débordement
 *          uint64 (_cmpgt_epu64, même motif que _mul128x4 lui-même)
 *          perdrait silencieusement des carries qui doivent se propager
 *          dans hi.
 *        - Double soustraction conditionnelle dans la réduction finale,
 *          pas une seule -- même motif que reduce128_mersenne (référence
 *          scalaire), qui a explicitement une "seconde soustraction pour
 *          le cas limite k > 1".
 *
 *      Vérifié par la suite de régression complète ET par 1,6M+ essais
 *      de fuzzing adverse ciblant spécifiquement les conditions de
 *      débordement de carry (entrées proches de p-1 et de 255), sur les
 *      8 premiers de Mersenne de production -- 0 divergence face à la
 *      version toujours-correcte (A+B) prise comme référence.
 *
 *      Gain mesuré : ~20-31 MB/s (AVX2, avant) → ~50-55 MB/s (AVX2,
 *      après), Z-Domain Shifting actif -- voir SECURITY.md §6.1 pour la
 *      méthodologie complète et ses limites (mesuré sur VM instable,
 *      traiter comme indicatif, pas comme référence absolue reproductible).
 */

#include "cagoule_matrix.h"
#include "cagoule_math.h"
#include <assert.h>

#if defined(__AVX2__)

#include "cagoule_math_avx2.h"
#include <immintrin.h>

/* ── Macros d'accumulation ────────────────────────────────────────── */

#define ACCUM_MERSENNE(a0,a1,a2,a3, mat,j_, pv,kv) do {           \
    __m256i _vj = _mm256_set1_epi64x((int64_t)v[(j_)]);           \
    (a0) = addmod64x4((a0), mulmod_mersenne64x4(                   \
        _mm256_loadu_si256((const __m256i*)&(mat)[0][(j_)*4]),     \
        _vj, pv, kv), pv);                                         \
    (a1) = addmod64x4((a1), mulmod_mersenne64x4(                   \
        _mm256_loadu_si256((const __m256i*)&(mat)[1][(j_)*4]),     \
        _vj, pv, kv), pv);                                         \
    (a2) = addmod64x4((a2), mulmod_mersenne64x4(                   \
        _mm256_loadu_si256((const __m256i*)&(mat)[2][(j_)*4]),     \
        _vj, pv, kv), pv);                                         \
    (a3) = addmod64x4((a3), mulmod_mersenne64x4(                   \
        _mm256_loadu_si256((const __m256i*)&(mat)[3][(j_)*4]),     \
        _vj, pv, kv), pv);                                         \
} while(0)

#define ACCUM_BARRETT(a0,a1,a2,a3, mat,j_, pv,mu_) do {           \
    __m256i _vj = _mm256_set1_epi64x((int64_t)v[(j_)]);           \
    (a0) = addmod64x4((a0), mulmod64x4(                            \
        _mm256_loadu_si256((const __m256i*)&(mat)[0][(j_)*4]),     \
        _vj, pv, mu_), pv);                                        \
    (a1) = addmod64x4((a1), mulmod64x4(                            \
        _mm256_loadu_si256((const __m256i*)&(mat)[1][(j_)*4]),     \
        _vj, pv, mu_), pv);                                        \
    (a2) = addmod64x4((a2), mulmod64x4(                            \
        _mm256_loadu_si256((const __m256i*)&(mat)[2][(j_)*4]),     \
        _vj, pv, mu_), pv);                                        \
    (a3) = addmod64x4((a3), mulmod64x4(                            \
        _mm256_loadu_si256((const __m256i*)&(mat)[3][(j_)*4]),     \
        _vj, pv, mu_), pv);                                        \
} while(0)

#define STORE4(vec, out, base) do {                                 \
    uint64_t _t[4];                                                 \
    _mm256_storeu_si256((__m256i*)_t, (vec));                       \
    (out)[(base)+0]=_t[0];(out)[(base)+1]=_t[1];                   \
    (out)[(base)+2]=_t[2];(out)[(base)+3]=_t[3];                   \
} while(0)

/* ── cagoule_matrix_mul_avx2 — Mersenne + Option A ─────────────────  */
void cagoule_matrix_mul_avx2(const CagouleMatrix* m,
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N])
{
    const uint64_t p = m->p;
    __m256i p_vec = _mm256_set1_epi64x((int64_t)p);

    __m256i a0a,a1a,a2a,a3a;   /* Passe A — j pair  */
    __m256i a0b,a1b,a2b,a3b;   /* Passe B — j impair */
    a0a=a1a=a2a=a3a=_mm256_setzero_si256();
    a0b=a1b=a2b=a3b=_mm256_setzero_si256();

    if (m->k_mersenne > 0) {
        __m256i k_vec = _mm256_set1_epi64x((int64_t)m->k_mersenne);
        for (int j = 0; j < CAGOULE_N; j += 2)
            ACCUM_MERSENNE(a0a,a1a,a2a,a3a, m->fwd_avx2, j, p_vec, k_vec);
        for (int j = 1; j < CAGOULE_N; j += 2)
            ACCUM_MERSENNE(a0b,a1b,a2b,a3b, m->fwd_avx2, j, p_vec, k_vec);
    } else {
        uint64_t mu = cagoule_barrett_mu(p);
        for (int j = 0; j < CAGOULE_N; j += 2)
            ACCUM_BARRETT(a0a,a1a,a2a,a3a, m->fwd_avx2, j, p_vec, mu);
        for (int j = 1; j < CAGOULE_N; j += 2)
            ACCUM_BARRETT(a0b,a1b,a2b,a3b, m->fwd_avx2, j, p_vec, mu);
    }

    STORE4(addmod64x4(a0a,a0b,p_vec), out,  0);
    STORE4(addmod64x4(a1a,a1b,p_vec), out,  4);
    STORE4(addmod64x4(a2a,a2b,p_vec), out,  8);
    STORE4(addmod64x4(a3a,a3b,p_vec), out, 12);
    _mm256_zeroupper();
}

/* ── cagoule_matrix_mul_avx2_lazy — CTR-only, deferred reduction ───
 *
 * SAFETY: only correct when v[] elements are byte-range (0-255), as
 * guaranteed by CTR counter blocks. CBC chaining produces full field
 * elements (~2^64) which would overflow the bound this function relies
 * on — CBC MUST continue calling cagoule_matrix_mul_avx2 (unchanged).
 *
 * Bound (derived, not assumed): each raw product mat[i][j]*v[j] has
 * hi < 255 (p<2^64, v[j]<=255). Summing 8 terms per pass keeps the
 * TRUE accumulated hi < 8*255 = 2040 — but only if lo/hi carries are
 * propagated correctly during accumulation (a plain _mm256_add_epi64
 * on lo without a carry check silently drops carries into hi,
 * corrupting the result — this is why _mul128x4 itself has to
 * carry-check every internal add; the same discipline is required here).
 *
 * Reduction: hi*k + lo (mod p), matching reduce128_mersenne (scalar
 * reference): the lo+hik addition can itself overflow 64 bits once
 * (single correction, +k, sufficient), and the final result needs UP
 * TO TWO conditional subtracts of p, matching reduce128_mersenne's own
 * "second subtract for k > 1 edge case" comment.
 *
 * k_mersenne==0 (non-Mersenne/Barrett test primes) is NOT handled here;
 * falls back to the always-correct cagoule_matrix_mul_avx2.
 */
void cagoule_matrix_mul_avx2_lazy(const CagouleMatrix* m,
                                    const uint64_t v[CAGOULE_N],
                                    uint64_t out[CAGOULE_N])
{
    /* CORRECTIF (P2-6, consistency with _matmul16_scalar_lazy) : same
     * byte-range precondition on v[], same self-verifying debug assert,
     * compiled out under NDEBUG (make release). */
    for (int _i = 0; _i < CAGOULE_N; _i++) assert(v[_i] < 256);

    if (m->k_mersenne == 0) {
        cagoule_matrix_mul_avx2(m, v, out);
        return;
    }

    const uint64_t p = m->p;
    __m256i p_vec = _mm256_set1_epi64x((int64_t)p);
    __m256i k_vec = _mm256_set1_epi64x((int64_t)m->k_mersenne);
    const __m256i zero = _mm256_setzero_si256();
    const __m256i one  = _mm256_set1_epi64x(1LL);
    const __m256i mask32 = _mm256_set1_epi64x(0xFFFFFFFFULL);

#define ACCUM_LAZY(lo,hi, mat,idx,j_) do {                              \
    __m256i _vj = _mm256_set1_epi64x((int64_t)v[(j_)]);                 \
    __m256i _plo, _phi;                                                 \
    _mul128x4(_mm256_loadu_si256((const __m256i*)&(mat)[(idx)][(j_)*4]), \
              _vj, &_plo, &_phi);                                       \
    __m256i _newlo = _mm256_add_epi64((lo), _plo);                      \
    __m256i _carry = _mm256_and_si256(_cmpgt_epu64((lo), _newlo), one); \
    (lo) = _newlo;                                                      \
    (hi) = _mm256_add_epi64(_mm256_add_epi64((hi), _phi), _carry);      \
} while(0)

#define REDUCE_LAZY(lo,hi) do {                                          \
    __m256i _hik = _mm256_mul_epu32(_mm256_and_si256((hi), mask32), k_vec); \
    __m256i _r = _mm256_add_epi64((lo), _hik);                           \
    __m256i _ovf = _mm256_and_si256(_cmpgt_epu64((lo), _r), one);        \
    _r = _mm256_add_epi64(_r, _mm256_and_si256(_ovf, k_vec));            \
    __m256i _geq1 = _mm256_or_si256(_cmpgt_epu64(_r, p_vec),             \
                                     _mm256_cmpeq_epi64(_r, p_vec));      \
    _r = _mm256_sub_epi64(_r, _mm256_and_si256(_geq1, p_vec));           \
    __m256i _geq2 = _mm256_or_si256(_cmpgt_epu64(_r, p_vec),             \
                                     _mm256_cmpeq_epi64(_r, p_vec));      \
    _r = _mm256_sub_epi64(_r, _mm256_and_si256(_geq2, p_vec));           \
    (lo) = _r;                                                           \
} while(0)

    __m256i lo0a=zero,hi0a=zero, lo1a=zero,hi1a=zero;
    __m256i lo2a=zero,hi2a=zero, lo3a=zero,hi3a=zero;
    __m256i lo0b=zero,hi0b=zero, lo1b=zero,hi1b=zero;
    __m256i lo2b=zero,hi2b=zero, lo3b=zero,hi3b=zero;

    for (int j = 0; j < CAGOULE_N; j += 2) {
        ACCUM_LAZY(lo0a,hi0a, m->fwd_avx2, 0, j);
        ACCUM_LAZY(lo1a,hi1a, m->fwd_avx2, 1, j);
        ACCUM_LAZY(lo2a,hi2a, m->fwd_avx2, 2, j);
        ACCUM_LAZY(lo3a,hi3a, m->fwd_avx2, 3, j);
    }
    for (int j = 1; j < CAGOULE_N; j += 2) {
        ACCUM_LAZY(lo0b,hi0b, m->fwd_avx2, 0, j);
        ACCUM_LAZY(lo1b,hi1b, m->fwd_avx2, 1, j);
        ACCUM_LAZY(lo2b,hi2b, m->fwd_avx2, 2, j);
        ACCUM_LAZY(lo3b,hi3b, m->fwd_avx2, 3, j);
    }

    REDUCE_LAZY(lo0a,hi0a); REDUCE_LAZY(lo0b,hi0b);
    REDUCE_LAZY(lo1a,hi1a); REDUCE_LAZY(lo1b,hi1b);
    REDUCE_LAZY(lo2a,hi2a); REDUCE_LAZY(lo2b,hi2b);
    REDUCE_LAZY(lo3a,hi3a); REDUCE_LAZY(lo3b,hi3b);

#undef ACCUM_LAZY
#undef REDUCE_LAZY

    STORE4(addmod64x4(lo0a,lo0b,p_vec), out,  0);
    STORE4(addmod64x4(lo1a,lo1b,p_vec), out,  4);
    STORE4(addmod64x4(lo2a,lo2b,p_vec), out,  8);
    STORE4(addmod64x4(lo3a,lo3b,p_vec), out, 12);
    _mm256_zeroupper();
}

/* ── cagoule_matrix_mul_inv_avx2 — identique, matrice inverse ─────── */
void cagoule_matrix_mul_inv_avx2(const CagouleMatrix* m,
                                   const uint64_t v[CAGOULE_N],
                                   uint64_t out[CAGOULE_N])
{
    const uint64_t p = m->p;
    __m256i p_vec = _mm256_set1_epi64x((int64_t)p);

    __m256i a0a,a1a,a2a,a3a;
    __m256i a0b,a1b,a2b,a3b;
    a0a=a1a=a2a=a3a=_mm256_setzero_si256();
    a0b=a1b=a2b=a3b=_mm256_setzero_si256();

    if (m->k_mersenne > 0) {
        __m256i k_vec = _mm256_set1_epi64x((int64_t)m->k_mersenne);
        for (int j = 0; j < CAGOULE_N; j += 2)
            ACCUM_MERSENNE(a0a,a1a,a2a,a3a, m->inv_avx2, j, p_vec, k_vec);
        for (int j = 1; j < CAGOULE_N; j += 2)
            ACCUM_MERSENNE(a0b,a1b,a2b,a3b, m->inv_avx2, j, p_vec, k_vec);
    } else {
        uint64_t mu = cagoule_barrett_mu(p);
        for (int j = 0; j < CAGOULE_N; j += 2)
            ACCUM_BARRETT(a0a,a1a,a2a,a3a, m->inv_avx2, j, p_vec, mu);
        for (int j = 1; j < CAGOULE_N; j += 2)
            ACCUM_BARRETT(a0b,a1b,a2b,a3b, m->inv_avx2, j, p_vec, mu);
    }

    STORE4(addmod64x4(a0a,a0b,p_vec), out,  0);
    STORE4(addmod64x4(a1a,a1b,p_vec), out,  4);
    STORE4(addmod64x4(a2a,a2b,p_vec), out,  8);
    STORE4(addmod64x4(a3a,a3b,p_vec), out, 12);
    _mm256_zeroupper();
}

#undef ACCUM_MERSENNE
#undef ACCUM_BARRETT
#undef STORE4

#endif /* __AVX2__ */
