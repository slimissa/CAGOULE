/**
 * cagoule_math_avx2.h — Arithmétique modulaire 64-bit vectorisée (AVX2)
 *                       CAGOULE v3.1.0
 *
 * Fournit mulmod64x4(), addmod64x4(), submod64x4() traitant 4 éléments
 * uint64_t simultanément dans des registres __m256i (256-bit, AVX2).
 *
 * Algorithme : réduction de Barrett avec µ = floor(2^127 / p).
 * Précondition : p ∈ (2^63, 2^64) — garantie pour tous les premiers CAGOULE.
 *
 * Bug corrigé (v2.2.0 rev2) :
 *   L'ajout de r_hi * mod2_64 à r_lo peut déborder uint64 silencieusement.
 *   Exemple : r_lo=18191862065771162509, mod2_64=932199698129707703,
 *             r_lo + mod2_64 = 19124061763900870212 > 2^64.
 *   Le débordement wraps → résultat = exp - mod2_64 au lieu de exp.
 *
 *   Fix : détecter le débordement uint64 après chaque addition de mod2_64
 *         et ajouter mod2_64 une fois de plus si débordement (preuve :
 *         (r_lo + mod2_64 - 2^64) + mod2_64 = r_lo + 2*mod2_64 - 2^64
 *         = exp + 2p - 2^64 - p = exp + p - 2^64 + (2^64-p) = exp ✓).
 *         La seconde addition ne déborde jamais car exp < p < 2^64.
 *
 * Résultats bit-à-bit identiques à mulmod64 scalaire — validés par
 * test_math_avx2.c (400 000 cas sur 4 premiers différents).
 */

#ifndef CAGOULE_MATH_AVX2_H
#define CAGOULE_MATH_AVX2_H

#if defined(__AVX2__)

#include <immintrin.h>
#include <stdint.h>

/* ── Constante de Barrett ────────────────────────────────────────────
 * µ = floor(2^127 / p)
 * Pour p ∈ (2^63, 2^64) : µ ∈ [1, 2^64) → tient dans uint64_t.
 */
static inline uint64_t cagoule_barrett_mu(uint64_t p) {
    __uint128_t num = (__uint128_t)1 << 127;
    return (uint64_t)(num / ((__uint128_t)p));
}

/* ── Comparaison unsigned 64-bit ─────────────────────────────────────
 * AVX2 n'a pas de cmpgt unsigned 64-bit natif.
 * a >u b  ⟺  (a ^ 2^63) >s (b ^ 2^63)
 * Retourne -1 (tous bits à 1) si a > b unsigned, 0 sinon.
 */
static inline __m256i _cmpgt_epu64(__m256i a, __m256i b) {
    const __m256i flip = _mm256_set1_epi64x((int64_t)0x8000000000000000LL);
    return _mm256_cmpgt_epi64(_mm256_xor_si256(a, flip),
                               _mm256_xor_si256(b, flip));
}

/* ── Produit 128-bit sur 4 lanes : (hi, lo) = a * b ─────────────────
 *
 * Décomposition : a = a_hi*2^32 + a_lo, b = b_hi*2^32 + b_lo
 *   a*b = a_hi*b_hi*2^64 + (a_hi*b_lo + a_lo*b_hi)*2^32 + a_lo*b_lo
 */
static inline void _mul128x4(__m256i a, __m256i b,
                               __m256i *lo_out, __m256i *hi_out)
{
    const __m256i mask32 = _mm256_set1_epi64x(0xFFFFFFFFULL);
    const __m256i one    = _mm256_set1_epi64x(1LL);

    __m256i a_lo = _mm256_and_si256(a, mask32);
    __m256i a_hi = _mm256_srli_epi64(a, 32);
    __m256i b_lo = _mm256_and_si256(b, mask32);
    __m256i b_hi = _mm256_srli_epi64(b, 32);

    __m256i p00 = _mm256_mul_epu32(a_lo, b_lo);
    __m256i p01 = _mm256_mul_epu32(a_lo, b_hi);
    __m256i p10 = _mm256_mul_epu32(a_hi, b_lo);
    __m256i p11 = _mm256_mul_epu32(a_hi, b_hi);

    /* mid = p01 + p10 (peut déborder uint64 → carry dans hi) */
    __m256i mid       = _mm256_add_epi64(p01, p10);
    __m256i carry_mid = _mm256_and_si256(_cmpgt_epu64(p01, mid), one);

    /* lo = p00 + (mid << 32) */
    __m256i mid_lo    = _mm256_slli_epi64(mid, 32);
    __m256i lo        = _mm256_add_epi64(p00, mid_lo);
    __m256i carry_lo  = _mm256_and_si256(_cmpgt_epu64(p00, lo), one);

    /* hi = p11 + (mid >> 32) + carry_mid*2^32 + carry_lo */
    __m256i hi = _mm256_add_epi64(p11, _mm256_srli_epi64(mid, 32));
    hi = _mm256_add_epi64(hi, _mm256_slli_epi64(carry_mid, 32));
    hi = _mm256_add_epi64(hi, carry_lo);

    *lo_out = lo;
    *hi_out = hi;
}

/* ── mulmod64x4 — réduction de Barrett avec correction de débordement ─
 *
 * Calcule a[i] * b[i] mod p pour i = 0..3.
 *
 * Préconditions : a, b ∈ [0, p) ; p ∈ (2^63, 2^64).
 *   p_vec = _mm256_set1_epi64x((int64_t)p)  (broadcaster 1× en dehors)
 *   mu    = cagoule_barrett_mu(p)
 *
 * Correction de débordement :
 *   r_hi ∈ {0,1,2} représente les bits hauts de n - q*p.
 *   L'ajout de r_hi * mod2_64 à r_lo peut déborder uint64.
 *   On détecte : r_new < r_prev (unsigned) → débordement → +mod2_64 encore.
 *   Preuve qu'une seule correction suffit (pas de récursion infinie) :
 *     après débordement, r_new = r_prev + mod2_64 - 2^64 = exp - mod2_64
 *     après correction : exp - mod2_64 + mod2_64 = exp < p → stable.
 */
static inline __m256i mulmod64x4(__m256i a, __m256i b,
                                  __m256i p_vec, uint64_t mu)
{
    const __m256i zero   = _mm256_setzero_si256();
    const __m256i one    = _mm256_set1_epi64x(1LL);
    __m256i mu_vec = _mm256_set1_epi64x((int64_t)mu);
    /* mod2_64 = 2^64 - p = (0 - p) en arithmétique uint64 */
    __m256i mod2_64 = _mm256_sub_epi64(zero, p_vec);

    /* Étape 1 : n = a * b  (128-bit) */
    __m256i prod_lo, prod_hi;
    _mul128x4(a, b, &prod_lo, &prod_hi);

    /* Étape 2 : q ≈ floor(n * µ / 2^127)
     *
     * n*µ = prod_hi*µ*2^64 + prod_lo*µ
     *     = (hm_hi*2^64 + hm_lo)*2^64 + (lm_hi*2^64 + lm_lo)
     *
     * floor(n*µ / 2^127) = 2*hm_hi + floor((hm_lo + lm_hi + sc*2^64) / 2^63)
     *                    = (hm_hi + sc) << 1 | (sum >> 63)
     */
    __m256i hm_lo, hm_hi;
    _mul128x4(prod_hi, mu_vec, &hm_lo, &hm_hi);
    __m256i lm_lo, lm_hi;
    _mul128x4(prod_lo, mu_vec, &lm_lo, &lm_hi);
    (void)lm_lo;  /* contribue < 1 au quotient, ignoré */

    __m256i sum       = _mm256_add_epi64(hm_lo, lm_hi);
    __m256i sum_carry = _mm256_and_si256(_cmpgt_epu64(hm_lo, sum), one);

    __m256i q = _mm256_or_si256(
        _mm256_slli_epi64(_mm256_add_epi64(hm_hi, sum_carry), 1),
        _mm256_srli_epi64(sum, 63)
    );

    /* Étape 3 : r = n - q*p  (soustraction 128-bit)
     *
     * r_lo = prod_lo - qp_lo  (borrow si prod_lo < qp_lo)
     * r_hi = prod_hi - qp_hi - borrow  ∈ {0, 1, 2}
     *
     * Preuve r_hi ≥ 0 : q ≤ floor(n/p) (Barrett), donc q*p ≤ n,
     * donc prod_hi*2^64 + prod_lo ≥ qp_hi*2^64 + qp_lo → r_hi ≥ 0.
     */
    __m256i qp_lo, qp_hi;
    _mul128x4(q, p_vec, &qp_lo, &qp_hi);

    __m256i r      = _mm256_sub_epi64(prod_lo, qp_lo);
    __m256i borrow = _mm256_and_si256(_cmpgt_epu64(qp_lo, prod_lo), one);
    __m256i r_hi   = _mm256_sub_epi64(_mm256_sub_epi64(prod_hi, qp_hi), borrow);

    /* Étape 4 : replier r_hi via 2^64 ≡ (2^64 - p) mod p — CONSTANT-TIME v2.5.0
     *
     * r_hi ∈ {0, 1, 2}. Chaque unité de r_hi contribue mod2_64 à r.
     * CORRECTION DE DÉBORDEMENT constant-time :
     *   Si r + mod2_64 déborde (r_new < r_old unsigned), ajouter mod2_64 encore.
     *   Aucun branchement conditionnel — masques bitmask uniquement.
     *
     * Suppression de _mm256_testz_si256 (v2.4.0) : créait un branchement
     * conditionnel dépendant de r_hi (donnée secrète). Side-channel timing.
     */
    __m256i mask1 = _cmpgt_epu64(r_hi, zero);   /* 0xFF..FF si r_hi >= 1 */
    {
        __m256i add1  = _mm256_and_si256(mask1, mod2_64);
        __m256i r_old = r;
        r = _mm256_add_epi64(r, add1);
        __m256i ovf1 = _mm256_and_si256(_cmpgt_epu64(r_old, r), mask1);
        r = _mm256_add_epi64(r, _mm256_and_si256(ovf1, mod2_64));
    }

    __m256i mask2 = _cmpgt_epu64(r_hi, one);    /* 0xFF..FF si r_hi >= 2 */
    {
        __m256i add2  = _mm256_and_si256(mask2, mod2_64);
        __m256i r_old = r;
        r = _mm256_add_epi64(r, add2);
        __m256i ovf2 = _mm256_and_si256(_cmpgt_epu64(r_old, r), mask2);
        r = _mm256_add_epi64(r, _mm256_and_si256(ovf2, mod2_64));
    }

    /* Étape 5 : corrections standard Barrett (r peut encore ≥ p) */
    __m256i geq1 = _mm256_or_si256(_cmpgt_epu64(r, p_vec),
                                     _mm256_cmpeq_epi64(r, p_vec));
    r = _mm256_sub_epi64(r, _mm256_and_si256(geq1, p_vec));

    __m256i geq2 = _mm256_or_si256(_cmpgt_epu64(r, p_vec),
                                     _mm256_cmpeq_epi64(r, p_vec));
    r = _mm256_sub_epi64(r, _mm256_and_si256(geq2, p_vec));

    return r;
}

/* ── addmod64x4 ──────────────────────────────────────────────────────
 * (a + b) mod p pour 4 lanes. Soustrait p si sum >= p ou si overflow.
 */
static inline __m256i addmod64x4(__m256i a, __m256i b, __m256i p_vec)
{
    __m256i sum  = _mm256_add_epi64(a, b);
    __m256i ovfl = _cmpgt_epu64(a, sum);   /* overflow uint64: sum < a */
    __m256i geqp = _mm256_or_si256(_cmpgt_epu64(sum, p_vec),
                                     _mm256_cmpeq_epi64(sum, p_vec));
    return _mm256_sub_epi64(sum, _mm256_and_si256(_mm256_or_si256(ovfl, geqp), p_vec));
}

/* ── submod64x4 ──────────────────────────────────────────────────────
 * (a - b) mod p pour 4 lanes. Ajoute p si underflow (a < b).
 */
static inline __m256i submod64x4(__m256i a, __m256i b, __m256i p_vec)
{
    __m256i diff      = _mm256_sub_epi64(a, b);
    __m256i underflow = _cmpgt_epu64(b, a);
    return _mm256_add_epi64(diff, _mm256_and_si256(underflow, p_vec));
}


/* ══════════════════════════════════════════════════════════════════════
 * mulmod_mersenne64x4 — CAGOULE v3.0.0
 *
 * Calcule a[i]*b[i] mod p pour i=0..3, avec p = 2^64 − k, k < 2^10.
 *
 * Principe : 2^64 ≡ k (mod p)  ⟹  a*b mod p ≡ hi*k + lo (mod p)
 *
 * vs Barrett : 4 mul_epu32 (au lieu de 6), ~13 instructions (au lieu de ~22).
 *              Libère ~4 registres YMM → Option A (2 acc) sans register spill.
 *
 * CONSTANT-TIME : zéro branchement conditionnel. Toutes les comparaisons
 * produisent des masques 0xFF..FF / 0x00..00. Timing parfaitement plat.
 *
 * Préconditions : a,b ∈ [0,p) ; p = 2^64-k ; k ∈ {59,83,95,179,189,257,279,323}.
 *   p_vec = _mm256_set1_epi64x((int64_t)p)
 *   k_vec = _mm256_set1_epi64x((int64_t)k)
 *
 * Algorithme 4 rounds (preuve complète dans cagoule_math.h) :
 *   R1 : (prod_hi, prod_lo) = a*b via 4 × _mm256_mul_epu32
 *   R2 : hik = prod_hi * k via split 32-bit → hik_lo + c_carry * 2^64
 *   R3 : r = prod_lo + hik_lo ; c_carry += overflow
 *   R4 : r += c_carry * k (tiny < 2^21) ; r += k si débordement (1 fois max)
 *   RF : r -= p si r >= p (masque constant-time)
 * ══════════════════════════════════════════════════════════════════════ */
static inline __m256i mulmod_mersenne64x4(__m256i a, __m256i b,
                                           __m256i p_vec, __m256i k_vec)
{
    const __m256i mask32 = _mm256_set1_epi64x(0xFFFFFFFFULL);
    const __m256i one    = _mm256_set1_epi64x(1LL);

    /* ── R1 : produit 128-bit (prod_hi, prod_lo) ─────────────────── */
    __m256i a_lo = _mm256_and_si256(a, mask32);
    __m256i a_hi = _mm256_srli_epi64(a, 32);
    __m256i b_lo = _mm256_and_si256(b, mask32);
    __m256i b_hi = _mm256_srli_epi64(b, 32);

    __m256i p00 = _mm256_mul_epu32(a_lo, b_lo);
    __m256i p01 = _mm256_mul_epu32(a_lo, b_hi);
    __m256i p10 = _mm256_mul_epu32(a_hi, b_lo);
    __m256i p11 = _mm256_mul_epu32(a_hi, b_hi);

    __m256i mid      = _mm256_add_epi64(p01, p10);
    __m256i carry_m  = _mm256_and_si256(_cmpgt_epu64(p01, mid), one);
    __m256i mid_lo   = _mm256_slli_epi64(mid, 32);
    __m256i prod_lo  = _mm256_add_epi64(p00, mid_lo);
    __m256i carry_l  = _mm256_and_si256(_cmpgt_epu64(p00, prod_lo), one);
    __m256i prod_hi  = _mm256_add_epi64(p11, _mm256_srli_epi64(mid, 32));
    prod_hi = _mm256_add_epi64(prod_hi, _mm256_slli_epi64(carry_m, 32));
    prod_hi = _mm256_add_epi64(prod_hi, carry_l);

    /* ── R2 : hik = prod_hi * k  (< 2^74, split 32-bit) ─────────── */
    __m256i h_lo  = _mm256_and_si256(prod_hi, mask32);
    __m256i h_hi  = _mm256_srli_epi64(prod_hi, 32);
    __m256i t0    = _mm256_mul_epu32(h_lo, k_vec);    /* < 2^42 */
    __m256i t1    = _mm256_mul_epu32(h_hi, k_vec);    /* < 2^42 */
    __m256i t1_lo = _mm256_slli_epi64(t1, 32);
    __m256i hik   = _mm256_add_epi64(t0, t1_lo);
    __m256i c_carry = _mm256_srli_epi64(t1, 32);      /* < 2^10 */
    __m256i ov1     = _mm256_and_si256(_cmpgt_epu64(t0, hik), one);
    c_carry = _mm256_add_epi64(c_carry, ov1);          /* < 2^10 + 1 */

    /* ── R3 : r = prod_lo + hik ──────────────────────────────────── */
    __m256i r   = _mm256_add_epi64(prod_lo, hik);
    __m256i ov2 = _mm256_and_si256(_cmpgt_epu64(prod_lo, r), one);
    c_carry = _mm256_add_epi64(c_carry, ov2);           /* < 2^10 + 2 */

    /* ── R4 : correction Mersenne des carries ────────────────────── */
    /* c_carry * k < (k+2)*k < 325*323 < 2^17 — tiny                 */
    __m256i correction = _mm256_mul_epu32(c_carry, k_vec);
    __m256i r_old = r;
    r = _mm256_add_epi64(r, correction);
    /* overflow → r += k (une seule fois, preuve : r_wrapped < 2^17 + k < p) */
    __m256i ov3 = _cmpgt_epu64(r_old, r);   /* 0xFF..FF si débordement */
    r = _mm256_add_epi64(r, _mm256_and_si256(ov3, k_vec));

    /* ── RF : réduction finale constant-time ─────────────────────── */
    __m256i geq = _mm256_or_si256(_cmpgt_epu64(r, p_vec),
                                   _mm256_cmpeq_epi64(r, p_vec));
    r = _mm256_sub_epi64(r, _mm256_and_si256(geq, p_vec));

    return r;
}

#endif /* __AVX2__ */
#endif /* CAGOULE_MATH_AVX2_H */
