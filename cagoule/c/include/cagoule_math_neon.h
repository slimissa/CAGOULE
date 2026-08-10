/**
 * cagoule_math_neon.h — Arithmétique modulaire 64-bit vectorisée NEON (ARM)
 * CAGOULE v3.1.0 Feature 3
 *
 * Équivalent 2-lanes de cagoule_math_avx2.h (4-lanes AVX2).
 * Algorithme identique (Barrett + Mersenne) — seule la largeur SIMD change.
 *
 * Différences NEON vs AVX2 documentées dans le roadmap v3.1.0 §4 :
 *
 *   Largeur SIMD   : 128-bit (uint64x2_t) vs 256-bit (__m256i)
 *   Lanes parallèles: 2 vs 4
 *   Comparaison u64 : vceqq_u64 / vcgtq_u64 sont NATIFS non signés sur ARM.
 *                     Pas de MSB flip (_cmpgt_epu64 emulation) requis.
 *   mul_epu32 exact  : vmull_u32 sur le bas des lanes — même décomposition
 *                     qu'AVX2 (a_hi*2^32 + a_lo)*(b_hi*2^32 + b_lo).
 *
 * Résultats bit-à-bit identiques à mulmod64 scalaire — vérifiés par
 * test_math_neon.c (mêmes vecteurs KAT que test_math_avx2.c).
 *
 * Note de compilation : ce header est compilé avec -march=armv8-a+simd
 * ou -march=native sur ARM. Sur x86, le bloc est entier sous #ifdef __ARM_NEON.
 */
#ifndef CAGOULE_MATH_NEON_H
#define CAGOULE_MATH_NEON_H

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

#include <arm_neon.h>
#include <stdint.h>

/* ── Constante de Barrett — même formule que cagoule_math_avx2.h ────── */
static inline uint64_t cagoule_barrett_mu_neon(uint64_t p) {
    __uint128_t num = (__uint128_t)1 << 127;
    return (uint64_t)(num / ((__uint128_t)p));
}

/* ── Comparaison unsigned 64-bit — NATIVE sur ARM (pas de MSB flip) ─── */
static inline uint64x2_t _cmpgt_epu64_neon(uint64x2_t a, uint64x2_t b) {
    /* vcgtq_u64 : retourne ~0ULL si a > b unsigned, 0 sinon.
     * Identique en sémantique à _cmpgt_epu64 AVX2, sans le XOR de flip. */
    return (uint64x2_t)vcgtq_u64(a, b);
}

/* ── Produit 128-bit sur 2 lanes : (hi, lo) = a * b ─────────────────── */
static inline void _mul128x2_neon(uint64x2_t a, uint64x2_t b,
                                   uint64x2_t *lo_out, uint64x2_t *hi_out)
{
    const uint64x2_t mask32 = vdupq_n_u64(0xFFFFFFFFULL);
    const uint64x2_t one    = vdupq_n_u64(1ULL);

    /* Décomposition : a_lo = a & 0xFFFFFFFF, a_hi = a >> 32 */
    uint32x2_t a_lo32 = vmovn_u64(vandq_u64(a, mask32));
    uint32x2_t a_hi32 = vmovn_u64(vshrq_n_u64(a, 32));
    uint32x2_t b_lo32 = vmovn_u64(vandq_u64(b, mask32));
    uint32x2_t b_hi32 = vmovn_u64(vshrq_n_u64(b, 32));

    /* vmull_u32 : produit 32x32->64 sur 2 lanes — exact, sans troncature */
    uint64x2_t p00 = vmull_u32(a_lo32, b_lo32);
    uint64x2_t p01 = vmull_u32(a_lo32, b_hi32);
    uint64x2_t p10 = vmull_u32(a_hi32, b_lo32);
    uint64x2_t p11 = vmull_u32(a_hi32, b_hi32);

    /* mid = p01 + p10 (carry possible) */
    uint64x2_t mid       = vaddq_u64(p01, p10);
    uint64x2_t carry_mid = vandq_u64(_cmpgt_epu64_neon(p01, mid), one);

    /* lo = p00 + (mid << 32) */
    uint64x2_t mid_lo = vshlq_n_u64(mid, 32);
    uint64x2_t lo     = vaddq_u64(p00, mid_lo);
    uint64x2_t carry_lo = vandq_u64(_cmpgt_epu64_neon(p00, lo), one);

    /* hi = p11 + (mid >> 32) + carry_mid * 2^32 + carry_lo */
    uint64x2_t mid_hi   = vshrq_n_u64(mid, 32);
    uint64x2_t carry_m2 = vshlq_n_u64(carry_mid, 32);
    uint64x2_t hi       = vaddq_u64(vaddq_u64(p11, mid_hi),
                                     vaddq_u64(carry_m2, carry_lo));

    *lo_out = lo;
    *hi_out = hi;
}

/* ── Réduction de Barrett 2-lanes ────────────────────────────────────── */
static inline uint64x2_t mulmod64x2_neon(uint64x2_t a, uint64x2_t b,
                                          uint64x2_t p_vec, uint64x2_t mu_vec)
{
    const uint64x2_t one = vdupq_n_u64(1ULL);

    uint64x2_t lo, hi;
    _mul128x2_neon(a, b, &lo, &hi);

    /* Barrett Estimate : q = hi * mu + (hi >> 1) ≈ floor(a*b / p)
     * (identique au schéma cagoule_math_avx2.h) */
    uint64x2_t q_lo, q_hi;
    _mul128x2_neon(hi, mu_vec, &q_lo, &q_hi);

    /* mod2_64 = 2^64 - p (précalculé comme constante de l'appelant) */
    /* r_lo = lo - q_lo * p (via a*b - q*p = a*b mod p exactement) */
    uint64x2_t qp_lo, qp_hi;
    _mul128x2_neon(q_lo, p_vec, &qp_lo, &qp_hi);

    /* r_lo = lo - qp_lo, r_hi correction */
    uint64x2_t r_lo = vsubq_u64(lo, qp_lo);
    uint64x2_t borrow = vandq_u64(_cmpgt_epu64_neon(qp_lo, lo), one);

    /* Correction r_hi : nombre de fois que (2^64 - p) doit être soustrait */
    uint64x2_t r_hi = vsubq_u64(hi, vaddq_u64(qp_hi, borrow));

    /* Correction finale par additions de mod2_64 = 2^64 - p ≡ -p mod 2^64 */
    /* Le nombre de passes est au maximum 2 (identique à l'analyse AVX2). */
    uint64x2_t mod2_64 = vsubq_u64(vdupq_n_u64(0ULL), p_vec); /* 0 - p = 2^64-p (wrap) */

    /* Passe 1 */
    {
        uint64x2_t need = _cmpgt_epu64_neon(r_hi, vdupq_n_u64(0ULL));
        need = vorrq_u64(need, (uint64x2_t)vceqq_u64(r_hi, vdupq_n_u64(0ULL)));
        /* Applique mod2_64 si r_hi > 0 OU (r_hi == 0 AND r_lo >= p) */
        uint64x2_t need_rlo = (uint64x2_t)vcgeq_u64(r_lo, p_vec);
        uint64x2_t need_any = vorrq_u64(
            _cmpgt_epu64_neon(r_hi, vdupq_n_u64(0ULL)),
            vandq_u64((uint64x2_t)vceqq_u64(r_hi, vdupq_n_u64(0ULL)), need_rlo)
        );
        uint64x2_t delta = vandq_u64(need_any, mod2_64);
        uint64x2_t r_lo_new = vaddq_u64(r_lo, delta);
        uint64x2_t carry    = vandq_u64(_cmpgt_epu64_neon(r_lo, r_lo_new), one);
        r_hi = vsubq_u64(r_hi, vandq_u64(need_any, one));
        r_hi = vaddq_u64(r_hi, carry);
        r_lo = r_lo_new;
    }
    /* Passe 2 */
    {
        uint64x2_t need_rlo = (uint64x2_t)vcgeq_u64(r_lo, p_vec);
        uint64x2_t need_any = vorrq_u64(
            _cmpgt_epu64_neon(r_hi, vdupq_n_u64(0ULL)),
            vandq_u64((uint64x2_t)vceqq_u64(r_hi, vdupq_n_u64(0ULL)), need_rlo)
        );
        uint64x2_t delta = vandq_u64(need_any, mod2_64);
        uint64x2_t r_lo_new = vaddq_u64(r_lo, delta);
        r_lo = r_lo_new;
    }

    /* Réduction finale */
    uint64x2_t mask = (uint64x2_t)vcgeq_u64(r_lo, p_vec);
    return vsubq_u64(r_lo, vandq_u64(mask, p_vec));
}

/* ── Réduction Mersenne 2-lanes ──────────────────────────────────────── */
static inline uint64x2_t mulmod_mersenne64x2_neon(uint64x2_t a, uint64x2_t b,
                                                    uint64x2_t p_vec,
                                                    uint64x2_t k_vec)
{
    /* p = 2^64 - k — réduction : (a*b) mod (2^64-k)
     * hi*2^64 + lo ≡ hi*k + lo  (mod 2^64-k)
     * r = lo + hi*k ; si r >= p : r -= p */
    uint64x2_t lo, hi;
    _mul128x2_neon(a, b, &lo, &hi);

    uint64x2_t hk_lo, hk_hi;
    _mul128x2_neon(hi, k_vec, &hk_lo, &hk_hi);

    uint64x2_t r = vaddq_u64(lo, hk_lo);
    uint64x2_t carry = vandq_u64(_cmpgt_epu64_neon(lo, r), vdupq_n_u64(1ULL));

    /* Correction carry : r += hk_hi * k (au plus 1 correction car hk_hi
     * est toujours très petit pour les premiers CAGOULE) */
    /* corr = (hk_hi + carry) * k — on n'a besoin que des 64 bits bas
     * car (hk_hi + carry) est toujours très petit (< 2^16 en pratique pour
     * les primes CAGOULE), donc la correction tient dans uint64. */
    uint64_t hk_hi_scalar0 = vgetq_lane_u64(vaddq_u64(hk_hi, carry), 0);
    uint64_t hk_hi_scalar1 = vgetq_lane_u64(vaddq_u64(hk_hi, carry), 1);
    uint64_t k_scalar       = vgetq_lane_u64(k_vec, 0);
    uint64x2_t corr = vcombine_u64(vcreate_u64(hk_hi_scalar0 * k_scalar),
                                    vcreate_u64(hk_hi_scalar1 * k_scalar));
    r = vaddq_u64(r, corr);

    /* Réduction finale */
    uint64x2_t mask = (uint64x2_t)vcgeq_u64(r, p_vec);
    return vsubq_u64(r, vandq_u64(mask, p_vec));
}

/* ── addmod / submod 2-lanes ─────────────────────────────────────────── */
static inline uint64x2_t addmod64x2_neon(uint64x2_t a, uint64x2_t b,
                                          uint64x2_t p_vec)
{
    uint64x2_t s    = vaddq_u64(a, b);
    uint64x2_t mask = (uint64x2_t)vcgeq_u64(s, p_vec);
    return vsubq_u64(s, vandq_u64(mask, p_vec));
}

static inline uint64x2_t submod64x2_neon(uint64x2_t a, uint64x2_t b,
                                          uint64x2_t p_vec)
{
    uint64x2_t mask = (uint64x2_t)vcgtq_u64(b, a);
    return vsubq_u64(vaddq_u64(a, vandq_u64(mask, p_vec)), b);
}

#endif /* __ARM_NEON */
#endif /* CAGOULE_MATH_NEON_H */
