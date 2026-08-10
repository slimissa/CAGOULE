/**
 * cagoule_matrix_neon.c — Multiplication matricielle Vandermonde NEON (ARM)
 * CAGOULE v3.1.0 Feature 3
 *
 * Port 2-lane du pipeline AVX2 4-lane de cagoule_matrix_avx2.c.
 * Réutilise le layout column-major fwd_avx2[4][N*4] existant dans
 * CagouleMatrix — les 2 lanes NEON lisent les 2 premiers uint64 de
 * chaque quartet stocké pour AVX2 (lanes 0,1) ; les lanes 2,3 du même
 * quartet sont traitées par un second vld1q_u64 décalé.
 *
 * Stratégie : double accumulateur (passe A : j pair, passe B : j impair)
 * sur 8 groupes de 2 lignes (rows 0-1, 2-3, ..., 14-15), soit 8
 * paires d'accumulateurs (acc_a[8], acc_b[8]).
 *
 * Le MSB flip requis par _cmpgt_epu64 AVX2 (bug de conception d'Intel —
 * _mm256_cmpgt_epi64 est signed uniquement) est ABSENT ici : vcgtq_u64
 * est nativement non signé sur ARM. Voir cagoule_math_neon.h.
 */
#include "cagoule_matrix.h"
#include "cagoule_math_neon.h"

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

#include <arm_neon.h>
#include <string.h>

/* ── Accumulation 2-lane NEON ──────────────────────────────────────
 * Inline loops below are the canonical implementation — no macro needed.
 * The compiler unrolls the 8-group loop automatically. */

/* ── Helper interne — une passe sur les 16 colonnes, 2 rows à la fois  */
static void _matmul_neon_pass(const uint64_t mat[4][CAGOULE_N * 4],
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N],
                               uint64_t p, uint64_t k_mersenne)
{
    uint64x2_t p_vec = vdupq_n_u64(p);
    /* Accumulateurs: 8 groupes × 2 (pair+impair) = 16 uint64x2_t.
     * group g traite rows {g*2, g*2+1} = lanes 0,1 du quartet AVX2 de grp g/2. */
    uint64x2_t acc_a[8], acc_b[8];
    for (int g = 0; g < 8; g++) acc_a[g] = acc_b[g] = vdupq_n_u64(0);

    if (k_mersenne > 0) {
        uint64x2_t k_vec = vdupq_n_u64(k_mersenne);
        for (int j = 0; j < CAGOULE_N; j += 2) {   /* j pair */
            uint64x2_t vj = vdupq_n_u64(v[j]);
            for (int g = 0; g < 8; g++) {
                /* mat stocké en fwd_avx2[grp][j*4 + lane] — grp=g/2, lane=g%2*2 */
                int grp  = g / 2;
                int lane = (g % 2) * 2;
                uint64x2_t row = vld1q_u64(&mat[grp][j*4 + lane]);
                acc_a[g] = addmod64x2_neon(acc_a[g],
                    mulmod_mersenne64x2_neon(row, vj, p_vec, k_vec), p_vec);
            }
        }
        for (int j = 1; j < CAGOULE_N; j += 2) {   /* j impair */
            uint64x2_t vj = vdupq_n_u64(v[j]);
            for (int g = 0; g < 8; g++) {
                int grp  = g / 2;
                int lane = (g % 2) * 2;
                uint64x2_t row = vld1q_u64(&mat[grp][j*4 + lane]);
                acc_b[g] = addmod64x2_neon(acc_b[g],
                    mulmod_mersenne64x2_neon(row, vj, p_vec, k_vec), p_vec);
            }
        }
    } else {
        uint64_t mu_scalar = cagoule_barrett_mu_neon(p);
        uint64x2_t mu_vec = vdupq_n_u64(mu_scalar);
        for (int j = 0; j < CAGOULE_N; j += 2) {
            uint64x2_t vj = vdupq_n_u64(v[j]);
            for (int g = 0; g < 8; g++) {
                int grp  = g / 2;
                int lane = (g % 2) * 2;
                uint64x2_t row = vld1q_u64(&mat[grp][j*4 + lane]);
                acc_a[g] = addmod64x2_neon(acc_a[g],
                    mulmod64x2_neon(row, vj, p_vec, mu_vec), p_vec);
            }
        }
        for (int j = 1; j < CAGOULE_N; j += 2) {
            uint64x2_t vj = vdupq_n_u64(v[j]);
            for (int g = 0; g < 8; g++) {
                int grp  = g / 2;
                int lane = (g % 2) * 2;
                uint64x2_t row = vld1q_u64(&mat[grp][j*4 + lane]);
                acc_b[g] = addmod64x2_neon(acc_b[g],
                    mulmod64x2_neon(row, vj, p_vec, mu_vec), p_vec);
            }
        }
    }

    /* Merge et store */
    for (int g = 0; g < 8; g++) {
        uint64x2_t result = addmod64x2_neon(acc_a[g], acc_b[g], p_vec);
        /* rows {g*2, g*2+1} */
        out[g*2]     = vgetq_lane_u64(result, 0);
        out[g*2 + 1] = vgetq_lane_u64(result, 1);
    }
}

void cagoule_matrix_mul_neon(const CagouleMatrix *m,
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N])
{
    _matmul_neon_pass(m->fwd_avx2, v, out, m->p, m->k_mersenne);
}

void cagoule_matrix_mul_inv_neon(const CagouleMatrix *m,
                                   const uint64_t v[CAGOULE_N],
                                   uint64_t out[CAGOULE_N])
{
    _matmul_neon_pass(m->inv_avx2, v, out, m->p, m->k_mersenne);
}

/**
 * Détection runtime NEON — bindings/reporting uniquement (v3.1.0
 * release audit, tâche 3). Miroir de cagoule_matrix_backend_is_avx2()
 * (cagoule_matrix_avx2.c). Ce fichier n'est compilé que sur aarch64
 * (voir Makefile : `SRCS += src/cagoule_matrix_neon.c` sous
 * `ifeq ($(shell uname -m),aarch64)`) -- donc le symbole n'existe même
 * pas dans libcagoule.so sur x86_64. Côté Python (_binding.py), la
 * détection de ce symbole se fait via try/except AttributeError,
 * exactement comme pour _HAS_AVX2_API/_HAS_CTR_API -- son absence sur
 * x86_64 est le signal normal, pas une erreur.
 *
 * Retourne 1 si compilé ET si __ARM_NEON était défini au moment de la
 * compilation (donc si cagoule_matrix_mul_neon() ci-dessus est le
 * vrai chemin NEON, pas un stub). N'a jamais été exécuté sur matériel
 * ARM réel (cross-compilé uniquement -- voir CHANGELOG v3.0.0/roadmap) ;
 * ce flag reporte donc "compilé disponible", pas "validé en production".
 */
int cagoule_matrix_backend_is_neon(void) {
    return 1;
}

#endif /* __ARM_NEON */
