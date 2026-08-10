/**
 * cagoule_matrix.h — Matrice de diffusion Vandermonde 16×16 mod p
 *
 * Interface publique de matrix.c.
 * Opère sur des éléments uint64_t dans Z/pZ, p premier ≈ 2^64.
 */

#ifndef CAGOULE_MATRIX_H
#define CAGOULE_MATRIX_H

#include <stdint.h>
#include <stddef.h>

#define CAGOULE_N 16   /* Taille de bloc fixe (ne pas modifier) */

/* Type de matrice (debug/fallback) */
typedef enum {
    CAGOULE_MATRIX_VANDERMONDE = 0,
    CAGOULE_MATRIX_CAUCHY      = 1
} CagouleMatrixKind;

/* ── Structure ─────────────────────────────────────────────────────── */
typedef struct {
    uint64_t fwd[CAGOULE_N][CAGOULE_N];   /* Matrice P (forward) — row-major */
    uint64_t inv[CAGOULE_N][CAGOULE_N];   /* Matrice P^-1 (inverse) — row-major */
    uint64_t p;                           /* Nombre premier de travail */
    CagouleMatrixKind kind;               /* Type réel (Vandermonde/Cauchy) */
    /* ── v2.2.1: AVX2-friendly column-major layout ────────────────────
     * fwd_avx2[group][j*4 + lane] = fwd[group*4 + lane][j]
     * group = 0..3 (rows 0-3, 4-7, 8-11, 12-15)
     * j     = 0..15 (column index)
     * lane  = 0..3 (row within the group)
     * Enables _mm256_loadu_si256 instead of _mm256_set_epi64x. */
    uint64_t fwd_avx2[4][CAGOULE_N * 4];
    uint64_t inv_avx2[4][CAGOULE_N * 4];
    uint64_t k_mersenne; /* v2.5.0: k tel que p=2^64-k. 0 → Barrett fallback */
} CagouleMatrix;

/* ── API ────────────────────────────────────────────────────────────── */

/**
 * Construit la matrice de Vandermonde depuis les nœuds.
 * Si les nœuds ont des collisions, bascule sur Cauchy automatiquement.
 *
 * @param nodes  Tableau de CAGOULE_N nœuds distincts dans [0, p)
 * @param n      DOIT être == CAGOULE_N (sinon retourne NULL)
 * @param p      Nombre premier de travail (>= 2)
 * @return       CagouleMatrix* alloué sur le tas, ou NULL si erreur
 */
CagouleMatrix* cagoule_matrix_build(const uint64_t* nodes, size_t n, uint64_t p);

/**
 * Libère la mémoire allouée par cagoule_matrix_build().
 */
void cagoule_matrix_free(CagouleMatrix* m);

/**
 * Produit matrice-vecteur : out = P × v mod p
 * Dispatch automatique AVX2 / scalaire selon le CPU au premier appel.
 */
void cagoule_matrix_mul(const CagouleMatrix* m,
                        const uint64_t v[CAGOULE_N],
                        uint64_t out[CAGOULE_N]);

/**
 * Produit matrice-vecteur inverse : out = P^-1 × v mod p
 * Dispatch automatique AVX2 / scalaire.
 */
void cagoule_matrix_mul_inv(const CagouleMatrix* m,
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N]);

/**
 * Chemin scalaire explicite — pour CI sans AVX2 et tests de parité.
 * Identique au résultat de cagoule_matrix_mul() sur toute entrée.
 */
void cagoule_matrix_mul_scalar(const CagouleMatrix* m,
                                const uint64_t v[CAGOULE_N],
                                uint64_t out[CAGOULE_N]);

void cagoule_matrix_mul_inv_scalar(const CagouleMatrix* m,
                                    const uint64_t v[CAGOULE_N],
                                    uint64_t out[CAGOULE_N]);

void _matmul16_scalar_lazy(const uint64_t mat[CAGOULE_N][CAGOULE_N],
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N],
                            uint64_t p, uint64_t k_mersenne);
                            
/**
 * Retourne 1 si le backend AVX2 est actif, 0 sinon.
 * Exposé à Python via ctypes pour backend_info.
 */
int cagoule_matrix_backend_is_avx2(void);

/* ── v3.1.0 Feature 3 — ARM NEON backend ─────────────────────────── */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
void cagoule_matrix_mul_neon(const CagouleMatrix *m,
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N]);
void cagoule_matrix_mul_inv_neon(const CagouleMatrix *m,
                                   const uint64_t v[CAGOULE_N],
                                   uint64_t out[CAGOULE_N]);

/**
 * Retourne 1 si le backend NEON est compilé et actif, 0 sinon.
 * Symbole présent uniquement dans les builds aarch64 (voir Makefile) --
 * absent du .so sur x86_64, à détecter côté Python via
 * try/except AttributeError, pas via un appel direct non protégé.
 */
int cagoule_matrix_backend_is_neon(void);
#endif

/**
 * Vérifie que P × P^-1 == I mod p.
 * @return 1 si correct, 0 sinon
 */
int cagoule_matrix_verify(const CagouleMatrix* m);

/**
 * Produit matrice-vecteur scalaire direct — pour cipher.c après hoisting.
 * v2.3.0: exposé pour éviter le dispatch par bloc.
 */
void _matmul16_scalar(const uint64_t mat[CAGOULE_N][CAGOULE_N],
                       const uint64_t v[CAGOULE_N],
                       uint64_t out[CAGOULE_N],
                       uint64_t p);

#endif /* CAGOULE_MATRIX_H */