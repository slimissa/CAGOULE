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
    uint64_t fwd[CAGOULE_N][CAGOULE_N];   /* Matrice P (forward)  */
    uint64_t inv[CAGOULE_N][CAGOULE_N];   /* Matrice P^-1 (inverse) */
    uint64_t p;                           /* Nombre premier de travail */
    CagouleMatrixKind kind;               /* Type réel (Vandermonde/Cauchy) */
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
 * Déroulé statiquement pour n=16.
 *
 * @param m    Matrice initialisée
 * @param v    Vecteur d'entrée (CAGOULE_N éléments)
 * @param out  Vecteur de sortie (CAGOULE_N éléments, peut être == v)
 */
void cagoule_matrix_mul(const CagouleMatrix* m,
                        const uint64_t v[CAGOULE_N],
                        uint64_t out[CAGOULE_N]);

/**
 * Produit matrice-vecteur inverse : out = P^-1 × v mod p
 */
void cagoule_matrix_mul_inv(const CagouleMatrix* m,
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N]);

/**
 * Vérifie que P × P^-1 == I mod p.
 * @return 1 si correct, 0 sinon
 */
int cagoule_matrix_verify(const CagouleMatrix* m);

#endif /* CAGOULE_MATRIX_H */