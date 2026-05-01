/**
 * matrix.c — Matrice de diffusion Vandermonde CAGOULE v2.0.0
 *
 * Remplace matrix.py (Python pur) par du C optimisé.
 * Chaque multiplication mod p : ≈5 cycles C vs ≈500 cycles Python.
 * Gain global pour 1 MB (65 536 blocs × 256 mul) : ×40–100.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cagoule_math.h"
#include "cagoule_matrix.h"

/* ── Helpers internes ──────────────────────────────────────────────── */

/* Construit la matrice de Vandermonde : M[i][j] = nodes[i]^j mod p */
static void _build_vandermonde(uint64_t mat[CAGOULE_N][CAGOULE_N],
                                const uint64_t* nodes, size_t n, uint64_t p)
{
    for (size_t i = 0; i < n; i++) {
        uint64_t power = 1;
        for (size_t j = 0; j < n; j++) {
            mat[i][j] = power;
            power = mulmod64(power, nodes[i], p);
        }
    }
}

/* Construit la matrice de Cauchy (version SANS fallback dangereux) */
static int _build_cauchy_safe(uint64_t mat[CAGOULE_N][CAGOULE_N],
                               const uint64_t* alpha, const uint64_t* beta,
                               size_t n, uint64_t p)
{
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++) {
            uint64_t denom = addmod64(alpha[i], beta[j], p);
            if (denom == 0) {
                return 0;  /* Annulation interdite */
            }
            mat[i][j] = invmod64(denom, p);
        }
    }
    return 1;
}

/* Vérifie si les nœuds sont tous distincts */
static int _all_distinct(const uint64_t* nodes, size_t n) {
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (nodes[i] == nodes[j]) return 0;
    return 1;
}

/* Rend les nœuds distincts par incrémentation (avec sécurité) */
static void _make_distinct(uint64_t* out, const uint64_t* in, size_t n, uint64_t p) {
    for (size_t i = 0; i < n; i++) {
        uint64_t v = in[i] % p;
        int dup, attempts = 0;
        do {
            if (++attempts > 1000000) {
                /* Fallback : utilisation de l'index comme graine */
                v = (uint64_t)(i * 7919) % p;
                break;
            }
            dup = 0;
            for (size_t j = 0; j < i; j++) {
                if (out[j] == v) {
                    v = (v + 1) % p;
                    dup = 1;
                    break;
                }
            }
        } while (dup);
        out[i] = v;
    }
}

/* ── Inversion Gauss-Jordan mod p ─────────────────────────────────── */
static int _gauss_jordan_inverse(uint64_t dst[CAGOULE_N][CAGOULE_N],
                                  const uint64_t src[CAGOULE_N][CAGOULE_N],
                                  size_t n, uint64_t p)
{
    uint64_t (*aug)[2 * CAGOULE_N] = malloc(n * sizeof(*aug));
    if (!aug) return 0;

    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < n; j++)
            aug[i][j] = src[i][j];
        for (size_t j = 0; j < n; j++)
            aug[i][n + j] = (i == j) ? 1 : 0;
    }

    for (size_t col = 0; col < n; col++) {
        size_t pivot = n;
        for (size_t row = col; row < n; row++) {
            if (aug[row][col] != 0) { pivot = row; break; }
        }
        if (pivot == n) { free(aug); return 0; }

        if (pivot != col) {
            for (size_t k = 0; k < 2 * n; k++) {
                uint64_t tmp = aug[col][k];
                aug[col][k] = aug[pivot][k];
                aug[pivot][k] = tmp;
            }
        }

        uint64_t inv_diag = invmod64(aug[col][col], p);
        for (size_t k = 0; k < 2 * n; k++)
            aug[col][k] = mulmod64(aug[col][k], inv_diag, p);

        for (size_t row = 0; row < n; row++) {
            if (row == col || aug[row][col] == 0) continue;
            uint64_t factor = aug[row][col];
            for (size_t k = 0; k < 2 * n; k++) {
                uint64_t sub = mulmod64(factor, aug[col][k], p);
                aug[row][k] = submod64(aug[row][k], sub, p);
            }
        }
    }

    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < n; j++)
            dst[i][j] = aug[i][n + j];

    free(aug);
    return 1;
}

/* ── API publique ───────────────────────────────────────────────────── */

CagouleMatrix* cagoule_matrix_build(const uint64_t* nodes, size_t n, uint64_t p) {
    if (n != CAGOULE_N || !nodes || p < 2) return NULL;

    CagouleMatrix* m = calloc(1, sizeof(CagouleMatrix));
    if (!m) return NULL;
    m->p = p;

    /* Tenter Vandermonde si nœuds distincts */
    if (_all_distinct(nodes, n)) {
        _build_vandermonde(m->fwd, nodes, n, p);
        m->kind = CAGOULE_MATRIX_VANDERMONDE;
    } else {
        /* Fallback Cauchy */
        uint64_t alpha[CAGOULE_N], beta[CAGOULE_N];
        _make_distinct(alpha, nodes, n, p);

        uint64_t beta_start = p / 2 + 1;
        for (size_t i = 0; i < n; i++)
            beta[i] = (beta_start + i * 7919) % p;

        for (size_t i = 0; i < n; i++) {
            for (size_t j = 0; j < i; j++) {
                while (beta[i] == beta[j])
                    beta[i] = (beta[i] + 1) % p;
            }
            for (size_t k = 0; k < n; k++) {
                while (addmod64(alpha[k], beta[i], p) == 0)
                    beta[i] = (beta[i] + 1) % p;
            }
        }

        if (!_build_cauchy_safe(m->fwd, alpha, beta, n, p)) {
            free(m);
            return NULL;
        }
        m->kind = CAGOULE_MATRIX_CAUCHY;
    }

    if (!_gauss_jordan_inverse(m->inv, m->fwd, n, p)) {
        free(m);
        return NULL;
    }

    return m;
}

void cagoule_matrix_free(CagouleMatrix* m) {
    free(m);
}

/* ── Produit matrice-vecteur déroulé (signature harmonisée) ───────── */
static void _matmul16(const uint64_t mat[CAGOULE_N][CAGOULE_N],
                       const uint64_t v[CAGOULE_N],
                       uint64_t out[CAGOULE_N],
                       uint64_t p)
{
    for (int i = 0; i < CAGOULE_N; i++) {
        const uint64_t* row = mat[i];
        __uint128_t s = 0;
        s += mulmod64(row[ 0], v[ 0], p);
        s += mulmod64(row[ 1], v[ 1], p);
        s += mulmod64(row[ 2], v[ 2], p);
        s += mulmod64(row[ 3], v[ 3], p);
        s += mulmod64(row[ 4], v[ 4], p);
        s += mulmod64(row[ 5], v[ 5], p);
        s += mulmod64(row[ 6], v[ 6], p);
        s += mulmod64(row[ 7], v[ 7], p);
        s += mulmod64(row[ 8], v[ 8], p);
        s += mulmod64(row[ 9], v[ 9], p);
        s += mulmod64(row[10], v[10], p);
        s += mulmod64(row[11], v[11], p);
        s += mulmod64(row[12], v[12], p);
        s += mulmod64(row[13], v[13], p);
        s += mulmod64(row[14], v[14], p);
        s += mulmod64(row[15], v[15], p);
        out[i] = (uint64_t)(s % p);
    }
}

void cagoule_matrix_mul(const CagouleMatrix* m,
                        const uint64_t v[CAGOULE_N],
                        uint64_t out[CAGOULE_N])
{
    uint64_t tmp[CAGOULE_N];
    _matmul16(m->fwd, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

void cagoule_matrix_mul_inv(const CagouleMatrix* m,
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N])
{
    uint64_t tmp[CAGOULE_N];
    _matmul16(m->inv, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

int cagoule_matrix_verify(const CagouleMatrix* m) {
    uint64_t v[CAGOULE_N], fwd[CAGOULE_N], back[CAGOULE_N];
    for (int i = 0; i < CAGOULE_N; i++) {
        memset(v, 0, sizeof(v));
        v[i] = 1;
        cagoule_matrix_mul(m, v, fwd);
        cagoule_matrix_mul_inv(m, fwd, back);
        if (back[i] != 1) return 0;
        for (int j = 0; j < CAGOULE_N; j++)
            if (j != i && back[j] != 0) return 0;
    }
    return 1;
}