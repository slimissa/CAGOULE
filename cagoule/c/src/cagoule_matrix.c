/**
 * cagoule_matrix.c — Matrice de diffusion Vandermonde CAGOULE v3.1.0
 *
 * Nouveautés v2.2.0 :
 *   - Dispatch runtime AVX2 : détection via __builtin_cpu_supports("avx2")
 *     au premier appel (initialisation lazy, thread-safe via __atomic).
 *   - Support CAGOULE_FORCE_SCALAR=1 pour CI sans AVX2.
 *   - Fallback scalaire _matmul16() inchangé vs v2.1.0.
 *   - cagoule_matrix_backend_is_avx2() : exposé pour Python (backend_info).
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/crypto.h> 

#include "cagoule_math.h"
#include "cagoule_matrix.h"

/* ── Déclarations forward des fonctions AVX2 (cagoule_matrix_avx2.c) ─ */
#if defined(__AVX2__)
void cagoule_matrix_mul_avx2(const CagouleMatrix* m,
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N]);
void cagoule_matrix_mul_inv_avx2(const CagouleMatrix* m,
                                   const uint64_t v[CAGOULE_N],
                                   uint64_t out[CAGOULE_N]);
#endif

/* ── Déclarations forward des fonctions NEON (cagoule_matrix_neon.c) ─ */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
void cagoule_matrix_mul_neon(const CagouleMatrix *m,
                               const uint64_t v[CAGOULE_N],
                               uint64_t out[CAGOULE_N]);
void cagoule_matrix_mul_inv_neon(const CagouleMatrix *m,
                                   const uint64_t v[CAGOULE_N],
                                   uint64_t out[CAGOULE_N]);
#endif

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
                /* CORRECTIF (code quality, audit note) : ce fallback force
                 * v = (i*7919) % p et sort de la boucle sans revérifier
                 * qu'il ne collide pas avec un out[j] déjà validé pour
                 * j < i -- contrairement au chemin normal ci-dessous, qui
                 * vérifie explicitement chaque candidat contre TOUS les
                 * out[j] précédents avant de l'accepter.
                 *
                 * Portée réelle du risque : atteindre ce fallback exige
                 * déjà 1 000 000 de collisions consécutives sur un champ
                 * de taille p ≈ 2^64 -- un événement d'une improbabilité
                 * écrasante en usage normal, et non atteignable du tout
                 * sur le chemin de production : params.c::derive_nodes()
                 * garantit des nœuds distincts (via sa propre logique de
                 * ré-échantillonnage) AVANT que cagoule_matrix_build() ne
                 * soit appelé -- cette fonction n'est donc jamais exercée
                 * en usage réel. Ce chemin ne protège que contre un appel
                 * direct et délibérément adversarial de l'API publique
                 * cagoule_matrix_build() avec un tableau nodes[] conçu
                 * pour provoquer des collisions massives.
                 *
                 * Si ce fallback collidait malgré tout avec un out[j]
                 * antérieur, la conséquence n'est PAS une corruption
                 * silencieuse : la matrice résultante serait singulière
                 * (deux nœuds Vandermonde identiques), et
                 * _gauss_jordan_inverse (appelé plus bas dans ce fichier)
                 * détecte déjà ce cas et fait échouer cagoule_matrix_build
                 * proprement (retourne NULL) plutôt que de produire une
                 * matrice incorrecte utilisable. C'est donc un échec net,
                 * pas un bug de sécurité -- mais documenté ici plutôt que
                 * laissé comme un angle mort silencieux, puisque ce n'est
                 * techniquement pas la même garantie que le chemin normal
                 * (vérification explicite avant acceptation, pas une
                 * garantie a posteriori via un échec de construction
                 * plus loin dans le pipeline). */
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

__attribute__((force_align_arg_pointer)) CagouleMatrix* cagoule_matrix_build(const uint64_t* nodes, size_t n, uint64_t p) {
    if (n != CAGOULE_N || !nodes || p < 2) return NULL;

    CagouleMatrix* m = calloc(1, sizeof(CagouleMatrix));
    if (!m) return NULL;
    m->p          = p;
    m->k_mersenne  = cagoule_mersenne_k(p); /* v2.5.0 */

    if (_all_distinct(nodes, n)) {
        _build_vandermonde(m->fwd, nodes, n, p);
        m->kind = CAGOULE_MATRIX_VANDERMONDE;
    } else {
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

    /* ── v2.2.1: Build AVX2-friendly column-major layout ──────────────
     * Transpose each group of 4 rows so that column j is contiguous:
     * fwd_avx2[group][j*4 + lane] = fwd[group*4 + lane][j]
     * This enables _mm256_loadu_si256 instead of _mm256_set_epi64x. */
    for (int group = 0; group < 4; group++) {
        int base_row = group * 4;
        for (int j = 0; j < CAGOULE_N; j++) {
            m->fwd_avx2[group][j * 4 + 0] = m->fwd[base_row + 0][j];
            m->fwd_avx2[group][j * 4 + 1] = m->fwd[base_row + 1][j];
            m->fwd_avx2[group][j * 4 + 2] = m->fwd[base_row + 2][j];
            m->fwd_avx2[group][j * 4 + 3] = m->fwd[base_row + 3][j];
        }
        for (int j = 0; j < CAGOULE_N; j++) {
            m->inv_avx2[group][j * 4 + 0] = m->inv[base_row + 0][j];
            m->inv_avx2[group][j * 4 + 1] = m->inv[base_row + 1][j];
            m->inv_avx2[group][j * 4 + 2] = m->inv[base_row + 2][j];
            m->inv_avx2[group][j * 4 + 3] = m->inv[base_row + 3][j];
        }
    }

    return m;
}

void cagoule_matrix_free(CagouleMatrix* m) {
    if (m) {
        OPENSSL_cleanse(m, sizeof(*m));
        free(m);
    }
}

/* ── Produit matrice-vecteur déroulé (signature harmonisée) ───────── */
void _matmul16_scalar(const uint64_t mat[CAGOULE_N][CAGOULE_N],
                       const uint64_t v[CAGOULE_N],
                       uint64_t out[CAGOULE_N],
                       uint64_t p) {
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

/* ── Lazy reduction matrix multiply (v3.1.0) ──────────────────────── */
/*
 * PRÉCONDITION (audit round 2, vérifiée empiriquement -- 40000 essais
 * fuzz, 8 primes de production) : le vecteur v[] DOIT être de petite
 * magnitude (octet, 0-255 -- ex: cagoule_ctr.c::_ctr_one_block_scalar,
 * blk[] chargé depuis IV/compteur un octet par élément, sans chaînage
 * inter-blocs). mat[][] peut être un élément de corps complet (~p) sans
 * problème -- seul v[] est contraint. Avec v[] en élément de corps
 * complet (ex: bloc CBC chaîné via addmod64 avant l'appel), chaque
 * terme mat[i][j]*v[j] approche p² ≈ 2^128 et l'accumulateur
 * __uint128_t déborde silencieusement -- résultats faux dans 100% des
 * cas testés, PAS une dégradation progressive détectable. Ne PAS
 * appeler cette fonction avec un v[] de magnitude non vérifiée sans
 * refaire ce test. cagoule_cipher.c (CBC, chaînage) utilise
 * délibérément _matmul16_scalar() (sans lazy) pour cette raison exacte.
 */
void _matmul16_scalar_lazy(const uint64_t mat[CAGOULE_N][CAGOULE_N],
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N],
                            uint64_t p, uint64_t k_mersenne)
{
    /* CORRECTIF (P2-6) : la précondition documentée juste au-dessus
     * (v[] doit être octet-range, 0-255) n'était vérifiée nulle part
     * en code -- seulement dans ce commentaire. Un assert compilé sous
     * NDEBUG (voir `make release`, qui définit -DNDEBUG) rend cette
     * précondition auto-vérifiante en debug/test sans coûter quoi que
     * ce soit en release. N'affecte PAS le comportement du chiffreur :
     * un appel correct (v[] déjà octet-range, comme tous les appelants
     * actuels) ne déclenche jamais cet assert. */
    for (int _i = 0; _i < CAGOULE_N; _i++) assert(v[_i] < 256);

    if (k_mersenne > 0) {
        /* Mersenne fast path: accumulate then reduce once */
        for (int i = 0; i < CAGOULE_N; i++) {
            const uint64_t* row = mat[i];
            __uint128_t acc = 0;
            mulacc128(&acc, row[ 0], v[ 0]);
            mulacc128(&acc, row[ 1], v[ 1]);
            mulacc128(&acc, row[ 2], v[ 2]);
            mulacc128(&acc, row[ 3], v[ 3]);
            mulacc128(&acc, row[ 4], v[ 4]);
            mulacc128(&acc, row[ 5], v[ 5]);
            mulacc128(&acc, row[ 6], v[ 6]);
            mulacc128(&acc, row[ 7], v[ 7]);
            mulacc128(&acc, row[ 8], v[ 8]);
            mulacc128(&acc, row[ 9], v[ 9]);
            mulacc128(&acc, row[10], v[10]);
            mulacc128(&acc, row[11], v[11]);
            mulacc128(&acc, row[12], v[12]);
            mulacc128(&acc, row[13], v[13]);
            mulacc128(&acc, row[14], v[14]);
            mulacc128(&acc, row[15], v[15]);
            out[i] = reduce128_mersenne(acc, p, k_mersenne);
        }
    } else {
        /* Generic: accumulate then reduce with DIV */
        for (int i = 0; i < CAGOULE_N; i++) {
            const uint64_t* row = mat[i];
            __uint128_t acc = 0;
            mulacc128(&acc, row[ 0], v[ 0]);
            mulacc128(&acc, row[ 1], v[ 1]);
            mulacc128(&acc, row[ 2], v[ 2]);
            mulacc128(&acc, row[ 3], v[ 3]);
            mulacc128(&acc, row[ 4], v[ 4]);
            mulacc128(&acc, row[ 5], v[ 5]);
            mulacc128(&acc, row[ 6], v[ 6]);
            mulacc128(&acc, row[ 7], v[ 7]);
            mulacc128(&acc, row[ 8], v[ 8]);
            mulacc128(&acc, row[ 9], v[ 9]);
            mulacc128(&acc, row[10], v[10]);
            mulacc128(&acc, row[11], v[11]);
            mulacc128(&acc, row[12], v[12]);
            mulacc128(&acc, row[13], v[13]);
            mulacc128(&acc, row[14], v[14]);
            mulacc128(&acc, row[15], v[15]);
            out[i] = reduce128_generic(acc, p);
        }
    }
}

/* ── Dispatch runtime AVX2 ───────────────────────────────────────────
 *
 * _g_avx2_ready : 0 = non initialisé, 1 = AVX2 dispo, 2 = scalaire.
 * Initialisation lazy — thread-safe via __atomic sur GCC/Clang.
 * CAGOULE_FORCE_SCALAR=1 force le chemin scalaire (CI sans AVX2).
 *
 * v2.5.0 fix: utilise CPUID directement au lieu de __builtin_cpu_supports
 * car ce dernier est désactivé par -mno-avx -mno-avx2.
 */
static volatile int _g_avx2_ready = 0;

/* AVX2 detection via /proc/cpuinfo — reliable and immune to compiler flags.
 * v2.5.1: replaced CPUID asm (broken by GCC 13 -O3 optimization)
 *         with a simple /proc/cpuinfo read that always works.
 *
 * CORRECTIF (audit round 2) : cette approche est Linux-only par
 * construction (/proc n'existe pas sur macOS/Windows/BSD). Sur ces
 * plateformes, fopen() échoue (retourne NULL), cette fonction retourne 0
 * ("pas d'AVX2"), et le chemin scalaire est utilisé inconditionnellement
 * -- MÊME sur un CPU qui supporte réellement AVX2. Ce n'est PAS un bug de
 * correction (le chemin scalaire produit toujours des résultats corrects,
 * juste plus lents) : c'est une limitation de performance/portabilité.
 * L'alternative (CPUID direct) a déjà été essayée et abandonnée -- voir
 * commentaire v2.5.1 ci-dessus -- donc ce n'est pas un remplacement
 * trivial ; documenté ici plutôt que "corrigé" pour ne pas réintroduire
 * la fragilité déjà rencontrée avec l'approche CPUID.
 */
#include <string.h>
static int _check_avx2_cpuid(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;  /* non-Linux, ou /proc restreint : fallback scalaire silencieux */
    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "flags") && strstr(line, "avx2")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}


static int _avx2_available(void) {
    int state = __atomic_load_n(&_g_avx2_ready, __ATOMIC_ACQUIRE);
    if (state == 0) {
        if (getenv("CAGOULE_FORCE_SCALAR")) {
            __atomic_store_n(&_g_avx2_ready, 2, __ATOMIC_RELEASE);
            return 0;
        }
        int avx2 = _check_avx2_cpuid();
        int new_state = avx2 ? 1 : 2;
        __atomic_store_n(&_g_avx2_ready, new_state, __ATOMIC_RELEASE);
        return avx2 ? 1 : 0;
    }
    return state == 1;
}

/* ── Garde Barrett : AVX2 requiert p > 2^63 ───────────────────────── */
#define CAGOULE_AVX2_P_MIN  ((uint64_t)1 << 63)

/* ── API publique — mul forward ─────────────────────────────────────── */
void cagoule_matrix_mul(const CagouleMatrix* m,
                        const uint64_t v[CAGOULE_N],
                        uint64_t out[CAGOULE_N])
{
#if defined(__AVX2__)
    if (_avx2_available() && m->p >= CAGOULE_AVX2_P_MIN) {
        cagoule_matrix_mul_avx2(m, v, out);
        return;
    }
#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
    /* ARM NEON — v3.1.0 Feature 3. Toujours actif sur ARM (pas de
     * détection runtime nécessaire : NEON est obligatoire sur ARMv8-A). */
    if (m->p >= CAGOULE_AVX2_P_MIN) {
        cagoule_matrix_mul_neon(m, v, out);
        return;
    }
#endif
    uint64_t tmp[CAGOULE_N];
    _matmul16_scalar(m->fwd, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

/* ── API publique — mul inverse ─────────────────────────────────────── */
void cagoule_matrix_mul_inv(const CagouleMatrix* m,
                            const uint64_t v[CAGOULE_N],
                            uint64_t out[CAGOULE_N])
{
#if defined(__AVX2__)
    if (_avx2_available() && m->p >= CAGOULE_AVX2_P_MIN) {
        cagoule_matrix_mul_inv_avx2(m, v, out);
        return;
    }
#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
    if (m->p >= CAGOULE_AVX2_P_MIN) {
        cagoule_matrix_mul_inv_neon(m, v, out);
        return;
    }
#endif
    uint64_t tmp[CAGOULE_N];
    _matmul16_scalar(m->inv, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

/* ── Scalaire explicit — CI sans AVX2 et tests de parité ────────────── */
void cagoule_matrix_mul_scalar(const CagouleMatrix* m,
                                const uint64_t v[CAGOULE_N],
                                uint64_t out[CAGOULE_N])
{
    uint64_t tmp[CAGOULE_N];
    _matmul16_scalar(m->fwd, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

void cagoule_matrix_mul_inv_scalar(const CagouleMatrix* m,
                                    const uint64_t v[CAGOULE_N],
                                    uint64_t out[CAGOULE_N])
{
    uint64_t tmp[CAGOULE_N];
    _matmul16_scalar(m->inv, v, tmp, m->p);
    memcpy(out, tmp, CAGOULE_N * sizeof(uint64_t));
}

/* ── Requête backend — exposé à Python via ctypes ────────────────────── */
int cagoule_matrix_backend_is_avx2(void) {
    return _avx2_available();
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