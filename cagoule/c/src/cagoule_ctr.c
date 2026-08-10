/**
 * cagoule_ctr.c — CTR Mode CAGOULE v3.1.0
 *
 * Pipeline keystream :
 *   Bloc bi → counter_block[16] (un octet par uint64) → matrix → sbox →
 *   add_rk → keystream[16] = {out[j] & 0xFF}
 *
 * 4x variant : 4 blocs indépendants traités simultanément pour ILP maximal.
 * Residual (n_blocks % 4) traité en scalaire dans la même fonction.
 *
 * Zéro branchement sur données secrètes dans le pipeline C.
 * Z-Domain Shifting appliqué inline (zo_byte[16] sur la stack).
 */

#include <stdlib.h>
#include <string.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"
#include "cagoule_ctr.h"

#if defined(__AVX2__)
#include <immintrin.h>
#include "cagoule_math_avx2.h"
#include "cagoule_sbox_avx2.h"
#endif

/* ── Performance profiling (compile with -DPROFILE_CTR to enable) ─── */
#ifdef PROFILE_CTR
#include <time.h>
static struct {
    uint64_t t_build;    /* _build_counter_block        */
    uint64_t t_matrix;   /* matrix multiplication        */
    uint64_t t_sbox;     /* S-box forward                */
    uint64_t t_rk_add;   /* round key addition           */
    uint64_t t_xor;      /* XOR + Z-shift                */
    uint64_t n_blocks;   /* total blocks processed       */
    uint64_t n_calls;    /* number of _ctr_process calls */
} _prof = {0};

static inline uint64_t _now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

#define PROFILE_START(var)  uint64_t _t_##var = _now_ns()
#define PROFILE_END(var)    _prof.t_##var += (_now_ns() - _t_##var)
#define PROFILE_INC(var)    _prof.n_##var++
#else
#define PROFILE_START(var)
#define PROFILE_END(var)
#define PROFILE_INC(var)
#endif

#define N CAGOULE_N

extern void _matmul16_scalar(const uint64_t[CAGOULE_N][CAGOULE_N],
                              const uint64_t[CAGOULE_N],
                              uint64_t[CAGOULE_N], uint64_t);

#if defined(__AVX2__)
extern void cagoule_matrix_mul_avx2(const CagouleMatrix*,
                                     const uint64_t[CAGOULE_N],
                                     uint64_t[CAGOULE_N]);
/* CTR-only lazy variant — deferred reduction. SAFE ONLY for byte-range
 * v[] (CTR counter blocks). CBC must never call this — see definition.
 *
 * DISPATCH (v3.1.0 performance pass): _ctr_one_block_avx2 and
 * _ctr_four_blocks_avx2 (below) call this function directly and
 * unconditionally — there is no runtime toggle between this and the
 * non-lazy cagoule_matrix_mul_avx2 within the AVX2 path itself. The
 * actual branch point that matters is one level up, in _ctr_process:
 * `_avx2_ok() && sbox->use_feistel` decides AVX2 vs scalar for the
 * whole CTR pipeline (matrix + S-box together, not matrix alone). Once
 * that condition selects AVX2, this lazy function is always what runs
 * for the matrix step — an earlier design draft during this pass
 * considered adding a separate `_ctr_use_avx2_matrix()` toggle to allow
 * falling back to the non-lazy function within the AVX2 path as a
 * safety net; that toggle was never implemented — this comment
 * documents what actually shipped, not that earlier draft. If a fast
 * revert is ever needed, the two call sites below are the only places
 * to change, and CBC's call sites (cagoule_cipher.c) are entirely
 * separate and unaffected either way. */
extern void cagoule_matrix_mul_avx2_lazy(const CagouleMatrix*,
                                          const uint64_t[CAGOULE_N],
                                          uint64_t[CAGOULE_N]);
#endif

extern void _matmul16_scalar_lazy(const uint64_t[CAGOULE_N][CAGOULE_N],
                                   const uint64_t[CAGOULE_N],
                                   uint64_t[CAGOULE_N],
                                   uint64_t, uint64_t);
                                   
/* ── Détection AVX2 ─────────────────────────────────────────────────── */
static int _avx2_ok(void) {
#if defined(__AVX2__)
    return __builtin_cpu_supports("avx2");
#else
    return 0;
#endif
}

/* ══════════════════════════════════════════════════════════════════════
 * Helpers internes
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * _build_counter_block — Construit les 16 éléments du bloc compteur.
 *
 * Disposition :
 *   blk[0..7]  = octets de iv   (big-endian uint64), un octet par élément
 *   blk[8..15] = octets de bi   (big-endian uint64), un octet par élément
 *
 * Chaque élément est dans [0, 255] — identique à l'entrée CBC plaintext.
 * La combinaison (iv, bi) est unique par (password, session, block position).
 */
static inline void _build_counter_block(uint64_t bi, const uint8_t iv[8],
                                          uint64_t blk[N]) {
    /* IV : 8 octets → éléments [0..7] */
    blk[0] = iv[0]; blk[1] = iv[1]; blk[2] = iv[2]; blk[3] = iv[3];
    blk[4] = iv[4]; blk[5] = iv[5]; blk[6] = iv[6]; blk[7] = iv[7];
    /* Counter bi : big-endian uint64 → éléments [8..15] */
    /* SÉCURITÉ : bi est uint64_t. Après 2^64 blocs (= 2^68 octets = 256 EiB),
     * bi déborde à 0 → réutilisation du keystream (CTR counter wraparound).
     * Limite documentée dans SECURITY.md. Re-dériver les paramètres avant
     * d'atteindre 2^64 blocs par clé. */
    blk[ 8] = (bi >> 56) & 0xFF;
    blk[ 9] = (bi >> 48) & 0xFF;
    blk[10] = (bi >> 40) & 0xFF;
    blk[11] = (bi >> 32) & 0xFF;
    blk[12] = (bi >> 24) & 0xFF;
    blk[13] = (bi >> 16) & 0xFF;
    blk[14] = (bi >>  8) & 0xFF;
    blk[15] = (bi >>  0) & 0xFF;
}

/**
 * _pré-calcul zo_byte[16] depuis z_offset uint64.
 * Identique à cagoule_cipher.c.
 */
static inline void _precompute_zo_byte(const uint64_t* zo, size_t nzo,
                                          uint8_t zo_byte[N]) {
    if (!zo || nzo < (size_t)N) { memset(zo_byte, 0, N); return; }
    for (int i = 0; i < N; i++)
        zo_byte[i] = (uint8_t)(zo[i] % 256);
}

/* ── Chemin scalaire ─────────────────────────────────────────────────── */

/**
 * _ctr_one_block_scalar — Un bloc compteur → 16 octets de keystream (scalaire).
 */
static void _ctr_one_block_scalar(uint64_t bi, const uint8_t iv[8],
                                    const CagouleMatrix* mat,
                                    const CagouleSBox64* sbox,
                                    const uint64_t* rk, size_t nk,
                                    uint64_t p,
                                    uint8_t ks[N])
{
    uint64_t blk[N], tmp[N];
    
    PROFILE_START(build);
    _build_counter_block(bi, iv, blk);
    PROFILE_END(build);
    
    PROFILE_START(matrix);
    _matmul16_scalar_lazy(mat->fwd, blk, tmp, p, mat->k_mersenne);
    PROFILE_END(matrix);
    
    PROFILE_START(sbox);
    cagoule_sbox_block_forward(sbox, tmp, blk, N);
    PROFILE_END(sbox);
    
    PROFILE_START(rk_add);
    uint64_t k = rk[bi % nk];
    for (int j = 0; j < N; j++)
        ks[j] = (uint8_t)((addmod64(blk[j], k, p)) & 0xFF);
    PROFILE_END(rk_add);
}

/* ── Chemin AVX2 ─────────────────────────────────────────────────────── */

#if defined(__AVX2__)

/**
 * _ctr_one_block_avx2 — Un bloc compteur → 16 octets de keystream (AVX2).
 *
 * Le bloc compteur est dans [0,255]^16, donc pas de bswap nécessaire :
 * les éléments sont de simples octets étendus à uint64.
 */
static void _ctr_one_block_avx2(uint64_t bi, const uint8_t iv[8],
                                   const CagouleMatrix* mat,
                                   const CagouleSBox64* sbox,
                                   const uint64_t* rk, size_t nk,
                                   uint64_t p,
                                   uint8_t ks[N])
{
    uint64_t blk[N], tmp[N];
    _build_counter_block(bi, iv, blk);
    cagoule_matrix_mul_avx2_lazy(mat, blk, tmp);
    _sbox_block_forward_hot_avx2(sbox, tmp, blk, N);

    /* add round_key via addmod64x4 SIMD */
    /* CORRECTIF v3.1.0 (Finding 1) : type-pun union pour éviter UBSan
     * implicit-conversion sur les primes Mersenne-64 (> INT64_MAX). */
    union { uint64_t u; int64_t s; } pun_p = { .u = p };
    union { uint64_t u; int64_t s; } pun_rk = { .u = rk[bi % nk] };
    __m256i pv = _mm256_set1_epi64x(pun_p.s);
    __m256i rv = _mm256_set1_epi64x(pun_rk.s);
    for (int j = 0; j < N; j += 4) {
        __m256i b = _mm256_loadu_si256((const __m256i*)(blk + j));
        b = addmod64x4(b, rv, pv);
        _mm256_storeu_si256((__m256i*)(blk + j), b);
    }

    /* Extraction keystream : low byte de chaque uint64 */
    for (int j = 0; j < N; j++)
        ks[j] = (uint8_t)(blk[j] & 0xFF);
}

/**
 * _ctr_four_blocks_avx2 — 4 blocs compteurs simultanés → 4 × 16 = 64 octets keystream.
 *
 * Les 4 blocs bi, bi+1, bi+2, bi+3 sont indépendants → ILP maximal.
 * Le CPU schedule les 4 pipelines matrix+sbox+rk en parallèle sur les ports
 * d'exécution vectorielle disponibles.
 */
static void _ctr_four_blocks_avx2(uint64_t bi, const uint8_t iv[8],
                                     const CagouleMatrix* mat,
                                     const CagouleSBox64* sbox,
                                     const uint64_t* rk, size_t nk,
                                     uint64_t p,
                                     uint8_t ks[4 * N])
{
    /* 4 blocs compteurs indépendants */
    uint64_t blk0[N], blk1[N], blk2[N], blk3[N];
    uint64_t tmp0[N], tmp1[N], tmp2[N], tmp3[N];

    _build_counter_block(bi + 0, iv, blk0);
    _build_counter_block(bi + 1, iv, blk1);
    _build_counter_block(bi + 2, iv, blk2);
    _build_counter_block(bi + 3, iv, blk3);

    /* Matrix : 4 appels indépendants — le CPU les recouvre en OOO */
    cagoule_matrix_mul_avx2_lazy(mat, blk0, tmp0);
    cagoule_matrix_mul_avx2_lazy(mat, blk1, tmp1);
    cagoule_matrix_mul_avx2_lazy(mat, blk2, tmp2);
    cagoule_matrix_mul_avx2_lazy(mat, blk3, tmp3);

    /* S-box : 4 appels indépendants */
    _sbox_block_forward_hot_avx2(sbox, tmp0, blk0, N);
    _sbox_block_forward_hot_avx2(sbox, tmp1, blk1, N);
    _sbox_block_forward_hot_avx2(sbox, tmp2, blk2, N);
    _sbox_block_forward_hot_avx2(sbox, tmp3, blk3, N);

    /* Round keys (broadcasts une seule fois par bloc) */
    /* CORRECTIF v3.1.0 (Finding 1) : type-pun union pour UBSan */
    union { uint64_t u; int64_t s; } pun_p4 = { .u = p };
    union { uint64_t u; int64_t s; } pun_rk0 = { .u = rk[(bi + 0) % nk] };
    union { uint64_t u; int64_t s; } pun_rk1 = { .u = rk[(bi + 1) % nk] };
    union { uint64_t u; int64_t s; } pun_rk2 = { .u = rk[(bi + 2) % nk] };
    union { uint64_t u; int64_t s; } pun_rk3 = { .u = rk[(bi + 3) % nk] };
    __m256i pv  = _mm256_set1_epi64x(pun_p4.s);
    __m256i rv0 = _mm256_set1_epi64x(pun_rk0.s);
    __m256i rv1 = _mm256_set1_epi64x(pun_rk1.s);
    __m256i rv2 = _mm256_set1_epi64x(pun_rk2.s);
    __m256i rv3 = _mm256_set1_epi64x(pun_rk3.s);

    for (int j = 0; j < N; j += 4) {
        __m256i b0 = _mm256_loadu_si256((const __m256i*)(blk0 + j));
        __m256i b1 = _mm256_loadu_si256((const __m256i*)(blk1 + j));
        __m256i b2 = _mm256_loadu_si256((const __m256i*)(blk2 + j));
        __m256i b3 = _mm256_loadu_si256((const __m256i*)(blk3 + j));
        _mm256_storeu_si256((__m256i*)(blk0 + j), addmod64x4(b0, rv0, pv));
        _mm256_storeu_si256((__m256i*)(blk1 + j), addmod64x4(b1, rv1, pv));
        _mm256_storeu_si256((__m256i*)(blk2 + j), addmod64x4(b2, rv2, pv));
        _mm256_storeu_si256((__m256i*)(blk3 + j), addmod64x4(b3, rv3, pv));
    }

    /* Extraction : low byte de chaque uint64 → 4 × 16 octets */
    for (int j = 0; j < N; j++) {
        ks[j +  0] = (uint8_t)(blk0[j] & 0xFF);
        ks[j + 16] = (uint8_t)(blk1[j] & 0xFF);
        ks[j + 32] = (uint8_t)(blk2[j] & 0xFF);
        ks[j + 48] = (uint8_t)(blk3[j] & 0xFF);
    }
}

#endif /* __AVX2__ */

/* ══════════════════════════════════════════════════════════════════════
 * API publique
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * cagoule_ctr_keystream — v3.0.0
 *
 * Génère n_blocks blocs de keystream (n_blocks × 16 octets) à partir
 * du bloc compteur start_bi.
 */
int cagoule_ctr_keystream(
    const uint8_t*       iv,
    size_t               start_bi,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      rk,
    size_t               nk,
    uint64_t             p,
    uint8_t*             out,
    size_t               n_blocks)
{
    if (!iv || !mat || !sbox || !rk) return CAGOULE_ERR_NULL;
    if (n_blocks == 0) return CAGOULE_OK;  /* Zéro blocs : no-op légal */
    if (!out) return CAGOULE_ERR_NULL;

#if defined(__AVX2__)
    if (_avx2_ok() && sbox->use_feistel) {
        size_t bi = start_bi;
        /* Traitement 4 par 4 */
        for (; bi + 4 <= start_bi + n_blocks; bi += 4) {
            _ctr_four_blocks_avx2(bi, iv, mat, sbox, rk, nk, p,
                                    out + (bi - start_bi) * N);
        }
        /* Résidu */
        for (; bi < start_bi + n_blocks; bi++) {
            _ctr_one_block_avx2(bi, iv, mat, sbox, rk, nk, p,
                                  out + (bi - start_bi) * N);
        }
        _mm256_zeroupper();
        return CAGOULE_OK;
    }
#endif

    /* Fallback scalaire */
    for (size_t bi = start_bi; bi < start_bi + n_blocks; bi++) {
        _ctr_one_block_scalar(bi, iv, mat, sbox, rk, nk, p,
                               out + (bi - start_bi) * N);
    }
    return CAGOULE_OK;
}

/**
 * _ctr_process — Core CTR encryption/decryption (internal).
 *
 * @param encrypt_mode  1 = encrypt (add zo before XOR), 0 = decrypt (subtract zo after XOR)
 */
static int _ctr_process(
    const uint8_t*       src,
    size_t               src_len,
    const uint8_t*       iv,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      rk,
    size_t               nk,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo,
    uint8_t*             dst,
    size_t               dst_size,
    int                  encrypt_mode)
{
    
    if (!iv || !mat || !sbox || !rk) return CAGOULE_ERR_NULL;
    if (src_len == 0) return CAGOULE_OK;
    if (!src || !dst) return CAGOULE_ERR_NULL;
    if (dst_size < src_len) return CAGOULE_ERR_SIZE;

    uint8_t zo_byte[N] = {0};
    int use_zo = (z_offset && num_zo >= (size_t)N);
    if (use_zo) _precompute_zo_byte(z_offset, num_zo, zo_byte);

    size_t n_full   = src_len / N;
    size_t residual = src_len % N;

#ifdef PROFILE_CTR
    /* Force scalar path for profiling */
    goto scalar_path;
#endif

#if defined(__AVX2__)
    if (_avx2_ok() && sbox->use_feistel) {
        uint8_t ks[4 * N];
        size_t  bi = 0;

        for (; bi + 4 <= n_full; bi += 4) {
            if (bi + 8 <= n_full) {
                __builtin_prefetch(src + (bi + 4) * N, 0, 1);
                __builtin_prefetch(src + (bi + 5) * N, 0, 1);
                __builtin_prefetch(src + (bi + 6) * N, 0, 1);
                __builtin_prefetch(src + (bi + 7) * N, 0, 1);
            }
            _ctr_four_blocks_avx2(bi, iv, mat, sbox, rk, nk, p, ks);

            for (int b = 0; b < 4; b++) {
                const uint8_t* s = src + (bi + b) * N;
                uint8_t*       d = dst + (bi + b) * N;
                const uint8_t* k = ks  + b * N;
                for (int j = 0; j < N; j++) {
                    if (use_zo) {
                        if (encrypt_mode)
                            d[j] = (uint8_t)(((s[j] + zo_byte[j]) & 0xFF) ^ k[j]);
                        else
                            d[j] = (uint8_t)((s[j] ^ k[j]) - zo_byte[j] + 256) & 0xFF;
                    } else {
                        d[j] = s[j] ^ k[j];
                    }
                }
            }
        }

        for (; bi < n_full; bi++) {
            uint8_t ks1[N];
            _ctr_one_block_avx2(bi, iv, mat, sbox, rk, nk, p, ks1);
            const uint8_t* s = src + bi * N;
            uint8_t*       d = dst + bi * N;
            for (int j = 0; j < N; j++) {
                if (use_zo) {
                    if (encrypt_mode)
                        d[j] = (uint8_t)(((s[j] + zo_byte[j]) & 0xFF) ^ ks1[j]);
                    else
                        d[j] = (uint8_t)((s[j] ^ ks1[j]) - zo_byte[j] + 256) & 0xFF;
                } else {
                    d[j] = s[j] ^ ks1[j];
                }
            }
        }

        if (residual > 0) {
            uint8_t ks1[N];
            _ctr_one_block_avx2(n_full, iv, mat, sbox, rk, nk, p, ks1);
            const uint8_t* s = src + n_full * N;
            uint8_t*       d = dst + n_full * N;
            for (size_t j = 0; j < residual; j++) {
                if (use_zo) {
                    if (encrypt_mode)
                        d[j] = (uint8_t)(((s[j] + zo_byte[j]) & 0xFF) ^ ks1[j]);
                    else
                        d[j] = (uint8_t)((s[j] ^ ks1[j]) - zo_byte[j] + 256) & 0xFF;
                } else {
                    d[j] = s[j] ^ ks1[j];
                }
            }
        }
        PROFILE_INC(calls);

        _mm256_zeroupper();
#ifdef PROFILE_CTR
        _prof.n_blocks += n_full + (residual > 0 ? 1 : 0);
#endif
        return CAGOULE_OK;
    }
#endif
#ifdef PROFILE_CTR
scalar_path:
#endif
    /* Scalaire */
    for (size_t bi = 0; bi < n_full; bi++) {
        uint8_t ks[N];
        _ctr_one_block_scalar(bi, iv, mat, sbox, rk, nk, p, ks);
        const uint8_t* s = src + bi * N;
        uint8_t*       d = dst + bi * N;
        for (int j = 0; j < N; j++) {
            if (use_zo) {
                if (encrypt_mode)
                    d[j] = (uint8_t)(((s[j] + zo_byte[j]) & 0xFF) ^ ks[j]);
                else
                    d[j] = (uint8_t)((s[j] ^ ks[j]) - zo_byte[j] + 256) & 0xFF;
            } else {
                d[j] = s[j] ^ ks[j];
            }
        }
    }
    if (residual > 0) {
        uint8_t ks[N];
        _ctr_one_block_scalar(n_full, iv, mat, sbox, rk, nk, p, ks);
        const uint8_t* s = src + n_full * N;
        uint8_t*       d = dst + n_full * N;
        for (size_t j = 0; j < residual; j++) {
            if (use_zo) {
                if (encrypt_mode)
                    d[j] = (uint8_t)(((s[j] + zo_byte[j]) & 0xFF) ^ ks[j]);
                else
                    d[j] = (uint8_t)((s[j] ^ ks[j]) - zo_byte[j] + 256) & 0xFF;
            } else {
                d[j] = s[j] ^ ks[j];
            }
        }
    }
    PROFILE_INC(calls);
#ifdef PROFILE_CTR
    _prof.n_blocks += n_full + (residual > 0 ? 1 : 0);
#endif

    return CAGOULE_OK;
}

/**
 * cagoule_ctr_encrypt — v3.0.0
 *
 * Chiffrement CTR.
 * Longueur ciphertext == longueur plaintext. Pas de PKCS7.
 * CTR est symétrique : même keystream pour encrypt et decrypt.
 */
int cagoule_ctr_encrypt(
    const uint8_t*       pt,
    size_t               pt_len,
    const uint8_t*       iv,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      rk,
    size_t               nk,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo,
    uint8_t*             out,
    size_t               out_size)
{
    return _ctr_process(pt, pt_len, iv, mat, sbox, rk, nk, p,
                         z_offset, num_zo, out, out_size, 1);
}

/**
 * cagoule_ctr_decrypt — v3.0.0
 *
 * Déchiffrement CTR. CTR étant symétrique, la seule différence avec encrypt
 * est l'inversion du Z-Domain Shifting :
 *   encrypt : ct[j] = ((pt[j] + zo[j]) & 0xFF) ^ ks[j]
 *   decrypt : pt[j] = ((ct[j] ^ ks[j]) - zo[j] + 256) & 0xFF
 */
int cagoule_ctr_decrypt(
    const uint8_t*       ct,
    size_t               ct_len,
    const uint8_t*       iv,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      rk,
    size_t               nk,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo,
    uint8_t*             out,
    size_t               out_size)
{
    return _ctr_process(ct, ct_len, iv, mat, sbox, rk, nk, p,
                         z_offset, num_zo, out, out_size, 0);
}

/**
 * cagoule_ctr_encrypt_4x — API Python explicite pour le pipeline 4x.
 *
 * Identique à cagoule_ctr_encrypt (qui dispatch déjà en 4x si AVX2).
 * Exposé séparément pour les benchmarks et le binding Python.
 */
int cagoule_ctr_encrypt_4x(
    const uint8_t*       pt,
    size_t               pt_len,
    const uint8_t*       iv,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      rk,
    size_t               nk,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo,
    uint8_t*             out,
    size_t               out_size)
{
    return cagoule_ctr_encrypt(pt, pt_len, iv, mat, sbox, rk, nk, p,
                                z_offset, num_zo, out, out_size);
}

#ifdef PROFILE_CTR
#include <stdio.h>
void cagoule_ctr_print_profile(void) {
    if (_prof.n_calls == 0) return;
    double total = _prof.t_build + _prof.t_matrix + _prof.t_sbox 
                 + _prof.t_rk_add + _prof.t_xor;
    printf("\n── CTR Pipeline Profile (%llu blocks) ──\n", 
           (unsigned long long)_prof.n_blocks);
    printf("  build_counter  : %5.1f%%  (%llu ns)\n",
           100.0 * _prof.t_build / total, (unsigned long long)_prof.t_build);
    printf("  matrix_mul     : %5.1f%%  (%llu ns)\n",
           100.0 * _prof.t_matrix / total, (unsigned long long)_prof.t_matrix);
    printf("  sbox_forward   : %5.1f%%  (%llu ns)\n",
           100.0 * _prof.t_sbox / total, (unsigned long long)_prof.t_sbox);
    printf("  rk_add         : %5.1f%%  (%llu ns)\n",
           100.0 * _prof.t_rk_add / total, (unsigned long long)_prof.t_rk_add);
    printf("  xor+zshift     : %5.1f%%  (%llu ns)\n",
           100.0 * _prof.t_xor / total, (unsigned long long)_prof.t_xor);
    printf("  total per block: %.1f ns\n", total / _prof.n_blocks);
    printf("──────────────────────────────────────────\n");
}
#endif