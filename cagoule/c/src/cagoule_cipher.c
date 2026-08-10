/**
 * cagoule_cipher.c — Pipeline CBC CAGOULE v3.1.0
 *
 * v2.5.4 — Z-Domain Shifting inline (no malloc) :
 *   z_offset[16] ∈ Z/pZ transmis depuis Python.
 *   Appliqué comme whitening additif sur les OCTETS du plaintext :
 *     encrypt : byte[j] = (byte[j] + zo[j] % 256) % 256  AVANT chiffrement
 *     decrypt : byte[j] = (byte[j] - zo[j] % 256 + 256) % 256  APRÈS déchiffrement
 *   L'opération est en Z/256Z (byte domain), pas en Z/pZ.
 *   Les zo[j] sont des uint64 dérivés de k_master via HKDF — zo[j]%256 est
 *   indistinguable d'un octet aléatoire pour un attaquant sans k_master.
 *
 *   Implémentation :
 * v2.5.4: Z-shift applied inline in _load_plain / _cbc_unsub — no malloc, no copy.
 *     Pré-calcul : zo_byte[16] = {zo[i]%256, ...} → 1 tableau de 16 uint8.
 *     Cost : 1 modulo par octet, ~6-8 ms/MB en C (vs 82 ms en Python).
 *
 * v2.4.0 — Pipeline multi-blocs SIMD, pipeline4, prefetch.
 */

#include <stdlib.h>
#include <string.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"

#if defined(__AVX2__)
#include <immintrin.h>
#include "cagoule_math_avx2.h"
#include "cagoule_sbox_avx2.h"
#endif

#define N CAGOULE_N

extern void _matmul16_scalar(const uint64_t[CAGOULE_N][CAGOULE_N],
                              const uint64_t[CAGOULE_N],
                              uint64_t[CAGOULE_N], uint64_t);

#if defined(__AVX2__)
extern void cagoule_matrix_mul_avx2(const CagouleMatrix*,
                                     const uint64_t[CAGOULE_N],
                                     uint64_t[CAGOULE_N]);
extern void cagoule_matrix_mul_inv_avx2(const CagouleMatrix*,
                                         const uint64_t[CAGOULE_N],
                                         uint64_t[CAGOULE_N]);
#endif

/* ── Helpers sérialisation ─────────────────────────────────────────── */
static inline size_t _pb(uint64_t p) { return cagoule_p_bytes(p); }

static inline void _u64_to_be(uint64_t v, uint8_t* b, size_t pb) {
    for (size_t i = pb; i-- > 0;) { b[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}
static inline uint64_t _be_to_u64(const uint8_t* b, size_t pb) {
    uint64_t v = 0;
    for (size_t i = 0; i < pb; i++) v = (v << 8) | b[i];
    return v;
}

static int _avx2_ok(void) {
#if defined(__AVX2__)
    return __builtin_cpu_supports("avx2");
#else
    return 0;
#endif
}

/* ══════════════════════════════════════════════════════════════════════
 * Z-Domain Shifting — niveau octet
 *
 * zo_byte[16] = {zo[0]%256, ..., zo[15]%256}
 * Appliqué comme whitening additif sur le plaintext (avant chiffrement)
 * et soustrait après déchiffrement.
 * ══════════════════════════════════════════════════════════════════════ */

/* Pré-calculer les 16 octets de z_offset */
static inline void _precompute_zo_byte(const uint64_t* zo, size_t nzo,
                                         uint8_t zo_byte[N]) {
    if (!zo || nzo < (size_t)N) { memset(zo_byte, 0, N); return; }
    for (int i = 0; i < N; i++)
        zo_byte[i] = (uint8_t)(zo[i] % 256);
}

/* v2.5.4: _apply_zshift and _undo_zshift removed — Z-shift now applied inline in _load_plain/_cbc_unsub */

#if defined(__AVX2__)
/* ── Sérialisation AVX2 ─────────────────────────────────────────────── */

static inline __m256i _bswap64x4(__m256i v) {
    const __m256i mask = _mm256_set_epi8(
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,
        8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7);
    return _mm256_shuffle_epi8(v, mask);
}

static inline void _store_blk(const uint64_t bl[N], uint8_t* dst) {
    __m256i r;
    r = _mm256_set_epi64x((int64_t)bl[3],(int64_t)bl[2],(int64_t)bl[1],(int64_t)bl[0]);
    _mm256_storeu_si256((__m256i*)(dst+  0), _bswap64x4(r));
    r = _mm256_set_epi64x((int64_t)bl[7],(int64_t)bl[6],(int64_t)bl[5],(int64_t)bl[4]);
    _mm256_storeu_si256((__m256i*)(dst+ 32), _bswap64x4(r));
    r = _mm256_set_epi64x((int64_t)bl[11],(int64_t)bl[10],(int64_t)bl[9],(int64_t)bl[8]);
    _mm256_storeu_si256((__m256i*)(dst+ 64), _bswap64x4(r));
    r = _mm256_set_epi64x((int64_t)bl[15],(int64_t)bl[14],(int64_t)bl[13],(int64_t)bl[12]);
    _mm256_storeu_si256((__m256i*)(dst+ 96), _bswap64x4(r));
}

static inline void _load_blk(const uint8_t* src, uint64_t bl[N]) {
    __m256i r;
    r = _mm256_loadu_si256((const __m256i*)(src+  0));
    _mm256_storeu_si256((__m256i*)&bl[0],  _bswap64x4(r));
    r = _mm256_loadu_si256((const __m256i*)(src+ 32));
    _mm256_storeu_si256((__m256i*)&bl[4],  _bswap64x4(r));
    r = _mm256_loadu_si256((const __m256i*)(src+ 64));
    _mm256_storeu_si256((__m256i*)&bl[8],  _bswap64x4(r));
    r = _mm256_loadu_si256((const __m256i*)(src+ 96));
    _mm256_storeu_si256((__m256i*)&bl[12], _bswap64x4(r));
}

/* v2.5.4: Z-shift applied inline — no malloc needed */
static inline void _load_plain(const uint8_t* src, uint64_t bl[N],
                                const uint8_t zo_byte[N]) {
    /* Load 16 bytes, apply Z-shift if zo_byte is provided, zero-extend to uint64 */
    uint8_t tmp[16];
    if (zo_byte) {
        /* CORRECTIF (audit round 2, M5) : masque explicite & 0xFF au lieu
         * de compter sur la promotion entière implicite (uint8_t+uint8_t
         * -> int) puis troncature via le cast (uint8_t). Résultat
         * identique (la somme max est 510, tient dans un int, aucun UB
         * dans les deux versions) mais l'intention "mod 256" est
         * maintenant explicite dans le code, pas seulement dans le
         * commentaire. Aligné sur l'idiome déjà utilisé dans le chemin
         * scalaire de cagoule_ctr.c : (uint8_t)((s[j] + zo_byte[j]) & 0xFF). */
        for (int j = 0; j < 16; j++)
            tmp[j] = (uint8_t)((src[j] + zo_byte[j]) & 0xFF);
    } else {
        memcpy(tmp, src, 16);
    }
    __m128i raw = _mm_loadu_si128((const __m128i*)tmp);
    _mm256_storeu_si256((__m256i*)&bl[0],
        _mm256_cvtepu8_epi64(_mm_srli_si128(raw,  0)));
    _mm256_storeu_si256((__m256i*)&bl[4],
        _mm256_cvtepu8_epi64(_mm_srli_si128(raw,  4)));
    _mm256_storeu_si256((__m256i*)&bl[8],
        _mm256_cvtepu8_epi64(_mm_srli_si128(raw,  8)));
    _mm256_storeu_si256((__m256i*)&bl[12],
        _mm256_cvtepu8_epi64(_mm_srli_si128(raw, 12)));
}

static inline void _rk_add(uint64_t bl[N], uint64_t rk, uint64_t p) {
    union { uint64_t u; int64_t s; } pun_p = { .u = p };
    union { uint64_t u; int64_t s; } pun_r = { .u = rk };
    __m256i pv = _mm256_set1_epi64x(pun_p.s);
    __m256i rv = _mm256_set1_epi64x(pun_r.s);
    for (int j = 0; j < N; j += 4) {
        __m256i b = _mm256_loadu_si256((const __m256i*)(bl+j));
        _mm256_storeu_si256((__m256i*)(bl+j), addmod64x4(b, rv, pv));
    }
}

static inline void _rk_sub(uint64_t bl[N], uint64_t rk, uint64_t p) {
    union { uint64_t u; int64_t s; } pun_p = { .u = p };
    union { uint64_t u; int64_t s; } pun_r = { .u = rk };
    __m256i pv = _mm256_set1_epi64x(pun_p.s);
    __m256i rv = _mm256_set1_epi64x(pun_r.s);
    for (int j = 0; j < N; j += 4) {
        __m256i b = _mm256_loadu_si256((const __m256i*)(bl+j));
        _mm256_storeu_si256((__m256i*)(bl+j), submod64x4(b, rv, pv));
    }
}

static inline void _cbc_add(uint64_t bl[N], const uint64_t prev[N], uint64_t p) {
    union { uint64_t u; int64_t s; } pun_p = { .u = p };
    __m256i pv = _mm256_set1_epi64x(pun_p.s);
    for (int j = 0; j < N; j += 4) {
        __m256i b = _mm256_loadu_si256((const __m256i*)(bl+j));
        __m256i v = _mm256_loadu_si256((const __m256i*)(prev+j));
        _mm256_storeu_si256((__m256i*)(bl+j), addmod64x4(b, v, pv));
    }
}

/* v2.5.4: inverse Z-shift applied inline */
static inline int _cbc_unsub(const uint64_t m[N], const uint64_t prev[N],
                               uint8_t* dst, uint64_t p,
                               const uint8_t zo_byte[N]) {
    union { uint64_t u; int64_t s; } pun_p = { .u = p };
    __m256i pv = _mm256_set1_epi64x(pun_p.s);
    uint64_t tmp[N];
    for (int j = 0; j < N; j += 4) {
        __m256i a = _mm256_loadu_si256((const __m256i*)(m+j));
        __m256i v = _mm256_loadu_si256((const __m256i*)(prev+j));
        _mm256_storeu_si256((__m256i*)(tmp+j), submod64x4(a, v, pv));
    }
    for (int j = 0; j < N; j++) {
        if (tmp[j] > 255) return 0;
        /* CORRECTIF (audit round 2) : `tmp[j] - zo_byte[j]` peut sous-
         * déborder si tmp[j] < zo_byte[j] (ex: tmp[j]=5, zo_byte[j]=200) --
         * `tmp[j]` est uint64_t, `zo_byte[j]` un uint8_t promu en
         * uint64_t pour la soustraction. Le débordement non signé est un
         * comportement DÉFINI en C (arithmétique modulaire, pas d'UB) :
         * le résultat s'enroule vers ~2^64, mais `& 0xFF` n'en extrait
         * que l'octet bas, qui coïncide exactement avec la soustraction
         * modulo 256 voulue (inverse de l'addition `(src[j]+zo_byte[j])
         * & 0xFF` côté chiffrement dans _load_plain). Vérifié
         * exhaustivement : 256×256 = 65536 combinaisons, 0 écart avec
         * une soustraction modulo 256 en arithmétique signée de
         * référence. Correct mais non évident sans connaître cette
         * propriété -- d'où ce commentaire plutôt qu'un changement de
         * code (le masquage & 0xFF est déjà explicite ici, contrairement
         * au cas corrigé dans _load_plain/M5).
         */
        dst[j] = (uint8_t)(zo_byte ? ((tmp[j] - zo_byte[j]) & 0xFF) : tmp[j]);
    }
    return 1;
}

/* ── Encrypt mono-bloc ───────────────────────────────────────────────── */
static int _enc_mono(const uint8_t* padded, size_t nb, uint8_t* out, size_t os,
                      const CagouleMatrix* mat, const CagouleSBox64* sb,
                      const uint64_t* rk, size_t nk, uint64_t p,
                      const uint8_t zo_byte[N])
{
    size_t pb = _pb(p);
    if (os < nb*N*pb) return CAGOULE_ERR_SIZE;
    uint64_t buf[2][N]; memset(buf,0,sizeof(buf));
    uint64_t *prev=buf[0], *blk=buf[1], tmp[N];
    for (size_t bi=0; bi<nb; bi++) {
        _load_plain(padded+bi*N, blk, zo_byte);
        _cbc_add(blk, prev, p);
        cagoule_matrix_mul_avx2(mat, blk, tmp);
        _sbox_block_forward_hot_avx2(sb, tmp, blk, N);
        _rk_add(blk, rk[bi%nk], p);
        _store_blk(blk, out+bi*N*pb);
        uint64_t* sw=prev; prev=blk; blk=sw;
    }
    _mm256_zeroupper(); return CAGOULE_OK;
}

/* ── Encrypt pipeline4 ──────────────────────────────────────────────── */
static int _enc_p4(const uint8_t* padded, size_t nb, uint8_t* out, size_t os,
                    const CagouleMatrix* mat, const CagouleSBox64* sb,
                    const uint64_t* rk, size_t nk, uint64_t p,
                    const uint8_t zo_byte[N])
{
    size_t pb = _pb(p);
    if (os < nb*N*pb) return CAGOULE_ERR_SIZE;
    uint64_t prev[N], blk[N], tmp[N]; memset(prev,0,N*8);
    size_t bi=0;
    for (; bi+4<=nb; bi+=4) {
        if (bi+8<=nb) {
            __builtin_prefetch(padded+(bi+4)*N,0,1);
            __builtin_prefetch(padded+(bi+5)*N,0,1);
            __builtin_prefetch(padded+(bi+6)*N,0,1);
            __builtin_prefetch(padded+(bi+7)*N,0,1);
        }
        /* CORRECTIF (audit round 2) : macro EB ci-dessous -- capture
         * IMPLICITE (pas de paramètres macro autres que I) de 13
         * identifiants de la portée englobante : padded, bi, blk,
         * zo_byte, prev, p, mat, tmp, sb, rk, nk, out, pb. Renommer
         * L'UN de ces identifiants dans _enc_p4() SANS mettre à jour la
         * macro casse la compilation (au mieux) ou lie silencieusement
         * un identifiant homonyme différent (au pire, si un tel
         * identifiant existe ailleurs en portée). Volontairement laissé
         * en macro (pas convertie en fonction) : code AVX2
         * critique-performance, déroulé manuellement ×4 pour l'ILP --
         * une conversion en fonction changerait potentiellement le
         * codegen réel, un risque de régression disproportionné pour
         * une préoccupation de maintenabilité, pas de correction. */
#define EB(I) _load_plain(padded+(bi+(I))*N,blk,zo_byte); \
    _cbc_add(blk,prev,p); cagoule_matrix_mul_avx2(mat,blk,tmp); \
    _sbox_block_forward_hot_avx2(sb,tmp,blk,N); \
    _rk_add(blk,rk[(bi+(I))%nk],p); \
    _store_blk(blk,out+(bi+(I))*N*pb); memcpy(prev,blk,N*8);
        EB(0) EB(1) EB(2) EB(3)
#undef EB
    }
    for (; bi<nb; bi++) {
        _load_plain(padded+bi*N,blk,zo_byte); _cbc_add(blk,prev,p);
        cagoule_matrix_mul_avx2(mat,blk,tmp);
        _sbox_block_forward_hot_avx2(sb,tmp,blk,N);
        _rk_add(blk,rk[bi%nk],p); _store_blk(blk,out+bi*N*pb);
        memcpy(prev,blk,N*8);
    }
    _mm256_zeroupper(); return CAGOULE_OK;
}

/* ── Decrypt mono-bloc ───────────────────────────────────────────────── */
static int _dec_mono(const uint8_t* cb, size_t nb, uint8_t* out, size_t os,
                      const CagouleMatrix* mat, const CagouleSBox64* sb,
                      const uint64_t* rk, size_t nk, uint64_t p,
                      const uint8_t zo_byte[N])
{
    size_t pb = _pb(p);
    if (os < nb*N) return CAGOULE_ERR_SIZE;
    uint64_t prev[N]; memset(prev,0,sizeof(prev));
    uint64_t cblk[N], tmp[N], cs[N];
    for (size_t bi=0; bi<nb; bi++) {
        _load_blk(cb+bi*N*pb, cblk); memcpy(cs,cblk,N*8);
        _rk_sub(cblk, rk[bi%nk], p);
        _sbox_block_inverse_hot_avx2(sb, cblk, tmp, N);
        cagoule_matrix_mul_inv_avx2(mat, tmp, cblk);
        if (!_cbc_unsub(cblk, prev, out+bi*N, p, zo_byte)) {
            _mm256_zeroupper(); return CAGOULE_ERR_CORRUPT;
        }
        memcpy(prev,cs,N*8);
    }
    _mm256_zeroupper(); return CAGOULE_OK;
}

/* ── Decrypt pipeline4 ──────────────────────────────────────────────── */
static int _dec_p4(const uint8_t* cb, size_t nb, uint8_t* out, size_t os,
                    const CagouleMatrix* mat, const CagouleSBox64* sb,
                    const uint64_t* rk, size_t nk, uint64_t p,
                    const uint8_t zo_byte[N])
{
    size_t pb = _pb(p);
    if (os < nb*N) return CAGOULE_ERR_SIZE;
    uint64_t cblk[4][N], tmp[4][N], saved[5][N], prev[N];
    memset(prev,0,N*8);
    size_t bi=0;
    for (; bi+4<=nb; bi+=4) {
        if (bi+8<=nb) __builtin_prefetch(cb+(bi+8)*N*pb,0,1);
        _load_blk(cb+(bi+0)*N*pb,cblk[0]); _load_blk(cb+(bi+1)*N*pb,cblk[1]);
        _load_blk(cb+(bi+2)*N*pb,cblk[2]); _load_blk(cb+(bi+3)*N*pb,cblk[3]);
        memcpy(saved[0],prev,N*8); memcpy(saved[1],cblk[0],N*8);
        memcpy(saved[2],cblk[1],N*8); memcpy(saved[3],cblk[2],N*8);
        memcpy(saved[4],cblk[3],N*8);
        _rk_sub(cblk[0],rk[(bi+0)%nk],p); _rk_sub(cblk[1],rk[(bi+1)%nk],p);
        _rk_sub(cblk[2],rk[(bi+2)%nk],p); _rk_sub(cblk[3],rk[(bi+3)%nk],p);
        _sbox_block_inverse_hot_avx2(sb,cblk[0],tmp[0],N);
        _sbox_block_inverse_hot_avx2(sb,cblk[1],tmp[1],N);
        _sbox_block_inverse_hot_avx2(sb,cblk[2],tmp[2],N);
        _sbox_block_inverse_hot_avx2(sb,cblk[3],tmp[3],N);
        cagoule_matrix_mul_inv_avx2(mat,tmp[0],cblk[0]);
        cagoule_matrix_mul_inv_avx2(mat,tmp[1],cblk[1]);
        cagoule_matrix_mul_inv_avx2(mat,tmp[2],cblk[2]);
        cagoule_matrix_mul_inv_avx2(mat,tmp[3],cblk[3]);
        if (!_cbc_unsub(cblk[0],saved[0],out+(bi+0)*N,p,zo_byte)) goto corrupt;
        if (!_cbc_unsub(cblk[1],saved[1],out+(bi+1)*N,p,zo_byte)) goto corrupt;
        if (!_cbc_unsub(cblk[2],saved[2],out+(bi+2)*N,p,zo_byte)) goto corrupt;
        if (!_cbc_unsub(cblk[3],saved[3],out+(bi+3)*N,p,zo_byte)) goto corrupt;
        memcpy(prev,saved[4],N*8);
    }
    for (; bi<nb; bi++) {
        _load_blk(cb+bi*N*pb,cblk[0]); memcpy(saved[0],prev,N*8);
        memcpy(prev,cblk[0],N*8);
        _rk_sub(cblk[0],rk[bi%nk],p);
        _sbox_block_inverse_hot_avx2(sb,cblk[0],tmp[0],N);
        cagoule_matrix_mul_inv_avx2(mat,tmp[0],cblk[0]);
        if (!_cbc_unsub(cblk[0],saved[0],out+bi*N,p,zo_byte)) goto corrupt;
    }
    _mm256_zeroupper(); return CAGOULE_OK;
corrupt:
    _mm256_zeroupper(); return CAGOULE_ERR_CORRUPT;
}

#endif /* __AVX2__ */

/* ══════════════════════════════════════════════════════════════════════
 * API publique — cagoule_cbc_encrypt v2.5.0
 *
 * z_offset appliqué sur les OCTETS du plaintext AVANT chiffrement.
 * Opération en Z/256Z (zo[i]%256) — domaine naturel des octets.
 * ══════════════════════════════════════════════════════════════════════ */
int cagoule_cbc_encrypt(
    const uint8_t* padded, size_t n_blocks,
    uint8_t* out, size_t out_size,
    const CagouleMatrix* mat, const CagouleSBox64* sbox,
    const uint64_t* rk, size_t nk, uint64_t p,
    const uint64_t* zo, size_t nzo)
{
    if (!padded||!out||!mat||!sbox||!rk) return CAGOULE_ERR_NULL;
    size_t pb = _pb(p);
    if (out_size < n_blocks*N*pb)        return CAGOULE_ERR_SIZE;

    /* Pré-calculer zo_byte[16] et appliquer sur le buffer padded (copie locale) */
    uint8_t zo_byte[N] = {0};
    int use_zo = (zo && nzo >= (size_t)N);
    if (use_zo) _precompute_zo_byte(zo, nzo, zo_byte);

    /* v2.5.4: Z-shift applied inline in _load_plain — no malloc needed */

#if defined(__AVX2__)
    if (_avx2_ok() && sbox->use_feistel) {
        const uint8_t* zo_ptr = use_zo ? zo_byte : NULL;
        return (n_blocks >= CAGOULE_PIPELINE4_THRESHOLD)
            ? _enc_p4(padded, n_blocks, out, out_size, mat, sbox, rk, nk, p, zo_ptr)
            : _enc_mono(padded, n_blocks, out, out_size, mat, sbox, rk, nk, p, zo_ptr);
    }
#endif

    /* Fallback scalaire */
    uint64_t buf[2][N]; memset(buf,0,sizeof(buf));
    uint64_t *prev=buf[0], *blk=buf[1], tmp[N];
    for (size_t bi=0; bi<n_blocks; bi++) {
        const uint8_t* src = padded + bi*N;
        for (int j=0; j<N; j++)
            blk[j] = (uint64_t)((src[j] + zo_byte[j]) & 0xFF);
        for (int j=0; j<N; j++) blk[j] = addmod64(blk[j], prev[j], p);
        /* NE PAS remplacer par _matmul16_scalar_lazy() -- CORRECTIF
         * (audit round 2) : une suggestion antérieure recommandait ce
         * remplacement pour la performance (~40% plus rapide sur
         * primes Mersenne-64). Testé empiriquement avant application :
         * FAUX RÉSULTATS dans 100% des cas (40000/40000 fuzz mismatches).
         * Cause : _matmul16_scalar_lazy() accumule 16 produits non
         * réduits dans un __uint128_t avant une réduction unique --
         * sûr seulement si le vecteur v[] est de petite magnitude
         * (ex: octet 0-255, cas d'usage réel : cagoule_ctr.c, blk[]
         * chargé depuis IV/compteur un octet par élément, AUCUN
         * chaînage). Ici, blk[] vient de subir addmod64(blk[j],
         * prev[j], p) juste au-dessus -- chaînage CBC -- donc blk[j]
         * est un élément de corps complet (~p, proche de 2^64), pas un
         * octet. mat[i][j]*blk[j] approche alors p² ≈ 2^128 PAR TERME,
         * et 16 termes accumulés débordent le __uint128_t. Voir
         * cagoule_ctr.c pour l'usage sûr existant de la variante lazy. */
        _matmul16_scalar(mat->fwd, blk, tmp, p);
        cagoule_sbox_block_forward(sbox, tmp, blk, N);
        uint64_t k = rk[bi%nk];
        for (int j=0; j<N; j++) blk[j] = addmod64(blk[j], k, p);
        uint8_t* dst = out + bi*N*pb;
        for (int j=0; j<N; j++) _u64_to_be(blk[j], dst+j*pb, pb);
        uint64_t* sw=prev; prev=blk; blk=sw;
    }
    return CAGOULE_OK;
}

/* ══════════════════════════════════════════════════════════════════════
 * API publique — cagoule_cbc_decrypt v2.5.0
 *
 * z_offset annulé sur les OCTETS du plaintext APRÈS déchiffrement.
 * ══════════════════════════════════════════════════════════════════════ */
int cagoule_cbc_decrypt(
    const uint8_t* cb, size_t n_blocks,
    uint8_t* out, size_t out_size,
    const CagouleMatrix* mat, const CagouleSBox64* sbox,
    const uint64_t* rk, size_t nk, uint64_t p,
    const uint64_t* zo, size_t nzo)
{
    if (!cb||!out||!mat||!sbox||!rk) return CAGOULE_ERR_NULL;
    if (out_size < n_blocks*N)       return CAGOULE_ERR_SIZE;

    uint8_t zo_byte[N] = {0};
    int use_zo = (zo && nzo >= (size_t)N);
    if (use_zo) _precompute_zo_byte(zo, nzo, zo_byte);

#if defined(__AVX2__)
    if (_avx2_ok() && sbox->use_feistel) {
        const uint8_t* zo_ptr = use_zo ? zo_byte : NULL;
        return (n_blocks >= CAGOULE_PIPELINE4_THRESHOLD)
            ? _dec_p4(cb, n_blocks, out, out_size, mat, sbox, rk, nk, p, zo_ptr)
            : _dec_mono(cb, n_blocks, out, out_size, mat, sbox, rk, nk, p, zo_ptr);
    }
#endif

    /* Fallback scalaire */
    size_t pbytes = _pb(p);
    uint64_t prev[N]; memset(prev,0,N*8);
    uint64_t cblk[N], tmp[N], cs[N];
    for (size_t bi=0; bi<n_blocks; bi++) {
        const uint8_t* src = cb + bi*N*pbytes;
        for (int j=0; j<N; j++) cblk[j] = _be_to_u64(src+j*pbytes, pbytes);
        memcpy(cs,cblk,N*8);
        uint64_t k = rk[bi%nk];
        for (int j=0; j<N; j++) tmp[j] = submod64(cblk[j], k, p);
        cagoule_sbox_block_inverse(sbox, tmp, cblk, N);
        /* NE PAS remplacer par _matmul16_scalar_lazy() -- voir le
         * commentaire équivalent dans le chemin encrypt ci-dessus pour
         * la preuve empirique complète. Ici cblk[] vient directement du
         * ciphertext sur le fil (_be_to_u64), un élément de corps
         * complet, pas un octet -- même cause d'incompatibilité. */
        _matmul16_scalar(mat->inv, cblk, tmp, p);
        uint8_t* dst = out + bi*N;
        for (int j=0; j<N; j++) {
            uint64_t b = submod64(tmp[j], prev[j], p);
            if (b > 255) return CAGOULE_ERR_CORRUPT;
            dst[j] = (uint8_t)((b - zo_byte[j]) & 0xFF);
        }
        memcpy(prev,cs,N*8);
    }
    return CAGOULE_OK;
}
