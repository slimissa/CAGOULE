/**
 * cagoule_stream.c — API de chiffrement en flux — CAGOULE v3.1.0 Feature 4
 * Voir cagoule_stream.h pour la documentation complète.
 */
#include "cagoule_stream.h"
#include "cagoule_kdf.h"
#include "cagoule_ctr.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

/* Identifiant de version interne pour le MAC AAD — distingue les deux modes
 * à la vérification sans exposer un VERSION byte CGL1 (pas de nouveau
 * format wire : roadmap §4 décision "C-API only for v3.1.0"). */
#define STREAM_VERSION_AEAD  0x02
#define STREAM_VERSION_RAW   0x03

#define MAGIC_LEN   4
#define MAGIC_BYTES "CGL1"

struct CagouleStreamCtx {
    CagouleDerivedParams params;
    uint8_t  session_salt[CAGOULE_STREAM_SESSION_SALT_SIZE];
    size_t   chunk_size;
    uint64_t chunk_idx;    /* Monotone croissant, incrémenté après chaque chunk */
    int      experimental; /* 0 = 0x02 ChaCha20-Poly1305, 1 = 0x03 Poly1305 seul */
};

/* CORRECTIF (audit round 2, consolidation) : local helper (volatile-pointer
 * loop, byte-identical to the one removed from cagoule_params.c) removed
 * below -- replaced with OPENSSL_cleanse(), already used and proven
 * elsewhere in this project (cagoule_kdf.c, cagoule_api.c, and now
 * cagoule_params.c). openssl/crypto.h was already included in this file. */

/* ── Dérivation de la clé MAC spécifique à un chunk ─────────────────── */
/* chunk_mac_key = HKDF(k_master, "CAGOULE_CHUNK" || chunk_idx_LE64, 32) */
static int derive_chunk_mac_key(const uint8_t k_master[CAGOULE_K_MASTER_LEN],
                                 uint64_t chunk_idx,
                                 uint8_t mac_key_out[32])
{
    uint8_t info[13 + 8]; /* "CAGOULE_CHUNK"(13) + chunk_idx(8) */
    memcpy(info, "CAGOULE_CHUNK", 13);
    /* Encodage little-endian pour éviter la confusion avec big-endian du reste */
    for (int i = 0; i < 8; i++) info[13 + i] = (uint8_t)(chunk_idx >> (i*8));
    return cagoule_kdf_hkdf(k_master, CAGOULE_K_MASTER_LEN, info, sizeof(info),
                             mac_key_out, 32) == CAGOULE_KDF_OK
           ? CAGOULE_STREAM_OK : CAGOULE_STREAM_ERR_KDF;
}

/* ── Construction de l'AAD lié au contexte de session + chunk ──────── */
/* AAD = MAGIC(4) || VERSION(1) || session_salt(32) || chunk_idx_LE64(8) */
static void build_chunk_aad(uint8_t version, const uint8_t session_salt[32],
                              uint64_t chunk_idx, uint8_t *aad, size_t *aad_len)
{
    size_t pos = 0;
    memcpy(aad + pos, MAGIC_BYTES, MAGIC_LEN); pos += MAGIC_LEN;
    aad[pos++] = version;
    memcpy(aad + pos, session_salt, 32); pos += 32;
    for (int i = 0; i < 8; i++) aad[pos++] = (uint8_t)(chunk_idx >> (i*8));
    *aad_len = pos;   /* = 4+1+32+8 = 45 */
}

/* ── Dérivation IV CTR — même label que cagoule_api.c chemin mono-message */
static int derive_chunk_iv(const uint8_t k_master[CAGOULE_K_MASTER_LEN],
                             uint64_t chunk_idx,
                             uint8_t iv_out[CAGOULE_CTR_IV_SIZE])
{
    /* CORRECTIF v3.1.0 : label V30→V31 pour cohérence avec cagoule_api.c et
     * cipher_ctr.py. Le chunk_idx joue le rôle du nonce (unique par chunk). */
    uint8_t info[15 + 8]; /* "CAGOULE_CTR_V31"(15) + chunk_idx(8) */
    memcpy(info, "CAGOULE_CTR_V31", 15);
    for (int i = 0; i < 8; i++) info[15 + i] = (uint8_t)(chunk_idx >> (i*8));
    return cagoule_kdf_hkdf(k_master, CAGOULE_K_MASTER_LEN, info, sizeof(info),
                             iv_out, CAGOULE_CTR_IV_SIZE) == CAGOULE_KDF_OK
           ? CAGOULE_STREAM_OK : CAGOULE_STREAM_ERR_KDF;
}

/* ── ChaCha20-Poly1305 helpers (réutilisés de cagoule_api.c) ─────────── */
static int chacha_enc(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, int aad_len,
                       const uint8_t *pt, int pt_len,
                       uint8_t *ct_out, uint8_t tag_out[16])
{
    int ret = CAGOULE_STREAM_ERR_CRYPTO;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CAGOULE_STREAM_ERR_ALLOC;
    int len;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad_len > 0 && 1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    if (pt_len > 0 && 1 != EVP_EncryptUpdate(ctx, ct_out, &len, pt, pt_len)) goto done;
    if (1 != EVP_EncryptFinal_ex(ctx, ct_out + (pt_len > 0 ? len : 0), &len)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out)) goto done;
    ret = CAGOULE_STREAM_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int chacha_dec(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *aad, int aad_len,
                       const uint8_t *ct, int ct_len, const uint8_t tag[16],
                       uint8_t *pt_out)
{
    int ret = CAGOULE_STREAM_ERR_CRYPTO;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CAGOULE_STREAM_ERR_ALLOC;
    int len;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL)) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad_len > 0 && 1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    if (ct_len > 0 && 1 != EVP_DecryptUpdate(ctx, pt_out, &len, ct, ct_len)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag)) goto done;
    if (1 != EVP_DecryptFinal_ex(ctx, pt_out + (ct_len > 0 ? len : 0), &len)) { ret = CAGOULE_STREAM_ERR_AUTH; goto done; }
    ret = CAGOULE_STREAM_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ── Poly1305 seul (expérimental 0x03) ───────────────────────────────── */
static int poly1305_tag_stream(const uint8_t key[32], const uint8_t *data, size_t dlen,
                                uint8_t tag_out[16])
{
    int ret = CAGOULE_STREAM_ERR_CRYPTO;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (!mac) return CAGOULE_STREAM_ERR_CRYPTO;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return CAGOULE_STREAM_ERR_ALLOC; }
    size_t out_len = 0;
    if (1 != EVP_MAC_init(ctx, key, 32, NULL)) goto done;
    if (1 != EVP_MAC_update(ctx, data, dlen)) goto done;
    if (1 != EVP_MAC_final(ctx, tag_out, &out_len, 16)) goto done;
    if (out_len != 16) goto done;
    ret = CAGOULE_STREAM_OK;
done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════
 * API publique
 * ════════════════════════════════════════════════════════════════════ */

CagouleStreamCtx* cagoule_stream_init(const uint8_t *password, size_t pwd_len,
                                       size_t chunk_size, int allow_experimental)
{
    if (!password) return NULL;

    /* Double gate pour le mode expérimental 0x03 */
    /* CORRECTIF v3.1.0 (Finding 3) : allow_experimental=1 sans env var →
     * mode sûr par défaut (experimental=0), pas NULL. Le NULL ne doit être
     * retourné que si l'appelant a explicitement demandé le mode expérimental
     * ET que le gate env var n'est pas ouvert — ce n'est pas le cas ici :
     * allow_experimental signifie "je suis prêt à utiliser le mode expérimental
     * si le gate est ouvert", pas "je le requiers impérativement". */
    int experimental = 0;
    if (allow_experimental) {
        const char *env = getenv("CAGOULE_EXPERIMENTAL_NO_AEAD");
        if (env && strcmp(env, "1") == 0) experimental = 1;
        /* sinon : experimental reste 0 (mode sûr par défaut) */
    }

    CagouleStreamCtx *ctx = calloc(1, sizeof(CagouleStreamCtx));
    if (!ctx) return NULL;

    if (1 != RAND_bytes(ctx->session_salt, CAGOULE_STREAM_SESSION_SALT_SIZE))
        goto fail;

    if (cagoule_params_derive(password, pwd_len,
                               ctx->session_salt, CAGOULE_STREAM_SESSION_SALT_SIZE,
                               &ctx->params) != CAGOULE_PARAMS_OK)
        goto fail;

    ctx->chunk_size  = chunk_size > 0 ? chunk_size : CAGOULE_STREAM_DEFAULT_CHUNK_SIZE;
    ctx->chunk_idx   = 0;
    ctx->experimental = experimental;
    return ctx;

fail:
    cagoule_stream_free(ctx);
    return NULL;
}

size_t cagoule_stream_update_out_len(const CagouleStreamCtx *ctx, size_t input_len)
{
    if (!ctx) return 0;
    int overhead = ctx->experimental ? CAGOULE_STREAM_OVERHEAD_RAW
                                     : CAGOULE_STREAM_OVERHEAD_AEAD;
    return input_len + (size_t)overhead;
}

size_t cagoule_stream_decrypt_out_len(const CagouleStreamCtx *ctx, size_t ct_chunk_len)
{
    if (!ctx) return 0;
    int overhead = ctx->experimental ? CAGOULE_STREAM_OVERHEAD_RAW
                                     : CAGOULE_STREAM_OVERHEAD_AEAD;
    return ct_chunk_len >= (size_t)overhead ? ct_chunk_len - (size_t)overhead : 0;
}

const uint8_t* cagoule_stream_session_salt(const CagouleStreamCtx *ctx) {
    return ctx ? ctx->session_salt : NULL;
}

CagouleStreamCtx* cagoule_stream_init_from_salt(const uint8_t *password, size_t pwd_len,
                                                  const uint8_t *session_salt,
                                                  size_t chunk_size,
                                                  int allow_experimental)
{
    if (!password || !session_salt) return NULL;

    /* CORRECTIF v3.1.0 (Finding 4) : même correction que stream_init */
    int experimental = 0;
    if (allow_experimental) {
        const char *env = getenv("CAGOULE_EXPERIMENTAL_NO_AEAD");
        if (env && strcmp(env, "1") == 0) experimental = 1;
    }

    CagouleStreamCtx *ctx = calloc(1, sizeof(CagouleStreamCtx));
    if (!ctx) return NULL;

    memcpy(ctx->session_salt, session_salt, CAGOULE_STREAM_SESSION_SALT_SIZE);

    if (cagoule_params_derive(password, pwd_len,
                               ctx->session_salt, CAGOULE_STREAM_SESSION_SALT_SIZE,
                               &ctx->params) != CAGOULE_PARAMS_OK) {
        /* CORRECTIF (P0-2) : cagoule_stream_free() cleanses session_salt
         * (OPENSSL_cleanse) before freeing — free() alone skipped that.
         * ctx->params is already self-cleaned by cagoule_params_derive's
         * own failure paths (verified), so this is not a double-free
         * risk; cagoule_stream_free's cagoule_params_free() on an
         * already-zeroed/freed params struct is a documented no-op. */
        cagoule_stream_free(ctx);
        return NULL;
    }

    ctx->chunk_size   = chunk_size > 0 ? chunk_size : CAGOULE_STREAM_DEFAULT_CHUNK_SIZE;
    ctx->chunk_idx    = 0;
    ctx->experimental = experimental;
    return ctx;
}

/* CORRECTIF (audit round 2, Phase 3 — documentation uniquement, voir
 * consolidation CGL1) : cette fonction N'ASSEMBLE PAS un paquet CGL1, à
 * ne PAS "harmoniser" avec cipher.py/cipher_ctr.py/cipher_ctr_raw.py/
 * cagoule_api.c (voir format.py côté Python, assemble_cgl1_aead() côté
 * C) -- c'est un protocole différent, pas une 5e variante du même format
 * qui aurait été oubliée lors de la centralisation :
 *
 *   - PAS de MAGIC ("CGL1") dans la sortie par chunk, contrairement à
 *     tous les formats single-message (v0x01/0x02/0x03).
 *   - PAS de salt par chunk. session_salt est dérivé UNE FOIS à
 *     l'initialisation (cagoule_stream_init) et transmis hors-bande, via
 *     cagoule_stream_session_salt() -- pas dans la sortie de update().
 *   - chunk_idx est encodé en PETIT-BOUTISTE (little-endian, octet 0 =
 *     LSB) ci-dessous -- contrairement aux conventions grand-boutiste
 *     utilisées ailleurs dans ce projet (champs HKDF info, etc.). Ne pas
 *     "corriger" en grand-boutiste par cohérence : casserait le
 *     déchiffrement de tout flux déjà produit.
 *
 * Le format complet (les deux variantes 0x02/0x03, construction AAD) est
 * documenté en tête de cagoule_stream.h -- s'y référer avant toute
 * modification de cette fonction ou de son pendant côté lecture. Conçu
 * pour un chunk À L'INTÉRIEUR d'une session déjà établie (session_salt
 * connue des deux côtés), pas comme un paquet autonome et auto-descriptif
 * comme CGL1 -- d'où l'absence volontaire de MAGIC/salt par chunk. */
int cagoule_stream_update(CagouleStreamCtx *ctx,
                           const uint8_t *input, size_t input_len,
                           uint8_t *out, size_t *out_len)
{
    if (!ctx || !input || !out || !out_len) return CAGOULE_STREAM_ERR_NULL;
    size_t needed = cagoule_stream_update_out_len(ctx, input_len);
    if (*out_len < needed) return CAGOULE_STREAM_ERR_SIZE;

    uint64_t idx = ctx->chunk_idx;
    uint8_t version = ctx->experimental ? STREAM_VERSION_RAW : STREAM_VERSION_AEAD;

    /* 1. Dériver IV CTR unique à ce chunk */
    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    if (derive_chunk_iv(ctx->params.k_master, idx, iv) != CAGOULE_STREAM_OK)
        return CAGOULE_STREAM_ERR_KDF;

    /* 2. Chiffrement algébrique CTR */
    uint8_t *ct_alg = malloc(input_len > 0 ? input_len : 1);
    if (!ct_alg) return CAGOULE_STREAM_ERR_ALLOC;
    int cret = cagoule_ctr_encrypt(input, input_len, iv,
                                    ctx->params.matrix, &ctx->params.sbox,
                                    ctx->params.round_keys, CAGOULE_NUM_ROUND_KEYS,
                                    ctx->params.p,
                                    ctx->params.z_offset, CAGOULE_Z_OFFSET_N,
                                    ct_alg, input_len > 0 ? input_len : 1);
    if (cret != CAGOULE_OK) { free(ct_alg); return CAGOULE_STREAM_ERR_CRYPTO; }

    /* 3. Clé MAC spécifique au chunk */
    uint8_t mac_key[32];
    if (derive_chunk_mac_key(ctx->params.k_master, idx, mac_key) != CAGOULE_STREAM_OK) {
        free(ct_alg); return CAGOULE_STREAM_ERR_KDF;
    }

    /* 4. AAD lié à la session */
    uint8_t aad[4 + 1 + 32 + 8]; size_t aad_len;
    build_chunk_aad(version, ctx->session_salt, idx, aad, &aad_len);

    /* 5. Assemblage dans out */
    size_t pos = 0;
    /* CHUNK_IDX (8 octets, little-endian) */
    for (int i = 0; i < 8; i++) out[pos++] = (uint8_t)(idx >> (i*8));

    int ret;
    if (!ctx->experimental) {
        /* VERSION 0x02 : ChaCha20-Poly1305(mac_key, nonce, AAD, ct_alg) */
        uint8_t nonce[12];
        if (1 != RAND_bytes(nonce, 12)) { free(ct_alg); OPENSSL_cleanse(mac_key,32); return CAGOULE_STREAM_ERR_CRYPTO; }
        memcpy(out + pos, nonce, 12); pos += 12;
        uint8_t tag[16];
        ret = chacha_enc(mac_key, nonce, aad, (int)aad_len,
                          ct_alg, (int)input_len, out + pos, tag);
        if (ret != CAGOULE_STREAM_OK) { free(ct_alg); OPENSSL_cleanse(mac_key,32); return ret; }
        pos += input_len;
        memcpy(out + pos, tag, 16); pos += 16;
    } else {
        /* VERSION 0x03 (expérimental) : Poly1305(mac_key, AAD || ct_alg) */
        uint8_t *mac_data = malloc(aad_len + input_len);
        if (!mac_data) { free(ct_alg); OPENSSL_cleanse(mac_key,32); return CAGOULE_STREAM_ERR_ALLOC; }
        memcpy(mac_data, aad, aad_len);
        memcpy(mac_data + aad_len, ct_alg, input_len);
        memcpy(out + pos, ct_alg, input_len); pos += input_len;
        uint8_t tag[16];
        ret = poly1305_tag_stream(mac_key, mac_data, aad_len + input_len, tag);
        free(mac_data);
        if (ret != CAGOULE_STREAM_OK) { free(ct_alg); OPENSSL_cleanse(mac_key,32); return ret; }
        memcpy(out + pos, tag, 16); pos += 16;
    }

    free(ct_alg);
    OPENSSL_cleanse(mac_key, 32);
    *out_len = pos;
    ctx->chunk_idx++;
    return CAGOULE_STREAM_OK;
}

int cagoule_stream_decrypt(CagouleStreamCtx *ctx,
                            const uint8_t *ct_chunk, size_t ct_chunk_len,
                            uint8_t *out, size_t *out_len)
{
    if (!ctx || !ct_chunk || !out || !out_len) return CAGOULE_STREAM_ERR_NULL;
    int overhead = ctx->experimental ? CAGOULE_STREAM_OVERHEAD_RAW
                                     : CAGOULE_STREAM_OVERHEAD_AEAD;
    if (ct_chunk_len < (size_t)overhead) return CAGOULE_STREAM_ERR_SIZE;
    size_t pt_len = ct_chunk_len - (size_t)overhead;
    if (*out_len < pt_len) return CAGOULE_STREAM_ERR_SIZE;

    /* Lire chunk_idx depuis le ciphertext */
    uint64_t wire_idx = 0;
    for (int i = 0; i < 8; i++) wire_idx |= (uint64_t)ct_chunk[i] << (i*8);
    if (wire_idx != ctx->chunk_idx) return CAGOULE_STREAM_ERR_FORMAT;

    uint8_t version = ctx->experimental ? STREAM_VERSION_RAW : STREAM_VERSION_AEAD;
    uint8_t aad[4 + 1 + 32 + 8]; size_t aad_len;
    build_chunk_aad(version, ctx->session_salt, wire_idx, aad, &aad_len);

    uint8_t mac_key[32];
    if (derive_chunk_mac_key(ctx->params.k_master, wire_idx, mac_key) != CAGOULE_STREAM_OK)
        return CAGOULE_STREAM_ERR_KDF;

    const uint8_t *payload = ct_chunk + 8;
    int ret;
    uint8_t *ct_alg_buf = malloc(pt_len > 0 ? pt_len : 1);
    if (!ct_alg_buf) { OPENSSL_cleanse(mac_key, 32); return CAGOULE_STREAM_ERR_ALLOC; }

    if (!ctx->experimental) {
        /* NONCE(12) | CT_ALG(pt_len) | TAG(16) */
        const uint8_t *nonce  = payload;
        const uint8_t *ct_alg = payload + 12;
        const uint8_t *tag    = ct_chunk + ct_chunk_len - 16;
        /* Authentifier ET déchiffrer ct_alg vers ct_alg_buf (en interne) */
        ret = chacha_dec(mac_key, nonce, aad, (int)aad_len,
                          ct_alg, (int)pt_len, tag, ct_alg_buf);
    } else {
        /* CT_ALG(pt_len) | TAG(16) */
        const uint8_t *ct_alg = payload;
        const uint8_t *tag    = ct_chunk + ct_chunk_len - 16;
        /* Vérification manuelle constant-time avant de toucher ct_alg */
        uint8_t *mac_data = malloc(aad_len + pt_len);
        if (!mac_data) { free(ct_alg_buf); OPENSSL_cleanse(mac_key,32); return CAGOULE_STREAM_ERR_ALLOC; }
        memcpy(mac_data, aad, aad_len);
        memcpy(mac_data + aad_len, ct_alg, pt_len);
        uint8_t computed_tag[16];
        ret = poly1305_tag_stream(mac_key, mac_data, aad_len + pt_len, computed_tag);
        free(mac_data);
        if (ret != CAGOULE_STREAM_OK) { free(ct_alg_buf); OPENSSL_cleanse(mac_key,32); return ret; }
        if (CRYPTO_memcmp(computed_tag, tag, 16) != 0) {
            free(ct_alg_buf); OPENSSL_cleanse(mac_key,32); return CAGOULE_STREAM_ERR_AUTH;
        }
        memcpy(ct_alg_buf, ct_alg, pt_len);
        ret = CAGOULE_STREAM_OK;
    }

    OPENSSL_cleanse(mac_key, 32);
    if (ret != CAGOULE_STREAM_OK) {
        OPENSSL_cleanse(ct_alg_buf, pt_len);
        free(ct_alg_buf);
        return ret; /* CAGOULE_STREAM_ERR_AUTH ou CRYPTO */
    }

    /* Authentifié -> déchiffrement CTR algébrique vers out */
    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    if (derive_chunk_iv(ctx->params.k_master, wire_idx, iv) != CAGOULE_STREAM_OK) {
        OPENSSL_cleanse(ct_alg_buf, pt_len);
        free(ct_alg_buf);
        return CAGOULE_STREAM_ERR_KDF;
    }
    int dret = cagoule_ctr_decrypt(ct_alg_buf, pt_len, iv,
                                    ctx->params.matrix, &ctx->params.sbox,
                                    ctx->params.round_keys, CAGOULE_NUM_ROUND_KEYS,
                                    ctx->params.p,
                                    ctx->params.z_offset, CAGOULE_Z_OFFSET_N,
                                    out, *out_len);
    OPENSSL_cleanse(ct_alg_buf, pt_len);
    free(ct_alg_buf);
    if (dret != CAGOULE_OK) return CAGOULE_STREAM_ERR_CRYPTO;

    *out_len = pt_len;
    ctx->chunk_idx++;
    return CAGOULE_STREAM_OK;
}

void cagoule_stream_free(CagouleStreamCtx *ctx)
{
    if (!ctx) return;
    cagoule_params_free(&ctx->params);
    OPENSSL_cleanse(ctx->session_salt, sizeof(ctx->session_salt));
    ctx->chunk_idx = 0;
    free(ctx);
}
