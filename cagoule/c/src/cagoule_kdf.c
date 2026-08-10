/**
 * cagoule_kdf.c — Implémentation HKDF-SHA256 multi-bloc + Argon2id
 * CAGOULE v3.1.0 — voir cagoule_kdf.h
 */
#include "cagoule_kdf.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <argon2.h>

int cagoule_kdf_argon2id(const uint8_t *password, size_t pwd_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t out_k_master[CAGOULE_K_MASTER_LEN])
{
    if (!password || !salt || !out_k_master) return CAGOULE_KDF_ERR_NULL;
    if (salt_len != CAGOULE_SALT_LEN) return CAGOULE_KDF_ERR_PARAM;

    int ret = argon2id_hash_raw(
        CAGOULE_ARGON2_TIME_COST,
        CAGOULE_ARGON2_MEM_COST_KB,
        CAGOULE_ARGON2_PARALLELISM,
        password, pwd_len,
        salt, salt_len,
        out_k_master, CAGOULE_K_MASTER_LEN
    );
    if (ret != ARGON2_OK) return CAGOULE_KDF_ERR_ARGON2;
    return CAGOULE_KDF_OK;
}

/* HKDF-Extract : PRK = HMAC-SHA256(zero_salt[32], IKM) — RFC 5869 §2.2,
 * salt=None côté Python ≡ sel de HashLen zéros. */
static int hkdf_extract(const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[CAGOULE_SHA256_LEN])
{
    static const uint8_t zero_salt[CAGOULE_SHA256_LEN] = {0};
    unsigned int out_len = CAGOULE_SHA256_LEN;
    if (!HMAC(EVP_sha256(), zero_salt, CAGOULE_SHA256_LEN,
              ikm, ikm_len, prk, &out_len))
        return CAGOULE_KDF_ERR_OPENSSL;
    return CAGOULE_KDF_OK;
}

/* HKDF-Expand multi-bloc — RFC 5869 §2.3 :
 *   T(0) = empty
 *   T(i) = HMAC-PRK( T(i-1) || info || i )   (i = 1, 2, ...)
 *   OKM  = T(1) || T(2) || ... tronqué à out_len
 *
 * Limite RFC : out_len <= 255 * HashLen (largement suffisant ; on plafonne
 * en pratique à 128 octets pour z_offset).
 */
static int hkdf_expand(const uint8_t prk[CAGOULE_SHA256_LEN],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    if (info_len > 200) return CAGOULE_KDF_ERR_PARAM;  /* marge généreuse */
    size_t n_blocks = (out_len + CAGOULE_SHA256_LEN - 1) / CAGOULE_SHA256_LEN;
    if (n_blocks == 0) return CAGOULE_KDF_OK;  /* out_len == 0 */
    if (n_blocks > 255) return CAGOULE_KDF_ERR_PARAM;

    uint8_t t_prev[CAGOULE_SHA256_LEN];
    size_t  t_prev_len = 0;
    uint8_t buf[CAGOULE_SHA256_LEN + 200 + 1];
    size_t  produced = 0;
    /* CORRECTIF (audit round 2, H3) : t_prev/buf/t_cur contiennent du
     * matériel dérivé (sortie HMAC intermédiaire, équivalent à du keystream)
     * et n'étaient jamais nettoyés avant retour -- ils persistaient sur la
     * pile après l'appel. Nettoyage sur TOUS les chemins de sortie
     * (succès, erreur HMAC, boucle normale) via le label unique `done`. */
    int ret = CAGOULE_KDF_OK;

    for (size_t i = 1; i <= n_blocks; i++) {
        size_t pos = 0;
        memcpy(buf + pos, t_prev, t_prev_len); pos += t_prev_len;
        memcpy(buf + pos, info, info_len);     pos += info_len;
        buf[pos] = (uint8_t)i;                 pos += 1;

        uint8_t t_cur[CAGOULE_SHA256_LEN];
        unsigned int t_cur_len = CAGOULE_SHA256_LEN;
        if (!HMAC(EVP_sha256(), prk, CAGOULE_SHA256_LEN,
                  buf, pos, t_cur, &t_cur_len)) {
            OPENSSL_cleanse(t_cur, sizeof(t_cur));
            ret = CAGOULE_KDF_ERR_OPENSSL;
            goto done;
        }

        size_t take = (out_len - produced < CAGOULE_SHA256_LEN)
                          ? (out_len - produced) : CAGOULE_SHA256_LEN;
        memcpy(out + produced, t_cur, take);
        produced += take;

        memcpy(t_prev, t_cur, CAGOULE_SHA256_LEN);
        t_prev_len = CAGOULE_SHA256_LEN;
        OPENSSL_cleanse(t_cur, sizeof(t_cur));
    }

done:
    OPENSSL_cleanse(t_prev, sizeof(t_prev));
    OPENSSL_cleanse(buf, sizeof(buf));
    return ret;
}

int cagoule_kdf_hkdf(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len)
{
    if (!ikm || !out) return CAGOULE_KDF_ERR_NULL;
    if (!info && info_len > 0) return CAGOULE_KDF_ERR_NULL;

    uint8_t prk[CAGOULE_SHA256_LEN];
    int ret = hkdf_extract(ikm, ikm_len, prk);
    if (ret != CAGOULE_KDF_OK) {
        OPENSSL_cleanse(prk, CAGOULE_SHA256_LEN);
        return ret;
    }

    ret = hkdf_expand(prk, info, info_len, out, out_len);
    OPENSSL_cleanse(prk, CAGOULE_SHA256_LEN);
    return ret;
}

int cagoule_kdf_hkdf_u64(const uint8_t *ikm, size_t ikm_len,
                          const uint8_t *info, size_t info_len,
                          size_t n_bytes, uint64_t *out)
{
    if (!out) return CAGOULE_KDF_ERR_NULL;
    if (n_bytes == 0 || n_bytes > 8) return CAGOULE_KDF_ERR_PARAM;

    uint8_t buf[8] = {0};
    int ret = cagoule_kdf_hkdf(ikm, ikm_len, info, info_len, buf, n_bytes);
    if (ret != CAGOULE_KDF_OK) { OPENSSL_cleanse(buf, sizeof(buf)); return ret; }

    uint64_t v = 0;
    for (size_t i = 0; i < n_bytes; i++) {
        v = (v << 8) | buf[i];
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    *out = v;
    return CAGOULE_KDF_OK;
}
