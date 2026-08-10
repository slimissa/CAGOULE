/**
 * cagoule_api.c — Wrapper C unifié — CAGOULE v3.1.0 Feature 2
 * Voir cagoule_api.h pour la documentation complète, en particulier le
 * constat de sécurité sur la réutilisation de handle (IV bulk-safe).
 */
#include "cagoule_api.h"
#include "cagoule_kdf.h"
#include "cagoule_ctr.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp — comparaison constant-time */
#include <openssl/core_names.h>

#define MAGIC_BYTES   "CGL1"
#define MAGIC_LEN     4
#define NONCE_SIZE    12
#define TAG_SIZE      16
#define SALT_SIZE     32

struct CagouleKeyHandle {
    CagouleDerivedParams params;
};

/* ════════════════════════════════════════════════════════════════════
 * IV CTR — deux formules distinctes, voir avertissement cagoule_api.h
 * ════════════════════════════════════════════════════════════════════ */

/* CORRECTIF v3.0.1 — Formule IV unifiée :
 *   IV = HKDF(k_master, "CAGOULE_CTR_V30" || header_salt, 8)
 *
 * header_salt est toujours le sel 32-octet présent dans le header CGL1 v0x02.
 * Cela garantit l'unicité du keystream par message même quand k_master est
 * partagé (bulk handle). La formule est identique pour les chemins mono-message
 * et bulk — même fonction, même label, même résultat si même (k_master, salt).
 *
 * Remplacement de l'ancienne paire derive_iv_single / derive_iv_bulk qui avait
 * des labels différents, rendant les ciphertexts mono-message et bulk mutuellement
 * indéchiffrables et laissant le chemin mono-message sans salt (two-time-pad actif).
 */
/* CORRECTIF v3.1.0 — derive_iv lie l'IV au NONCE (12 octets, aléatoire par
 * message), pas au salt (32 octets, identique pour tous les messages d'un
 * handle partagé). Ce changement aligne cagoule_api.c sur le comportement de
 * cipher_ctr.py v3.0.1 (fix définitif Bug 2).
 *
 * Formule unifiée C et Python :
 *   IV = HKDF(k_master, "CAGOULE_CTR_V31" + nonce, 8)
 *
 * Le nonce (12 octets ChaCha20, os.urandom par appel) est :
 *   - Déjà aléatoire et unique par message (garantit l'unicité de l'IV)
 *   - Présent dans le header CGL1 → disponible côté decrypt
 *   - Indépendant du salt Argon2id → pas de problème de concordance
 *
 * Le salt (32 octets) reste dans le header pour permettre la re-dérivation
 * de k_master/k_stream cross-session (invariant CGL1 préservé).
 */
static int derive_iv(const uint8_t k_master[CAGOULE_K_MASTER_LEN],
                     const uint8_t nonce[NONCE_SIZE],
                     uint8_t iv_out[CAGOULE_CTR_IV_SIZE])
{
    uint8_t info[15 + NONCE_SIZE];  /* "CAGOULE_CTR_V31"(15) + nonce(12) */
    memcpy(info, "CAGOULE_CTR_V31", 15);
    memcpy(info + 15, nonce, NONCE_SIZE);
    uint8_t buf[CAGOULE_CTR_IV_SIZE];
    if (cagoule_kdf_hkdf(k_master, CAGOULE_K_MASTER_LEN,
                          info, sizeof(info),
                          buf, CAGOULE_CTR_IV_SIZE) != CAGOULE_KDF_OK)
        return CAGOULE_API_ERR_KDF;
    memcpy(iv_out, buf, CAGOULE_CTR_IV_SIZE);
    return CAGOULE_API_OK;
}

/* CORRECTIF (audit round 2, M9 — élevé de "mineur" à "casse l'interop
 * C/Python en mode RAW") : derive_iv() ci-dessus est correct pour le
 * chemin AEAD (0x02), où `nonce` est un vrai nonce ChaCha20 de 12 octets.
 *
 * Le chemin RAW (0x03) n'a PAS de nonce ChaCha20 — cipher_ctr_raw.py
 * utilise le SALT DU MESSAGE (32 octets) comme entrée IV :
 *   IV = HKDF(k_master, "CAGOULE_CTR_V31" + salt[0:32], 8)   -- Python
 *
 * Les deux sites d'appel RAW ci-dessous appelaient à tort derive_iv()
 * (typé nonce[12]) avec msg_salt (32 octets) : `memcpy(info+15, nonce,
 * NONCE_SIZE)` ne recopiait que les 12 premiers octets de msg_salt,
 * ignorant silencieusement les 20 derniers. Résultat vérifié par test
 * croisé direct : IV C != IV Python pour le même (k_master, salt) —
 * chaque ciphertext RAW produit par cagoule_encrypt_with_handle_raw()
 * était indéchiffrable par cipher_ctr_raw.py, et réciproquement, même
 * avec des k_master/S-box parfaitement identiques (H1 corrigé, vérifié
 * séparément). Fix : dériver l'IV RAW avec le salt complet (32 octets),
 * miroir exact de _derive_ctr_iv(params, nonce=salt) côté Python. */
static int derive_iv_raw(const uint8_t k_master[CAGOULE_K_MASTER_LEN],
                          const uint8_t msg_salt[SALT_SIZE],
                          uint8_t iv_out[CAGOULE_CTR_IV_SIZE])
{
    uint8_t info[15 + SALT_SIZE];  /* "CAGOULE_CTR_V31"(15) + salt(32) */
    memcpy(info, "CAGOULE_CTR_V31", 15);
    memcpy(info + 15, msg_salt, SALT_SIZE);
    uint8_t buf[CAGOULE_CTR_IV_SIZE];
    if (cagoule_kdf_hkdf(k_master, CAGOULE_K_MASTER_LEN,
                          info, sizeof(info),
                          buf, CAGOULE_CTR_IV_SIZE) != CAGOULE_KDF_OK)
        return CAGOULE_API_ERR_KDF;
    memcpy(iv_out, buf, CAGOULE_CTR_IV_SIZE);
    return CAGOULE_API_OK;
}

/* CORRECTIF (audit round 2, finding C2) — poly_key lié au msg_salt, PAS
 * dérivé une seule fois par handle.
 *
 * L'ancien design stockait poly_key = HKDF(k_master, "CAGOULE_POLY_V31", 32)
 * une seule fois dans CagouleDerivedParams (cagoule_params_derive), et
 * cagoule_encrypt_with_handle_raw / cagoule_decrypt_with_handle_raw
 * réutilisaient p->poly_key identique pour CHAQUE message d'un handle.
 * Poly1305 n'est sûr que pour un seul message par clé (contrairement à
 * ChaCha20-Poly1305 dont la sécurité vient du couple clé+nonce) — un
 * handle partagé entre plusieurs messages (l'usage bulk documenté de
 * cagoule_derive_key()) produisait donc la même clé MAC pour tous les
 * messages, permettant la forgerie universelle après 2 messages authentifiés.
 *
 * Fix : dériver poly_key par message, lié à msg_salt (32 octets, frais par
 * appel via RAND_bytes — voir cagoule_encrypt_with_handle_raw). Miroir exact
 * du fix Python (_derive_poly_key(params, salt) dans cipher_ctr_raw.py) et
 * du même pattern déjà utilisé par derive_iv() ci-dessus pour l'IV CTR.
 *
 *   poly_key = HKDF(k_master, "CAGOULE_POLY_V31" || msg_salt, 32)
 *
 * p->poly_key (dérivé statiquement dans cagoule_params_derive) n'est plus
 * utilisé par le chemin RAW — conservé dans la struct pour compatibilité
 * ABI mais son usage doit être retiré/documenté comme mort (voir suivi).
 */
static int derive_poly_key(const uint8_t k_master[CAGOULE_K_MASTER_LEN],
                            const uint8_t msg_salt[SALT_SIZE],
                            uint8_t poly_key_out[32])
{
    uint8_t info[sizeof("CAGOULE_POLY_V31") - 1 + SALT_SIZE];
    memcpy(info, "CAGOULE_POLY_V31", sizeof("CAGOULE_POLY_V31") - 1);
    memcpy(info + sizeof("CAGOULE_POLY_V31") - 1, msg_salt, SALT_SIZE);
    if (cagoule_kdf_hkdf(k_master, CAGOULE_K_MASTER_LEN,
                          info, sizeof(info),
                          poly_key_out, 32) != CAGOULE_KDF_OK)
        return CAGOULE_API_ERR_KDF;
    return CAGOULE_API_OK;
}

/* CORRECTIF (audit round 2, consolidation) : assemblage CGL1 v0x02
 * (MAGIC|VERSION|SALT|NONCE|CT|TAG) extrait dans un helper partagé.
 * cagoule_encrypt_with_handle() et cagoule_encrypt_v3() avaient chacune
 * leur propre copie de ce bloc, vérifiée IDENTIQUE octet pour octet
 * (seul le nom de variable locale du salt différait : msg_salt vs salt,
 * même rôle/taille) avant extraction.
 *
 * cagoule_encrypt_with_handle_raw() (v0x03) N'utilise PAS ce helper --
 * volontairement. Ce chemin écrit le ciphertext DIRECTEMENT dans
 * out+pos via cagoule_ctr_encrypt() (pas de buffer ct_alg séparé
 * copié ensuite), une optimisation délibérée qui évite un malloc+memcpy
 * supplémentaire pour le corps du message. Forcer ce chemin dans ce
 * helper (qui suppose un ct_aead déjà entièrement calculé en mémoire)
 * annulerait cette optimisation sans réduire la complexité réelle -- le
 * format v0x03 (pas de NONCE) diffère de toute façon structurellement. */
static size_t assemble_cgl1_aead(uint8_t *out,
                                  const uint8_t salt[SALT_SIZE],
                                  const uint8_t nonce[NONCE_SIZE],
                                  const uint8_t *ct_aead, size_t ct_len,
                                  const uint8_t tag[TAG_SIZE])
{
    size_t pos = 0;
    memcpy(out + pos, MAGIC_BYTES, MAGIC_LEN); pos += MAGIC_LEN;
    out[pos++] = CAGOULE_API_VERSION_AEAD;
    memcpy(out + pos, salt, SALT_SIZE); pos += SALT_SIZE;
    memcpy(out + pos, nonce, NONCE_SIZE); pos += NONCE_SIZE;
    memcpy(out + pos, ct_aead, ct_len); pos += ct_len;
    memcpy(out + pos, tag, TAG_SIZE); pos += TAG_SIZE;
    return pos;
}

static void build_aad(uint8_t version, const uint8_t salt[SALT_SIZE],
                       uint8_t aad_out[MAGIC_LEN + 1 + SALT_SIZE])
{
    memcpy(aad_out, MAGIC_BYTES, MAGIC_LEN);
    aad_out[MAGIC_LEN] = version;
    memcpy(aad_out + MAGIC_LEN + 1, salt, SALT_SIZE);
}

/* ════════════════════════════════════════════════════════════════════
 * OpenSSL EVP — ChaCha20-Poly1305 (VERSION 0x02)
 * ════════════════════════════════════════════════════════════════════ */

static int chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[NONCE_SIZE],
                                     const uint8_t *aad, int aad_len,
                                     const uint8_t *pt, int pt_len,
                                     uint8_t *ct_out, uint8_t tag_out[TAG_SIZE])
{
    int ret = CAGOULE_API_ERR_CRYPTO;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CAGOULE_API_ERR_ALLOC;

    int len;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad_len > 0 && 1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    if (pt_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, ct_out, &len, pt, pt_len)) goto done;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, ct_out + (pt_len > 0 ? len : 0), &len)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag_out)) goto done;
    ret = CAGOULE_API_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Déchiffre dans un buffer INTERNE (pt_internal_out), vérifie le tag, et
 * NE COPIE VERS LA SORTIE QUE SI le tag est valide — appelé par le code
 * de plus haut niveau, voir garantie d'ordre dans cagoule_api.h. */
static int chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[NONCE_SIZE],
                                     const uint8_t *aad, int aad_len,
                                     const uint8_t *ct, int ct_len,
                                     const uint8_t tag[TAG_SIZE],
                                     uint8_t *pt_internal_out)
{
    int ret = CAGOULE_API_ERR_CRYPTO;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CAGOULE_API_ERR_ALLOC;

    int len;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, NULL)) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto done;
    if (aad_len > 0 && 1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) goto done;
    if (ct_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, pt_internal_out, &len, ct, ct_len)) goto done;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void *)tag)) goto done;
    /* EVP_DecryptFinal_ex retourne <=0 si le tag ne correspond pas */
    if (1 != EVP_DecryptFinal_ex(ctx, pt_internal_out + (ct_len > 0 ? len : 0), &len)) {
        ret = CAGOULE_API_ERR_AUTH;
        goto done;
    }
    ret = CAGOULE_API_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════
 * OpenSSL EVP_MAC — Poly1305 seul (VERSION 0x03, expérimental)
 * ════════════════════════════════════════════════════════════════════ */

static int poly1305_tag(const uint8_t key[32], const uint8_t *data, size_t data_len,
                         uint8_t tag_out[TAG_SIZE])
{
    int ret = CAGOULE_API_ERR_CRYPTO;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (!mac) return CAGOULE_API_ERR_CRYPTO;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return CAGOULE_API_ERR_ALLOC; }

    size_t out_len = 0;
    if (1 != EVP_MAC_init(ctx, key, 32, NULL)) goto done;
    if (1 != EVP_MAC_update(ctx, data, data_len)) goto done;
    if (1 != EVP_MAC_final(ctx, tag_out, &out_len, TAG_SIZE)) goto done;
    if (out_len != TAG_SIZE) goto done;
    ret = CAGOULE_API_OK;
done:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════
 * Messages d'erreur humainement lisibles
 * ════════════════════════════════════════════════════════════════════ */

const char* cagoule_api_strerror(int code)
{
    switch (code) {
        case CAGOULE_API_OK:
            return "success";
        case CAGOULE_API_ERR_NULL:
            return "a required argument was NULL";
        case CAGOULE_API_ERR_SIZE:
            return "output buffer is too small for this operation";
        case CAGOULE_API_ERR_AUTH:
            return "authentication failed (wrong password, or ciphertext was corrupted or tampered with)";
        case CAGOULE_API_ERR_FORMAT:
            return "ciphertext has an invalid or unrecognized format (bad magic bytes or version)";
        case CAGOULE_API_ERR_KDF:
            return "key derivation failed (Argon2id or HKDF error)";
        case CAGOULE_API_ERR_CRYPTO:
            return "an internal cryptographic operation failed";
        case CAGOULE_API_ERR_ALLOC:
            return "memory allocation failed";
        case CAGOULE_API_ERR_EXPERIMENTAL_DISABLED:
            return "experimental mode (VERSION 0x03) was requested but is not enabled "
                   "(requires allow_experimental=1 and CAGOULE_EXPERIMENTAL_NO_AEAD=1)";
        default:
            /* Code inconnu : jamais NULL (voir contrat dans cagoule_api.h)
             * -- une chaîne générique plutôt qu'un pointeur nul, pour que
             * l'appelant puisse toujours logger sans vérification
             * supplémentaire. Ne devrait pas se produire avec les
             * fonctions de ce header ; peut arriver si un futur code de
             * retour est ajouté ici sans mettre à jour cette fonction --
             * fail loud dans les logs plutôt que de crasher l'appelant. */
            return "unknown error code (not defined in cagoule_api.h)";
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Handle
 * ════════════════════════════════════════════════════════════════════ */

CagouleKeyHandle* cagoule_derive_key(const uint8_t* password, size_t pwd_len,
                                      const uint8_t* salt, size_t salt_len)
{
    if (!password || !salt || salt_len != SALT_SIZE) return NULL;

    CagouleKeyHandle *h = calloc(1, sizeof(CagouleKeyHandle));
    if (!h) return NULL;

    if (cagoule_params_derive(password, pwd_len, salt, salt_len, &h->params)
        != CAGOULE_PARAMS_OK) {
        free(h);
        return NULL;
    }
    return h;
}

void cagoule_key_handle_free(CagouleKeyHandle* handle)
{
    if (!handle) return;
    cagoule_params_free(&handle->params);
    free(handle);
}

/* ════════════════════════════════════════════════════════════════════
 * Bulk — VERSION 0x02 (ChaCha20-Poly1305, défaut)
 * ════════════════════════════════════════════════════════════════════ */

int cagoule_encrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* pt, size_t pt_len,
                                 uint8_t* out, size_t* out_len)
{
    if (!handle || !pt || !out || !out_len) return CAGOULE_API_ERR_NULL;
    size_t needed = cagoule_api_encrypt_out_len(pt_len);
    if (*out_len < needed) return CAGOULE_API_ERR_SIZE;

    CagouleDerivedParams *p = &handle->params;

    /* CORRECTIF v3.1.0 : générer le nonce AVANT derive_iv (IV = f(nonce)).
     * msg_salt frais dans le header → re-dérivation cross-session possible.
     * handle->original_salt serait l'alternative pour la cohérence avec Python
     * bulk, mais msg_salt frais + k_master partagé est le design C bulk correct
     * (chaque message a son propre sel Argon2id virtuel dans le header). */
    uint8_t msg_salt[SALT_SIZE];
    if (1 != RAND_bytes(msg_salt, SALT_SIZE)) return CAGOULE_API_ERR_CRYPTO;

    /* Nonce généré AVANT derive_iv — l'IV dépend du nonce (pas du salt) */
    uint8_t nonce[NONCE_SIZE];
    if (1 != RAND_bytes(nonce, NONCE_SIZE)) return CAGOULE_API_ERR_CRYPTO;

    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int ret = derive_iv(p->k_master, nonce, iv);
    if (ret != CAGOULE_API_OK) return ret;

    /* ct_alg : pipeline algébrique CTR */
    uint8_t *ct_alg = malloc(pt_len > 0 ? pt_len : 1);
    if (!ct_alg) return CAGOULE_API_ERR_ALLOC;
    int cret = cagoule_ctr_encrypt(pt, pt_len, iv, p->matrix, &p->sbox,
                                    p->round_keys, CAGOULE_NUM_ROUND_KEYS, p->p,
                                    p->z_offset, CAGOULE_Z_OFFSET_N,
                                    ct_alg, pt_len > 0 ? pt_len : 1);
    if (cret != CAGOULE_OK) { free(ct_alg); return CAGOULE_API_ERR_CRYPTO; }

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_AEAD, msg_salt, aad);

    uint8_t *ct_aead = malloc(pt_len > 0 ? pt_len : 1);
    uint8_t tag[TAG_SIZE];
    if (!ct_aead) { free(ct_alg); return CAGOULE_API_ERR_ALLOC; }

    ret = chacha20poly1305_encrypt(p->k_stream, nonce, aad, sizeof(aad),
                                    ct_alg, (int)pt_len, ct_aead, tag);
    free(ct_alg);
    if (ret != CAGOULE_API_OK) { free(ct_aead); return ret; }

    /* Assemblage : MAGIC|VERSION|SALT|NONCE|CT|TAG */
    size_t pos = assemble_cgl1_aead(out, msg_salt, nonce, ct_aead, pt_len, tag);
    free(ct_aead);

    *out_len = pos;
    return CAGOULE_API_OK;
}

int cagoule_decrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* ct, size_t ct_len,
                                 uint8_t* out, size_t* out_len)
{
    if (!handle || !ct || !out || !out_len) return CAGOULE_API_ERR_NULL;
    if (ct_len < CAGOULE_API_OVERHEAD_AEAD) return CAGOULE_API_ERR_SIZE;
    if (memcmp(ct, MAGIC_BYTES, MAGIC_LEN) != 0) return CAGOULE_API_ERR_FORMAT;
    if (ct[MAGIC_LEN] != CAGOULE_API_VERSION_AEAD) return CAGOULE_API_ERR_FORMAT;

    size_t body_len = ct_len - CAGOULE_API_OVERHEAD_AEAD; /* == pt_len */
    if (*out_len < body_len) return CAGOULE_API_ERR_SIZE;

    const uint8_t *msg_salt = ct + MAGIC_LEN + 1;
    const uint8_t *nonce    = msg_salt + SALT_SIZE;
    const uint8_t *ct_aead  = nonce + NONCE_SIZE;
    const uint8_t *tag      = ct + ct_len - TAG_SIZE;

    CagouleDerivedParams *p = &handle->params;

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_AEAD, msg_salt, aad);

    /* 1. Déchiffrer + vérifier le tag dans un buffer INTERNE */
    uint8_t *ct_alg = malloc(body_len > 0 ? body_len : 1);
    if (!ct_alg) return CAGOULE_API_ERR_ALLOC;

    int ret = chacha20poly1305_decrypt(p->k_stream, nonce, aad, sizeof(aad),
                                        ct_aead, (int)body_len, tag, ct_alg);
    if (ret != CAGOULE_API_OK) {
        /* Authentification échouée — out n'est JAMAIS touché */
        OPENSSL_cleanse(ct_alg, body_len);
        free(ct_alg);
        return ret;  /* CAGOULE_API_ERR_AUTH */
    }

    /* 2. Authentifié -> déchiffrement CTR algébrique vers le buffer appelant */
    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int iret = derive_iv(p->k_master, nonce, iv);
    if (iret != CAGOULE_API_OK) {
        OPENSSL_cleanse(ct_alg, body_len);
        free(ct_alg);
        return iret;
    }

    int cret = cagoule_ctr_decrypt(ct_alg, body_len, iv, p->matrix, &p->sbox,
                                    p->round_keys, CAGOULE_NUM_ROUND_KEYS, p->p,
                                    p->z_offset, CAGOULE_Z_OFFSET_N,
                                    out, *out_len);
    OPENSSL_cleanse(ct_alg, body_len);
    free(ct_alg);
    if (cret != CAGOULE_OK) return CAGOULE_API_ERR_CRYPTO;

    *out_len = body_len;
    return CAGOULE_API_OK;
}

/* ════════════════════════════════════════════════════════════════════
 * Bulk — VERSION 0x03 (Poly1305 seul, EXPÉRIMENTAL)
 * Double gate runtime, identique en esprit à cipher_ctr_raw.py (Feature 1).
 * ════════════════════════════════════════════════════════════════════ */

#include <stdlib.h>  /* getenv */

static int experimental_gate_open(int allow_experimental)
{
    if (!allow_experimental) return 0;
    const char *env = getenv("CAGOULE_EXPERIMENTAL_NO_AEAD");
    return (env && strcmp(env, "1") == 0);
}

int cagoule_encrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* pt, size_t pt_len,
                                     uint8_t* out, size_t* out_len)
{
    if (!experimental_gate_open(allow_experimental)) return CAGOULE_API_ERR_EXPERIMENTAL_DISABLED;
    if (!handle || !pt || !out || !out_len) return CAGOULE_API_ERR_NULL;
    size_t needed = cagoule_api_encrypt_raw_out_len(pt_len);
    if (*out_len < needed) return CAGOULE_API_ERR_SIZE;

    CagouleDerivedParams *p = &handle->params;

    uint8_t msg_salt[SALT_SIZE];
    if (1 != RAND_bytes(msg_salt, SALT_SIZE)) return CAGOULE_API_ERR_CRYPTO;

    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int ret = derive_iv_raw(p->k_master, msg_salt, iv);
    if (ret != CAGOULE_API_OK) return ret;

    /* Assemblage direct dans out : MAGIC|VERSION|SALT|CT|TAG, CT écrit en place */
    size_t pos = 0;
    memcpy(out + pos, MAGIC_BYTES, MAGIC_LEN); pos += MAGIC_LEN;
    out[pos++] = CAGOULE_API_VERSION_RAW;
    memcpy(out + pos, msg_salt, SALT_SIZE); pos += SALT_SIZE;

    int cret = cagoule_ctr_encrypt(pt, pt_len, iv, p->matrix, &p->sbox,
                                    p->round_keys, CAGOULE_NUM_ROUND_KEYS, p->p,
                                    p->z_offset, CAGOULE_Z_OFFSET_N,
                                    out + pos, *out_len - pos - TAG_SIZE);
    if (cret != CAGOULE_OK) {
        /* Zéroiser les octets déjà écrits dans out avant de retourner l'erreur
         * (out+pos contient un ciphertext partiel non authentifié) */
        OPENSSL_cleanse(out, *out_len);
        return CAGOULE_API_ERR_CRYPTO;
    }

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_RAW, msg_salt, aad);

    /* CORRECTIF (audit round 2, C2) : poly_key dérivé par message depuis
     * msg_salt, PAS p->poly_key (identique pour tout le handle — voir
     * derive_poly_key() ci-dessus pour la justification complète). */
    uint8_t poly_key[32];
    ret = derive_poly_key(p->k_master, msg_salt, poly_key);
    if (ret != CAGOULE_API_OK) return ret;

    /* TAG = Poly1305(poly_key, AAD || ct_alg) — voir cipher_ctr_raw.py
     * pour la justification de lier l'AAD (déviation vs roadmap §2.2). */
    uint8_t *mac_input = malloc(sizeof(aad) + pt_len);
    if (!mac_input) { OPENSSL_cleanse(poly_key, sizeof(poly_key)); return CAGOULE_API_ERR_ALLOC; }
    memcpy(mac_input, aad, sizeof(aad));
    memcpy(mac_input + sizeof(aad), out + pos, pt_len);

    uint8_t tag[TAG_SIZE];
    ret = poly1305_tag(poly_key, mac_input, sizeof(aad) + pt_len, tag);
    free(mac_input);
    OPENSSL_cleanse(poly_key, sizeof(poly_key));
    if (ret != CAGOULE_API_OK) return ret;

    memcpy(out + pos + pt_len, tag, TAG_SIZE);
    *out_len = pos + pt_len + TAG_SIZE;
    return CAGOULE_API_OK;
}

int cagoule_decrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* ct, size_t ct_len,
                                     uint8_t* out, size_t* out_len)
{
    if (!experimental_gate_open(allow_experimental)) return CAGOULE_API_ERR_EXPERIMENTAL_DISABLED;
    if (!handle || !ct || !out || !out_len) return CAGOULE_API_ERR_NULL;
    if (ct_len < CAGOULE_API_OVERHEAD_RAW) return CAGOULE_API_ERR_SIZE;
    if (memcmp(ct, MAGIC_BYTES, MAGIC_LEN) != 0) return CAGOULE_API_ERR_FORMAT;
    if (ct[MAGIC_LEN] != CAGOULE_API_VERSION_RAW) return CAGOULE_API_ERR_FORMAT;

    size_t body_len = ct_len - CAGOULE_API_OVERHEAD_RAW;
    if (*out_len < body_len) return CAGOULE_API_ERR_SIZE;

    const uint8_t *msg_salt = ct + MAGIC_LEN + 1;
    const uint8_t *ct_alg   = msg_salt + SALT_SIZE;
    const uint8_t *tag      = ct + ct_len - TAG_SIZE;

    CagouleDerivedParams *p = &handle->params;

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_RAW, msg_salt, aad);

    /* CORRECTIF (audit round 2, C2) : même dérivation par message côté
     * decrypt — voir cagoule_encrypt_with_handle_raw pour la justification. */
    uint8_t poly_key[32];
    int ret = derive_poly_key(p->k_master, msg_salt, poly_key);
    if (ret != CAGOULE_API_OK) return ret;

    uint8_t *mac_input = malloc(sizeof(aad) + body_len);
    if (!mac_input) { OPENSSL_cleanse(poly_key, sizeof(poly_key)); return CAGOULE_API_ERR_ALLOC; }
    memcpy(mac_input, aad, sizeof(aad));
    memcpy(mac_input + sizeof(aad), ct_alg, body_len);

    uint8_t computed_tag[TAG_SIZE];
    ret = poly1305_tag(poly_key, mac_input, sizeof(aad) + body_len, computed_tag);
    free(mac_input);
    OPENSSL_cleanse(poly_key, sizeof(poly_key));
    if (ret != CAGOULE_API_OK) return ret;

    /* Comparaison constant-time — pas de memcmp() court-circuitable */
    if (CRYPTO_memcmp(computed_tag, tag, TAG_SIZE) != 0) {
        return CAGOULE_API_ERR_AUTH;  /* out n'est jamais touché */
    }

    /* Mode RAW (0x03) : pas de nonce ChaCha20 dans le header. L'IV est dérivé
     * depuis msg_salt (comme côté chiffrement raw). msg_salt joue ici le rôle
     * du nonce pour l'unicité de l'IV (dérivé via HKDF(k_master, V31+msg_salt)). */
    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int iret = derive_iv_raw(p->k_master, msg_salt, iv);
    if (iret != CAGOULE_API_OK) return iret;

    int cret = cagoule_ctr_decrypt(ct_alg, body_len, iv, p->matrix, &p->sbox,
                                    p->round_keys, CAGOULE_NUM_ROUND_KEYS, p->p,
                                    p->z_offset, CAGOULE_Z_OFFSET_N,
                                    out, *out_len);
    if (cret != CAGOULE_OK) return CAGOULE_API_ERR_CRYPTO;

    *out_len = body_len;
    return CAGOULE_API_OK;
}

/* ════════════════════════════════════════════════════════════════════
 * Mono-message — derive + crypt + free (VERSION 0x02, défaut)
 * Compatible bit-à-bit avec encrypt_ctr()/decrypt_ctr() Python.
 * ════════════════════════════════════════════════════════════════════ */

int cagoule_encrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* out, size_t* out_len)
{
    if (!password || !pt || !out || !out_len) return CAGOULE_API_ERR_NULL;
    if (*out_len < cagoule_api_encrypt_out_len(pt_len)) return CAGOULE_API_ERR_SIZE;

    uint8_t salt[SALT_SIZE];
    if (1 != RAND_bytes(salt, SALT_SIZE)) return CAGOULE_API_ERR_CRYPTO;

    CagouleDerivedParams params;
    if (cagoule_params_derive(password, pwd_len, salt, SALT_SIZE, &params)
        != CAGOULE_PARAMS_OK)
        return CAGOULE_API_ERR_KDF;

    /* CORRECTIF v3.1.0 : nonce généré avant derive_iv (IV = f(nonce)) */
    uint8_t nonce[NONCE_SIZE];
    if (1 != RAND_bytes(nonce, NONCE_SIZE)) {
        cagoule_params_free(&params);
        return CAGOULE_API_ERR_CRYPTO;
    }

    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int ret = derive_iv(params.k_master, nonce, iv);
    if (ret != CAGOULE_API_OK) { cagoule_params_free(&params); return ret; }

    uint8_t *ct_alg = malloc(pt_len > 0 ? pt_len : 1);
    if (!ct_alg) { cagoule_params_free(&params); return CAGOULE_API_ERR_ALLOC; }
    int cret = cagoule_ctr_encrypt(pt, pt_len, iv, params.matrix, &params.sbox,
                                    params.round_keys, CAGOULE_NUM_ROUND_KEYS, params.p,
                                    params.z_offset, CAGOULE_Z_OFFSET_N,
                                    ct_alg, pt_len > 0 ? pt_len : 1);
    if (cret != CAGOULE_OK) { free(ct_alg); cagoule_params_free(&params); return CAGOULE_API_ERR_CRYPTO; }

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_AEAD, salt, aad);

    uint8_t *ct_aead = malloc(pt_len > 0 ? pt_len : 1);
    uint8_t tag[TAG_SIZE];
    if (!ct_aead) { free(ct_alg); cagoule_params_free(&params); return CAGOULE_API_ERR_ALLOC; }

    ret = chacha20poly1305_encrypt(params.k_stream, nonce, aad, sizeof(aad),
                                    ct_alg, (int)pt_len, ct_aead, tag);
    free(ct_alg);
    cagoule_params_free(&params);
    if (ret != CAGOULE_API_OK) { free(ct_aead); return ret; }

    size_t pos = assemble_cgl1_aead(out, salt, nonce, ct_aead, pt_len, tag);
    free(ct_aead);

    *out_len = pos;
    return CAGOULE_API_OK;
}

int cagoule_decrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* ct, size_t ct_len,
                        uint8_t* out, size_t* out_len)
{
    if (!password || !ct || !out || !out_len) return CAGOULE_API_ERR_NULL;
    if (ct_len < CAGOULE_API_OVERHEAD_AEAD) return CAGOULE_API_ERR_SIZE;
    if (memcmp(ct, MAGIC_BYTES, MAGIC_LEN) != 0) return CAGOULE_API_ERR_FORMAT;
    if (ct[MAGIC_LEN] != CAGOULE_API_VERSION_AEAD) return CAGOULE_API_ERR_FORMAT;

    size_t body_len = ct_len - CAGOULE_API_OVERHEAD_AEAD;
    if (*out_len < body_len) return CAGOULE_API_ERR_SIZE;

    const uint8_t *salt     = ct + MAGIC_LEN + 1;
    const uint8_t *nonce    = salt + SALT_SIZE;
    const uint8_t *ct_aead  = nonce + NONCE_SIZE;
    const uint8_t *tag      = ct + ct_len - TAG_SIZE;

    CagouleDerivedParams params;
    if (cagoule_params_derive(password, pwd_len, salt, SALT_SIZE, &params)
        != CAGOULE_PARAMS_OK)
        return CAGOULE_API_ERR_KDF;

    uint8_t aad[MAGIC_LEN + 1 + SALT_SIZE];
    build_aad(CAGOULE_API_VERSION_AEAD, salt, aad);

    uint8_t *ct_alg = malloc(body_len > 0 ? body_len : 1);
    if (!ct_alg) { cagoule_params_free(&params); return CAGOULE_API_ERR_ALLOC; }

    int ret = chacha20poly1305_decrypt(params.k_stream, nonce, aad, sizeof(aad),
                                        ct_aead, (int)body_len, tag, ct_alg);
    if (ret != CAGOULE_API_OK) {
        OPENSSL_cleanse(ct_alg, body_len);
        free(ct_alg);
        cagoule_params_free(&params);
        return ret;
    }

    uint8_t iv[CAGOULE_CTR_IV_SIZE];
    int iret = derive_iv(params.k_master, nonce, iv);
    if (iret != CAGOULE_API_OK) {
        OPENSSL_cleanse(ct_alg, body_len);
        free(ct_alg);
        cagoule_params_free(&params);
        return iret;
    }

    int cret = cagoule_ctr_decrypt(ct_alg, body_len, iv, params.matrix, &params.sbox,
                                    params.round_keys, CAGOULE_NUM_ROUND_KEYS, params.p,
                                    params.z_offset, CAGOULE_Z_OFFSET_N,
                                    out, *out_len);
    OPENSSL_cleanse(ct_alg, body_len);
    free(ct_alg);
    cagoule_params_free(&params);
    if (cret != CAGOULE_OK) return CAGOULE_API_ERR_CRYPTO;

    *out_len = body_len;
    return CAGOULE_API_OK;
}
