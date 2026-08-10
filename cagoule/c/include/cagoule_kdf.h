/**
 * cagoule_kdf.h — Primitives KDF partagées pour cagoule_api.c — CAGOULE v3.1.0
 *
 * Portage C de params.py (dérivation complète des paramètres) :
 *   - Argon2id (k_master) via libargon2
 *   - HKDF-SHA256 générique multi-bloc (Extract + Expand RFC 5869),
 *     bit-compatible avec cryptography.hazmat.primitives.kdf.hkdf.HKDF
 *     (salt=None ≡ sel de SHA256_LEN zéros à l'Extract).
 *
 * Différence avec l'implémentation privée dans cagoule_omega.c : celle-ci
 * supporte un nombre arbitraire de blocs en sortie (nécessaire pour
 * z_offset, 128 octets = 4 blocs), alors que omega.c se limite à un seul
 * bloc T(1) (32 octets max), suffisant pour les clés de ronde uniquement.
 *
 * Vérifié par KAT croisé Python/C — voir tests/test_kdf_kat.c.
 */
#ifndef CAGOULE_KDF_H
#define CAGOULE_KDF_H

#include <stdint.h>
#include <stddef.h>

#define CAGOULE_KDF_OK            0
#define CAGOULE_KDF_ERR_NULL     -1
#define CAGOULE_KDF_ERR_PARAM    -2
#define CAGOULE_KDF_ERR_OPENSSL  -3
#define CAGOULE_KDF_ERR_ARGON2   -4

#define CAGOULE_SHA256_LEN  32
#define CAGOULE_K_MASTER_LEN 64
#define CAGOULE_SALT_LEN     32

/* Paramètres Argon2id — DOIVENT rester synchronisés avec params.py
 * (_kdf_argon2id : time_cost=3, memory_cost=65536 KiB, parallelism=1). */
#define CAGOULE_ARGON2_TIME_COST   3
#define CAGOULE_ARGON2_MEM_COST_KB 65536
#define CAGOULE_ARGON2_PARALLELISM 1

/**
 * k_master = Argon2id(password, salt, t=3, m=65536KiB, p=1, len=64)
 *
 * @param password,pwd_len  Mot de passe
 * @param salt              DOIT faire CAGOULE_SALT_LEN (32) octets
 * @param out_k_master      Buffer de sortie, CAGOULE_K_MASTER_LEN (64) octets
 * @return CAGOULE_KDF_OK ou code d'erreur négatif
 */
int cagoule_kdf_argon2id(const uint8_t *password, size_t pwd_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t out_k_master[CAGOULE_K_MASTER_LEN]);

/**
 * HKDF-SHA256 complet (Extract avec salt=zéros, puis Expand multi-bloc).
 * Reproduit exactement hkdf_derive() de params.py pour out_len arbitraire.
 *
 * @param ikm,ikm_len    Clé d'entrée (typiquement k_master)
 * @param info,info_len  Contexte (ex: b"CAGOULE_DELTA")
 * @param out,out_len    Buffer de sortie, out_len arbitraire (multi-bloc géré)
 */
int cagoule_kdf_hkdf(const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out, size_t out_len);

/**
 * Équivalent hkdf_int() de params.py : dérive n_bytes octets via HKDF,
 * interprète comme un entier big-endian dans un uint64_t.
 * n_bytes DOIT être <= 8.
 */
int cagoule_kdf_hkdf_u64(const uint8_t *ikm, size_t ikm_len,
                          const uint8_t *info, size_t info_len,
                          size_t n_bytes, uint64_t *out);

#endif /* CAGOULE_KDF_H */
