/**
 * cagoule_math.c — Données constantes arithmétique CAGOULE v3.1.0
 *
 * Définitions des tables Mersenne-64 (déclarées extern dans cagoule_math.h).
 * Pool de 8 premiers de la forme p = 2^64 - k, vérifiés Miller-Rabin (13 témoins).
 */
#include "cagoule_math.h"

const uint64_t CAGOULE_MERSENNE_K[CAGOULE_MERSENNE_POOL_SIZE] = {
     59ULL,  83ULL,  95ULL, 179ULL,
    189ULL, 257ULL, 279ULL, 323ULL
};

const uint64_t CAGOULE_MERSENNE_P[CAGOULE_MERSENNE_POOL_SIZE] = {
    18446744073709551557ULL,  /* 2^64 -  59 */
    18446744073709551533ULL,  /* 2^64 -  83 */
    18446744073709551521ULL,  /* 2^64 -  95 */
    18446744073709551437ULL,  /* 2^64 - 179 */
    18446744073709551427ULL,  /* 2^64 - 189 */
    18446744073709551359ULL,  /* 2^64 - 257 */
    18446744073709551337ULL,  /* 2^64 - 279 */
    18446744073709551293ULL,  /* 2^64 - 323 */
};

uint64_t cagoule_mersenne_k(uint64_t p) {
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++)
        if (CAGOULE_MERSENNE_P[i] == p) return CAGOULE_MERSENNE_K[i];
    return 0;
}
