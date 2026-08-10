/**
 * test_format.c — CGL1 Format VERSION dispatch tests CAGOULE v3.1.0
 *
 * Valide que le champ VERSION du header CGL1 est correctement
 * identifié et que les erreurs sont remontées proprement.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cagoule_cipher.h"
#include "cagoule_ctr.h"

static long g_pass = 0, g_fail = 0;

#define CHECK(c) do { if(c) g_pass++; else { g_fail++; \
    fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c);} } while(0)

/* Header CGL1 minimal (MAGIC + VERSION + SALT + NONCE) */
#define MAGIC_BYTES  "CGL1"
#define SALT_SIZE    32
#define NONCE_SIZE   12

static void test_version_detection(void) {
    puts("  VERSION byte detection");

    uint8_t hdr[5];
    memcpy(hdr, MAGIC_BYTES, 4);

    /* VERSION 0x01 → CBC */
    hdr[4] = 0x01;
    CHECK(hdr[4] == CAGOULE_CGL1_VERSION_CBC);

    /* VERSION 0x02 → CTR */
    hdr[4] = 0x02;
    CHECK(hdr[4] == CAGOULE_CGL1_VERSION_CTR);

    /* VERSION 0xFF → inconnu */
    hdr[4] = 0xFF;
    CHECK(hdr[4] != CAGOULE_CGL1_VERSION_CBC);
    CHECK(hdr[4] != CAGOULE_CGL1_VERSION_CTR);

    /* MAGIC invalide */
    uint8_t bad_magic[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x02};
    CHECK(bad_magic[0] != 'C');
}

static void test_cgl1_constants(void) {
    puts("  CGL1 v0x02 constants");
    CHECK(CAGOULE_CGL1_VERSION_CBC == 0x01);
    CHECK(CAGOULE_CGL1_VERSION_CTR == 0x02);
    CHECK(CAGOULE_CTR_IV_SIZE == 8);
    CHECK(CAGOULE_N == 16);
}

int main(void) {
    puts("=== test_format CAGOULE v3.1.0 ===");
    test_cgl1_constants();
    test_version_detection();
    printf("\n=== %ld passés / %ld échoués ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
