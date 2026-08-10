/**
 * test_params_kat.c — Known-Answer Test for cagoule_params_derive
 * CAGOULE v3.1.0
 *
 * Closes a real audit gap: cagoule_params_derive backs both flagship
 * v3.1.0 features (cagoule_api.c's unified C API, cagoule_stream.c's
 * streaming API) but had zero test coverage — no test, C or Python,
 * verified its output byte-by-byte before this file existed.
 *
 * The expected values below were cross-checked directly against the
 * Python reference (CagouleParams.derive, params.py) for the exact
 * same (password, salt) pair, with fast_mode=False so the Argon2id
 * parameters match cagoule_kdf.c's CAGOULE_ARGON2_TIME_COST=3 /
 * CAGOULE_ARGON2_MEM_COST_KB=65536 / CAGOULE_ARGON2_PARALLELISM=1
 * exactly (fast_mode=True uses cheaper, non-matching parameters).
 * All fields matched exactly: k_master (64 bytes), p, k_mersenne, n,
 * k_stream (32 bytes), and the full round_keys[64] and z_offset[16]
 * arrays (not just a prefix). This file hardcodes that cross-checked
 * result so future changes are caught without needing Python at all.
 *
 * If this test starts failing, it means the C KDF pipeline has
 * diverged from the Python reference implementation for the same
 * password+salt — a real interop bug, not a flaky test.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cagoule_params.h"

static long g_pass = 0, g_fail = 0;

#define CHECK(c) do { if(c) g_pass++; else { g_fail++; \
    fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c);} } while(0)

/* Fixed test vector: password + salt = bytes 0x00..0x1F */
static const uint8_t KAT_PASSWORD[] = "CAGOULE_KAT_TEST_PASSWORD";
static const size_t  KAT_PASSWORD_LEN = sizeof(KAT_PASSWORD) - 1;

static const uint8_t KAT_EXPECTED_K_MASTER[64] = {
    0x92,0xb6,0xe6,0xf0,0xac,0x72,0x03,0x3a,0x21,0x2d,0x62,0x92,0x2b,0xc6,0x43,0x54,
    0x5a,0x87,0x21,0xa1,0x7a,0x30,0x1e,0xae,0x6c,0xc5,0xb1,0xb6,0x64,0x9d,0x84,0x5c,
    0x5f,0x79,0x35,0x01,0x96,0xec,0xbe,0xab,0xdb,0x5b,0xd5,0x62,0x58,0x34,0xd6,0x7d,
    0x87,0x32,0x92,0xd2,0xc6,0x52,0xa1,0xc8,0x28,0xd5,0xeb,0x22,0xd6,0x64,0x33,0x4c
};

static const uint64_t KAT_EXPECTED_P          = 18446744073709551521ULL;
static const uint64_t KAT_EXPECTED_K_MERSENNE = 95ULL;
static const int      KAT_EXPECTED_N          = 39350;

static const uint8_t KAT_EXPECTED_K_STREAM[32] = {
    0xb2,0x83,0x31,0xab,0x3e,0x89,0xcc,0xd2,0x54,0x13,0xe1,0xf4,0xfa,0xd4,0xe2,0xf7,
    0x61,0xf5,0xf7,0xa6,0x78,0x10,0x5c,0x0d,0xdc,0x64,0x3e,0xa8,0xa3,0xee,0x62,0x5a
};

static const uint64_t KAT_EXPECTED_ROUND_KEYS[64] = {
    8282801272827154463ULL,9106065451482819274ULL,2354257583153206022ULL,8056360953070842038ULL,
    1057751194114792196ULL,14844052832360153589ULL,1309654403666390102ULL,13591763838692561067ULL,
    8265054382095786520ULL,13708964359213603646ULL,660097527757301872ULL,14672399715703918645ULL,
    2897282635433085481ULL,3335032199651986135ULL,643215701941317468ULL,1847268581273481170ULL,
    9692438316137179684ULL,14401726475903668342ULL,1691991812922800319ULL,6924060352490015133ULL,
    12540753992978855031ULL,11902197402854186185ULL,6368992926565217202ULL,10751630777635016489ULL,
    8772702485860938160ULL,6475049987780660419ULL,392427908191152527ULL,7024929588369767011ULL,
    10574650897246948376ULL,2981768466941955187ULL,11961133168773949325ULL,6063686017889842421ULL,
    14538476228868011043ULL,11018877846370372338ULL,12917126823994405672ULL,11627087606873790979ULL,
    9171534890082001758ULL,11161225403412120842ULL,6150947873516032062ULL,7801393008861154192ULL,
    15372295217808131842ULL,1846223745048161446ULL,7511416793080565927ULL,18150866849563005342ULL,
    3538171104606489108ULL,1185433143621738222ULL,11874848235002516889ULL,12842456331381552868ULL,
    11656719904617442198ULL,6653752471606380096ULL,7304402656928709553ULL,15566388326854912103ULL,
    9254630169028907742ULL,16113744775074898819ULL,4024226274956693523ULL,9171671140665857508ULL,
    1534840041796336883ULL,2033613945342587355ULL,12194411247132472611ULL,9534256809345875670ULL,
    11018969757469522496ULL,2445498697334789550ULL,15791269594351582273ULL,11840835021511339763ULL
};

static const uint64_t KAT_EXPECTED_Z_OFFSET[16] = {
    12156878684717804700ULL,1292918075975190723ULL,17621098322991936392ULL,2321529748176537018ULL,
    10326235790625657943ULL,18414145423943540004ULL,8892308055491879596ULL,1474577420799323176ULL,
    11232451028978251809ULL,6610305115741185353ULL,14897702302703981203ULL,13534781196613235848ULL,
    9994281119307568932ULL,4839465516825210353ULL,12856973584978201968ULL,9580612129644841673ULL
};

static void test_kat_derive(void) {
    puts("  KAT : cagoule_params_derive vs Python reference (fast_mode=False)");

    uint8_t salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (uint8_t)i;

    CagouleDerivedParams params;
    memset(&params, 0, sizeof(params));

    int ret = cagoule_params_derive(KAT_PASSWORD, KAT_PASSWORD_LEN, salt, sizeof(salt), &params);
    CHECK(ret == CAGOULE_PARAMS_OK);
    if (ret != CAGOULE_PARAMS_OK) return;

    CHECK(memcmp(params.k_master, KAT_EXPECTED_K_MASTER, 64) == 0);
    CHECK(params.p == KAT_EXPECTED_P);
    CHECK(params.k_mersenne == KAT_EXPECTED_K_MERSENNE);
    CHECK(params.n_zeta == KAT_EXPECTED_N);
    CHECK(memcmp(params.k_stream, KAT_EXPECTED_K_STREAM, 32) == 0);
    CHECK(memcmp(params.round_keys, KAT_EXPECTED_ROUND_KEYS, sizeof(KAT_EXPECTED_ROUND_KEYS)) == 0);
    CHECK(memcmp(params.z_offset, KAT_EXPECTED_Z_OFFSET, sizeof(KAT_EXPECTED_Z_OFFSET)) == 0);

    /* matrix must have been allocated (part of what derive() produces) */
    CHECK(params.matrix != NULL);

    cagoule_params_free(&params);
}

static void test_kat_deterministic_repeat(void) {
    puts("  KAT : repeat derivation is deterministic (same salt -> same output)");

    uint8_t salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (uint8_t)i;

    CagouleDerivedParams p1, p2;
    memset(&p1, 0, sizeof(p1));
    memset(&p2, 0, sizeof(p2));

    CHECK(cagoule_params_derive(KAT_PASSWORD, KAT_PASSWORD_LEN, salt, sizeof(salt), &p1) == CAGOULE_PARAMS_OK);
    CHECK(cagoule_params_derive(KAT_PASSWORD, KAT_PASSWORD_LEN, salt, sizeof(salt), &p2) == CAGOULE_PARAMS_OK);

    CHECK(memcmp(p1.k_master, p2.k_master, 64) == 0);
    CHECK(p1.p == p2.p);
    CHECK(memcmp(p1.round_keys, p2.round_keys, sizeof(p1.round_keys)) == 0);

    cagoule_params_free(&p1);
    cagoule_params_free(&p2);
}

static void test_kat_different_salt_diverges(void) {
    puts("  KAT : different salt produces different k_master (sanity check)");

    uint8_t salt_a[32], salt_b[32];
    for (int i = 0; i < 32; i++) { salt_a[i] = (uint8_t)i; salt_b[i] = (uint8_t)(i + 1); }

    CagouleDerivedParams pa, pb;
    memset(&pa, 0, sizeof(pa));
    memset(&pb, 0, sizeof(pb));

    CHECK(cagoule_params_derive(KAT_PASSWORD, KAT_PASSWORD_LEN, salt_a, sizeof(salt_a), &pa) == CAGOULE_PARAMS_OK);
    CHECK(cagoule_params_derive(KAT_PASSWORD, KAT_PASSWORD_LEN, salt_b, sizeof(salt_b), &pb) == CAGOULE_PARAMS_OK);

    CHECK(memcmp(pa.k_master, pb.k_master, 64) != 0);

    cagoule_params_free(&pa);
    cagoule_params_free(&pb);
}

int main(void) {
    puts("=== test_params_kat CAGOULE v3.1.0 ===");
    test_kat_derive();
    test_kat_deterministic_repeat();
    test_kat_different_salt_diverges();
    printf("\n=== %ld passés / %ld échoués ===\n", g_pass, g_fail);
    return g_fail != 0;
}
