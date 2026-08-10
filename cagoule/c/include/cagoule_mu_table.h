/**
 * cagoule_mu_table.h — Table précalculée µ (racine de x⁴+x²+1) — CAGOULE v3.1.0
 *
 * ── Justification de la précalculation (au lieu d'un port complet de
 *    mu.py + fp2.py en C) ──────────────────────────────────────────────
 *
 * mu.py::generate_mu(p) est une fonction PURE de p uniquement (aucune
 * dépendance à password/salt/k_master). Le pool de premiers Mersenne-64
 * est figé à 8 valeurs (CAGOULE_MERSENNE_P[8], cagoule_math.c) — changer
 * le pool est un changement de version majeur, pas un événement runtime.
 * generate_mu() est donc une fonction déterministe à domaine fini (8
 * entrées) : la précalculer est strictement équivalente à l'exécuter,
 * sans risque de divergence, et évite de porter en C ~165 lignes de
 * Tonelli-Shanks (mu.py) + arithmétique Fp² (fp2.py) pour un domaine qui
 * ne variera jamais à runtime.
 *
 * Simplification supplémentaire : pour les 4 primes où generate_mu()
 * résout dans Fp² (in_fp2=True, stratégie C), le résultat est TOUJOURS
 * Fp2Element.t_generator(p) = Fp2(a=0, b=1) — t_generator() est un
 * générateur canonique constant, pas une recherche. Et le seul
 * consommateur de mu (_derive_nodes() dans params.py) n'utilise que la
 * composante `.a` (alpha0 = mu.a si in_fp2, sinon mu lui-même) — donc
 * alpha0 = 0 pour ces 4 primes, par construction, pas par coïncidence.
 *
 * Pour les 4 primes où generate_mu() résout dans Z/pZ (in_fp2=False,
 * stratégie A — racine carrée de x²+x+1 via Tonelli-Shanks), alpha0 est
 * une vraie constante dépendant de p, ci-dessous.
 *
 * Vérifié par KAT croisé : tests/test_params_kat.c compare alpha0[i]
 * (via les nœuds dérivés) à la sortie de mu.py::generate_mu() pour les
 * 8 primes — voir Makefile cible `test-params-kat`.
 *
 * ⚠️ Si le pool CAGOULE_MERSENNE_P change en v3.x+1, cette table DOIT
 * être régénérée (script : tools/gen_mu_table.py) — sinon dérivation
 * silencieusement incorrecte pour le(s) nouveau(x) premier(s).
 */
#ifndef CAGOULE_MU_TABLE_H
#define CAGOULE_MU_TABLE_H

#include <stdint.h>
#include "cagoule_math.h"  /* CAGOULE_MERSENNE_POOL_SIZE */

/* Index identique à CAGOULE_MERSENNE_P[] / CAGOULE_MERSENNE_K[] —
 * cagoule_math.c : k = {59, 83, 95, 179, 189, 257, 279, 323}. */
static const uint64_t CAGOULE_MU_ALPHA0[CAGOULE_MERSENNE_POOL_SIZE] = {
    0ULL,                     /* idx=0 k=59   in_fp2=True  (t_generator.a=0) */
    0ULL,                     /* idx=1 k=83   in_fp2=True  (t_generator.a=0) */
    0ULL,                     /* idx=2 k=95   in_fp2=True  (t_generator.a=0) */
    0ULL,                     /* idx=3 k=179  in_fp2=True  (t_generator.a=0) */
    11212893662801646712ULL,  /* idx=4 k=189  in_fp2=False (racine Z/pZ)     */
    0ULL,                     /* idx=5 k=257  in_fp2=True  (t_generator.a=0) */
    8882532405220777589ULL,   /* idx=6 k=279  in_fp2=False (racine Z/pZ)     */
    0ULL,                     /* idx=7 k=323  in_fp2=True  (t_generator.a=0) */
};

#endif /* CAGOULE_MU_TABLE_H */
