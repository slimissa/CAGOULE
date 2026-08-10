# Makefile — CAGOULE v3.1.0 libcagoule.so
#
# Cibles principales :
#   make              → compile libcagoule.so (AVX2 si disponible)
#   make tests        → exécute tous les tests C (scalaires + AVX2 + CTR)
#   make test-avx2    → tests AVX2 uniquement
#   make test-scalar  → force le chemin scalaire (CI sans AVX2)
#   make test-ctr     → tests CTR uniquement (v3.1.0)
#   make test-format  → tests format CGL1 (v3.1.0)
#   make test-ct      → test constant-time (dudect)
#   make profile      → build profiling isolé (PROFILE_CTR), clean avant/après
#   make valgrind     → vérifie les fuites mémoire (inclut CTR)
#   make debug        → compile avec ASan + UBSan
#   make fuzz         → libFuzzer 1M runs (CBC + CTR)
#   make release      → build production : LTO + NDEBUG + strip
#   make benchmark    → CTR, runs répétés + warmup, rapporte mean/min/max
#   make install      → copie dans le package Python
#   make clean        → nettoie
#
# Nouveautés v3.0.0 :
#   - cagoule_ctr.c : mode CTR avec pipeline 4x
#   - test_ctr / test_format : nouveaux binaires de test
#   - fuzz_cipher : support CTR (mode bit 2)
#   - cagoule_cipher.h : constantes CGL1_VERSION_CBC/CTR
#   - Makefile : cibles test-ctr, test-format, test-ct

CC       = gcc
# -O3 (vs -O2) est intentionnel pour une bibliothèque cryptographique :
#   - déroulage de boucles (-funroll-loops implicite) → critique pour les
#     boucles de 4 iterations dans les fonctions SIMD (sbox, rk_add, etc.)
#   - inlining plus agressif des helpers static inline
#   - meilleure allocation de registres pour les registres YMM
# -funroll-loops : déroulage explicite des boucles N=16 (4 iterations de 4)
CFLAGS   = -O3 -funroll-loops -std=c99 -Wall -Wextra -fPIC -Iinclude
CFLAGS  += -D_POSIX_C_SOURCE=200809L
# EXTRA_CFLAGS/EXTRA_LDFLAGS : hooks pour `make release` (LTO, NDEBUG).
# Vides par défaut -- n'affectent aucune cible existante. Utiliser des
# variables séparées plutôt que d'écraser CFLAGS/LDFLAGS directement sur
# la ligne de commande, car une variable make positionnée en ligne de
# commande devient immuable pour le reste du run et bloquerait les
# `CFLAGS +=` qui suivent (détection AVX2, OpenSSL, -march=native).
CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS  = -shared $(EXTRA_LDFLAGS)
LDLIBS   = -lm -lcrypto -largon2

PYTHON  ?= python3

ifeq ($(shell uname -m),x86_64) 
    CFLAGS += -march=native
endif

# Détection AVX2
HAS_AVX2 := $(shell $(PYTHON) $(dir $(firstword $(MAKEFILE_LIST)))check_avx2.py 2>/dev/null || echo no)

# Détection __uint128_t
HAS_UINT128 := $(shell echo 'int main() { __uint128_t x = 0; return 0; }' | \
               $(CC) -x c -o /dev/null - 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_UINT128),no)
    $(error Ce compilateur ne supporte pas __uint128_t. GCC >= 4.6 requis)
endif

# Détection OpenSSL
HAS_OPENSSL := $(shell pkg-config --exists openssl 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_OPENSSL),yes)
    CFLAGS  += $(shell pkg-config --cflags openssl)
    LDLIBS  += $(shell pkg-config --libs-only-l openssl)
else
    $(warning OpenSSL non trouvé via pkg-config, utilisation de -lcrypto direct)
endif

# Détection Argon2
HAS_ARGON2 := $(shell pkg-config --exists libargon2 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_ARGON2),yes)
    CFLAGS  += $(shell pkg-config --cflags libargon2)
else
    $(error libargon2 non trouvé. Installer : sudo apt install libargon2-dev)
endif

# ── Sources de base ─────────────────────────────────────────────────────
SRCS     = src/cagoule_math.c \
           src/cagoule_matrix.c \
           src/cagoule_sbox.c   \
           src/cagoule_cipher.c \
           src/cagoule_ctr.c \
           src/cagoule_omega.c \
           src/cagoule_api.c \
           src/cagoule_kdf.c \
           src/cagoule_params.c \
           src/cagoule_stream.c

# ── ARM NEON (v3.1.0 Feature 3) ─────────────────────────────────────
ifeq ($(shell uname -m),aarch64)
    SRCS += src/cagoule_matrix_neon.c
endif

# ── Modules AVX2 (compilés avec -mavx2 séparément) ─────────────────────
ifeq ($(HAS_AVX2),yes)
    SRCS       += src/cagoule_matrix_avx2.c
    SRCS       += src/cagoule_sbox_avx2.c
    CFLAGS_AVX2 = -mavx2
    AVX2_STATUS = actif (matrice + S-box)
else
    CFLAGS_AVX2 =
    AVX2_STATUS = absent (fallback scalaire)
endif

OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)
LIB  = libcagoule.so

# ── Règles spéciales AVX2 ───────────────────────────────────────────────
src/cagoule_matrix_avx2.o: src/cagoule_matrix_avx2.c
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -MMD -c $< -o $@

src/cagoule_sbox_avx2.o: src/cagoule_sbox_avx2.c
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -MMD -c $< -o $@

src/cagoule_cipher.o: src/cagoule_cipher.c
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -MMD -c $< -o $@


.PHONY: all tests test-avx2 test-scalar test-ctr test-format test-ct profile \
        bench clean install check-openssl debug valgrind help sysinfo \
        fuzz fuzz-long release benchmark dist

all: $(LIB)
	@echo "  AVX2 : $(AVX2_STATUS)"

$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "✓ $(LIB) compilé (CAGOULE v3.1.0)"

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(DEPS)

tests: $(LIB) test_math test_matrix test_sbox test_cipher test_omega test_ctr test_format \
             test_math_avx2 test_matrix_avx2 test_sbox_avx2 test_cipher_pipeline4 test_mersenne \
             test_api_raw test_params_kat test_stream test_error_paths
	@echo ""
	@echo "══════════════════════════════════════════════════════"
	@echo "  Exécution des tests CAGOULE v3.1.0 (scalaires + AVX2 + CTR)"
	@echo "══════════════════════════════════════════════════════"
	@status=0; \
	./test_mersenne        && echo "✓ test_mersenne        OK" || { echo "✗ test_mersenne        FAIL"; status=1; }; \
	./test_math            && echo "✓ test_math            OK" || { echo "✗ test_math            FAIL"; status=1; }; \
	./test_matrix          && echo "✓ test_matrix          OK" || { echo "✗ test_matrix          FAIL"; status=1; }; \
	./test_sbox            && echo "✓ test_sbox            OK" || { echo "✗ test_sbox            FAIL"; status=1; }; \
	./test_cipher          && echo "✓ test_cipher          OK" || { echo "✗ test_cipher          FAIL"; status=1; }; \
	./test_omega           && echo "✓ test_omega           OK" || { echo "✗ test_omega           FAIL"; status=1; }; \
	./test_ctr             && echo "✓ test_ctr             OK" || { echo "✗ test_ctr             FAIL"; status=1; }; \
	./test_format          && echo "✓ test_format          OK" || { echo "✗ test_format          FAIL"; status=1; }; \
	./test_api_raw         && echo "✓ test_api_raw         OK" || { echo "✗ test_api_raw         FAIL"; status=1; }; \
	./test_params_kat      && echo "✓ test_params_kat      OK" || { echo "✗ test_params_kat      FAIL"; status=1; }; \
	./test_stream          && echo "✓ test_stream          OK" || { echo "✗ test_stream          FAIL"; status=1; }; \
	./test_error_paths     && echo "✓ test_error_paths     OK" || { echo "✗ test_error_paths     FAIL"; status=1; }; \
	./test_math_avx2       && echo "✓ test_math_avx2       OK" || { echo "✗ test_math_avx2       FAIL"; status=1; }; \
	./test_matrix_avx2     && echo "✓ test_matrix_avx2     OK" || { echo "✗ test_matrix_avx2     FAIL"; status=1; }; \
	./test_sbox_avx2       && echo "✓ test_sbox_avx2       OK" || { echo "✗ test_sbox_avx2       FAIL"; status=1; }; \
	./test_cipher_pipeline4 && echo "✓ test_cipher_pipeline4 OK" || { echo "✗ test_cipher_pipeline4 FAIL"; status=1; }; \
	echo "══════════════════════════════════════════════════════"; \
	[ $$status -eq 0 ] && echo "  ✅ Tous les tests passent (v3.1.0)" || echo "  ❌ Certains tests ont échoué"; \
	echo "══════════════════════════════════════════════════════"; \
	exit $$status

test-avx2: $(LIB) test_math_avx2 test_matrix_avx2 test_sbox_avx2 test_mersenne
	./test_mersenne && ./test_math_avx2 && ./test_matrix_avx2 && ./test_sbox_avx2
	@echo "✓ Tests AVX2 OK (Mersenne + matrice + S-box)"

test-scalar: $(LIB) test_matrix_avx2 test_sbox_avx2
	@echo "=== Mode scalaire forcé (CAGOULE_FORCE_SCALAR=1) ==="
	CAGOULE_FORCE_SCALAR=1 ./test_matrix_avx2
	CAGOULE_FORCE_SCALAR=1 ./test_sbox_avx2
	@echo "✓ Tests scalaires OK"

test-ctr: $(LIB) test_ctr test_format test_api_raw
	./test_ctr && ./test_format && ./test_api_raw
	@echo "✓ Tests CTR + format OK (v3.1.0)"

test-format: $(LIB) test_format
	./test_format && echo "✓ test_format OK"

# ── Compilation des exécutables de test ─────────────────────────────────
test_mersenne: tests/test_mersenne.c $(LIB) include/cagoule_math.h include/cagoule_math_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_math: tests/test_math.c $(LIB) include/cagoule_math.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_matrix: tests/test_matrix.c $(LIB) include/cagoule_math.h include/cagoule_matrix.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_sbox: tests/test_sbox.c $(LIB) include/cagoule_math.h include/cagoule_sbox.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_cipher: tests/test_cipher.c $(LIB) include/cagoule_cipher.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_omega: tests/test_omega.c $(LIB) include/cagoule_omega.h include/cagoule_math.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS) -lpthread

test_params_kat: tests/test_params_kat.c $(LIB) include/cagoule_params.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_stream: tests/test_stream.c $(LIB) include/cagoule_stream.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_error_paths: tests/test_error_paths.c $(LIB) include/cagoule_api.h include/cagoule_ctr.h include/cagoule_cipher.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_math_avx2: tests/test_math_avx2.c $(LIB) include/cagoule_math.h include/cagoule_math_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_matrix_avx2: tests/test_matrix_avx2.c $(LIB) include/cagoule_math.h include/cagoule_matrix.h include/cagoule_math_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_sbox_avx2: tests/test_sbox_avx2.c $(LIB) \
                include/cagoule_math.h include/cagoule_sbox.h \
                include/cagoule_math_avx2.h include/cagoule_sbox_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_cipher_pipeline4: tests/test_cipher_pipeline4.c $(LIB) \
                       include/cagoule_cipher.h include/cagoule_math_avx2.h \
                       include/cagoule_sbox_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_ctr: tests/test_ctr.c $(LIB) include/cagoule_ctr.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_api_raw: tests/test_api_raw.c $(LIB) include/cagoule_api.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_format: tests/test_format.c $(LIB) include/cagoule_cipher.h include/cagoule_ctr.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_constant_time: tests/test_constant_time.c $(LIB) include/cagoule_math.h include/cagoule_math_avx2.h
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS) -lm

# ── Constant-time test ───────────────────────────────────────────────────
test-ct: $(LIB) test_constant_time
	@echo "══════════════════════════════════════════════════════"
	@echo "  dudect — constant-time validation"
	@echo "══════════════════════════════════════════════════════"
	./test_constant_time
	@echo "✓ Constant-time tests OK"

# ── Profiling (PROFILE_CTR) ────────────────────────────────────────────
# CORRECTIF (audit round 2, N5) : cagoule_ctr_print_profile() et le
# compteur _prof (cagoule_ctr.c) n'existent que sous -DPROFILE_CTR.
# Basculer ce flag SANS `make clean` entre deux builds laisse des .o
# incohérents (certains compilés avec PROFILE_CTR, d'autres sans) liés
# ensemble dans le même .so -- observé 3 fois pendant l'audit round 2,
# dont un crash "Illegal instruction" dans du code sans rapport avec
# PROFILE_CTR (cagoule_cipher.c), simplement parce que l'objet lié était
# périmé. `make profile` force `make clean` avant ET après, pour qu'un
# appel isolé ne laisse jamais l'arbre dans un état mixte -- l'appelant
# n'a pas besoin de se souvenir de nettoyer après coup.
profile:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Build profiling (PROFILE_CTR) — isolé, clean avant/après"
	@echo "══════════════════════════════════════════════════════"
	$(MAKE) clean
	$(MAKE) libcagoule.so CFLAGS="$(CFLAGS) -DPROFILE_CTR"
	$(MAKE) test_ctr CFLAGS="$(CFLAGS) -DPROFILE_CTR"
	./test_ctr
	@echo ""
	@echo "── Nettoyage post-profiling : retour au build standard ──"
	$(MAKE) clean
	$(MAKE) libcagoule.so
	@echo "✓ profile terminé — arbre reconstruit avec les flags standard (pas de PROFILE_CTR)"

# ── Benchmarks ───────────────────────────────────────────────────────────
bench: $(LIB) test_math test_matrix test_sbox test_omega test_ctr \
             test_matrix_avx2 test_sbox_avx2
	@echo "══════════════════════════════════════════════════════"
	@echo "  Benchmarks CAGOULE v3.1.0 (scalaires + AVX2 + CTR)"
	@echo "══════════════════════════════════════════════════════"
	@./test_math && ./test_matrix && ./test_sbox && ./test_omega && ./test_ctr
	@./test_matrix_avx2 && ./test_sbox_avx2

# ── Debug (ASan + UBSan) ─────────────────────────────────────────────────
debug: CFLAGS  += -g -fsanitize=address,undefined -DDEBUG -O0
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(LIB) tests
	@echo "✓ Build debug avec sanitizers"

# ── Valgrind ─────────────────────────────────────────────────────────────
valgrind: $(LIB) test_math test_matrix test_sbox test_cipher test_omega \
               test_ctr test_matrix_avx2 test_sbox_avx2
	@echo "══════════════════════════════════════════════════════"
	@echo "  Valgrind — vérification des fuites mémoire"
	@echo "══════════════════════════════════════════════════════"
	@for t in test_math test_matrix test_sbox test_cipher test_omega \
	           test_ctr test_matrix_avx2 test_sbox_avx2; do \
	    echo "  → $$t"; \
	    RUNNING_ON_VALGRIND=1 valgrind --leak-check=full --error-exitcode=1 \
	        ./$$t > /tmp/valgrind_$$t.log 2>&1 \
	    && echo "    ✓ $$t : pas de fuite" \
	    || { echo "    ✗ $$t : fuite détectée (voir /tmp/valgrind_$$t.log)"; exit 1; }; \
	done
	@echo "✅ Aucune fuite mémoire détectée"

# ── Build de production ────────────────────────────────────────────────
# LTO (-flto) + NDEBUG (désactive les assert() de precondition ajoutés en
# P2-6 -- voir la note ci-dessous) + strip des symboles. Ne change AUCUN
# comportement du chiffreur : NDEBUG retire uniquement des assert()
# internes sur des invariants déjà garantis par tous les appelants actuels
# (v[] octet-range en CTR) -- ce ne sont pas des vérifications de sécurité
# sur des entrées attaquant-contrôlées (ça reste le rôle du tag MAC,
# vérifié indépendamment de NDEBUG, avant tout accès mémoire).
release: clean
	@echo "══════════════════════════════════════════════════════"
	@echo "  Release build : LTO + NDEBUG + strip"
	@echo "══════════════════════════════════════════════════════"
	@command -v strip >/dev/null 2>&1 || { echo "✗ 'strip' introuvable -- installer binutils"; exit 1; }
	$(MAKE) $(LIB) EXTRA_CFLAGS="-flto -DNDEBUG" EXTRA_LDFLAGS="-flto"
	strip --strip-unneeded $(LIB)
	@echo "✓ $(LIB) : LTO + NDEBUG + stripped"
	@ls -la $(LIB)
	@echo ""
	@echo "  NOTE : NDEBUG désactive les assert() de precondition interne"
	@echo "  (_matmul16_scalar_lazy, cagoule_matrix_mul_avx2_lazy -- P2-6)."
	@echo "  Ce sont des invariants internes déjà garantis par tous les"
	@echo "  appelants actuels, pas une vérification de sécurité sur des"
	@echo "  entrées attaquant-contrôlées. Build release == build"
	@echo "  production normal, pas un mode dégradé de sécurité."

# ── Benchmark reproductible ──────────────────────────────────────────────
# Répond directement au problème de variance rencontré pendant l'audit
# perf (mêmes builds mesurés entre 20 et 55 MB/s selon le run, sur VM
# partagée sans pinning) : plusieurs invocations *séparées* du binaire
# (pas juste les 5 reps internes de test_ctr) + warmup jetable +
# mean/min/max explicites, plutôt qu'un seul chiffre pris pour argent
# comptant. Voir SECURITY.md §6.1 pour la méthodologie complète et ses
# limites dans un environnement virtualisé sans contrôle du gouverneur CPU.
BENCH_RUNS   ?= 7
BENCH_WARMUP ?= 2

benchmark: $(LIB) test_ctr
	@echo "══════════════════════════════════════════════════════"
	@echo "  Benchmark CTR reproductible ($(BENCH_WARMUP) warmup + $(BENCH_RUNS) mesurés)"
	@echo "══════════════════════════════════════════════════════"
	@if command -v taskset >/dev/null 2>&1; then \
		echo "  taskset disponible -- épinglage sur le coeur 0"; \
		RUNNER="taskset -c 0"; \
	else \
		echo "  ⚠ taskset indisponible -- PAS d'épinglage CPU, variance possible"; \
		RUNNER=""; \
	fi; \
	echo "  ⚠ Gouverneur CPU non modifiable depuis ce Makefile (nécessite"; \
	echo "    accès root + matériel hôte, indisponible en conteneur/VM)."; \
	echo ""; \
	echo "  Warmup ($(BENCH_WARMUP) runs, non comptés) :"; \
	for i in $$(seq 1 $(BENCH_WARMUP)); do \
		$$RUNNER ./test_ctr > /dev/null 2>&1; \
		echo "    warmup $$i/$(BENCH_WARMUP) terminé"; \
	done; \
	echo ""; \
	echo "  Mesures ($(BENCH_RUNS) runs) :"; \
	RESULTS=/tmp/cagoule_bench_$$$$.txt; \
	rm -f $$RESULTS; \
	for i in $$(seq 1 $(BENCH_RUNS)); do \
		VAL=$$($$RUNNER ./test_ctr 2>&1 | grep "CTR 1MB" | grep -oE '[0-9]+\.[0-9]+ MB/s' | grep -oE '^[0-9]+\.[0-9]+'); \
		echo "    run $$i/$(BENCH_RUNS) : $$VAL MB/s"; \
		echo "$$VAL" >> $$RESULTS; \
	done; \
	echo ""; \
	awk '{ if(NR==1||$$1<min) min=$$1; if(NR==1||$$1>max) max=$$1; sum+=$$1; n++ } \
	     END { printf "  mean = %.2f MB/s\n  min  = %.2f MB/s\n  max  = %.2f MB/s\n  n    = %d runs\n", sum/n, min, max, n }' $$RESULTS; \
	rm -f $$RESULTS
	@echo "══════════════════════════════════════════════════════"
	@echo "  ⚠ Voir SECURITY.md §6.1 : ces chiffres dépendent fortement"
	@echo "    du matériel/environnement (pinning CPU, gouverneur,"
	@echo "    virtualisation). Ne pas citer un seul run comme référence --"
	@echo "    citer la plage mean/min/max ci-dessus avec sa méthodologie."
	@echo "══════════════════════════════════════════════════════"

# ── Distribution ──────────────────────────────────────────────────────────
# Extrait la version depuis ../__version__.py plutôt que de la coder en
# dur ici -- évite qu'un nom de tarball devienne silencieusement obsolète
# après une release (exactement la classe de problème rencontrée à
# plusieurs reprises dans cet audit : un nombre ou une chaîne dupliquée
# à la main dans deux fichiers finit par diverger).
DIST_VERSION := $(shell grep -oE '"[^"]+"' ../__version__.py | head -1 | tr -d '"')
DIST_NAME    := cagoule-v$(DIST_VERSION)
DIST_DIR     := ../../dist

dist:
	@echo "══════════════════════════════════════════════════════"
	@echo "  Distribution : $(DIST_NAME).tar.gz"
	@echo "══════════════════════════════════════════════════════"
	$(MAKE) clean
	$(MAKE) release
	$(MAKE) tests
	@echo ""
	@echo "  Suppression des binaires de test avant archivage (le .so"
	@echo "  release construit ci-dessus, lui, doit rester dans l'archive"
	@echo "  -- 'make clean' les supprimerait tous les deux, donc on"
	@echo "  retire seulement les binaires de test, explicitement, par"
	@echo "  nom -- même liste que la cible 'clean', pas un motif glob"
	@echo "  qui pourrait accidentellement exclure du code source)."
	rm -f test_math test_matrix test_sbox test_cipher test_omega
	rm -f test_ctr test_format test_constant_time test_api_raw
	rm -f test_math_avx2 test_matrix_avx2 test_sbox_avx2 test_cipher_pipeline4 test_mersenne
	rm -f test_params_kat test_stream test_error_paths
	@mkdir -p $(DIST_DIR)
	@rm -f $(DIST_DIR)/$(DIST_NAME).tar.gz
	tar -czf $(DIST_DIR)/$(DIST_NAME).tar.gz \
		-C ../.. \
		--exclude='*.o' --exclude='*.d' --exclude='__pycache__' \
		--exclude='.git' --exclude='dist' --exclude='*.gcda' --exclude='*.gcno' \
		--transform 's,^,$(DIST_NAME)/,' \
		cagoule tests docs CHANGELOG.md SECURITY.md ARCHITECTURE.md README.md LICENSE pyproject.toml
	@echo ""
	@echo "✓ $(DIST_DIR)/$(DIST_NAME).tar.gz créé"
	@ls -la $(DIST_DIR)/$(DIST_NAME).tar.gz
	@echo ""
	@echo "  NOTE : cette archive contient un libcagoule.so déjà compilé"
	@echo "  (build release : LTO + NDEBUG + strip) pour la plateforme de"
	@echo "  build actuelle -- pas un binaire portable multi-plateforme."
	@echo "  Un destinataire sur une autre architecture/OS doit reconstruire"
	@echo "  via 'cd cagoule/c && make release'."

# ── Installation ─────────────────────────────────────────────────────────
# CORRECTIF (testé, pas seulement écrit) : $(DESTDIR)../$(LIB) concatène
# littéralement en chaîne -- avec DESTDIR=/tmp/stage/, ça devient
# "/tmp/stage/../libcagoule.so", qui résout comme CHEMIN à
# "/tmp/libcagoule.so" -- le ".." annule un niveau de DESTDIR et le
# fichier s'échappe complètement du répertoire de staging. Trouvé en
# testant réellement `make install DESTDIR=/tmp/stage/`, pas en
# supposant que la substitution de variable suffisait. Corrigé : deux
# cibles distinctes selon que DESTDIR est défini, plutôt qu'une
# concaténation naïve qui ne marche que dans le cas non-DESTDIR.
ifdef DESTDIR
INSTALL_TARGET := $(DESTDIR)/$(LIB)
else
INSTALL_TARGET := ../$(LIB)
endif

install: $(LIB)
	@echo "══════════════════════════════════════════════════════"
	@echo "  Installation : $(LIB) → $(INSTALL_TARGET)"
	@echo "══════════════════════════════════════════════════════"
	@mkdir -p $(dir $(INSTALL_TARGET))
	rm -f $(INSTALL_TARGET)
	cp $(LIB) $(INSTALL_TARGET)
	chmod 755 $(INSTALL_TARGET)
	@echo "✓ $(LIB) → $(INSTALL_TARGET) (mode 755)"
ifdef DESTDIR
	@echo ""
	@echo "  DESTDIR défini -- copie de staging, PAS un import Python"
	@echo "  fonctionnel depuis cet emplacement (un paquet système"
	@echo "  copiera ce fichier vers son emplacement final ensuite)."
	@echo "  Vérification d'import sautée intentionnellement."
else
	@echo ""
	@echo "  Vérification : import cagoule depuis Python..."
	@cd ../.. && python3 -c "import cagoule; from cagoule._binding import CAGOULE_C_AVAILABLE; \
	    print('  ✓ import cagoule OK, backend C disponible :', CAGOULE_C_AVAILABLE); \
	    exit(0 if CAGOULE_C_AVAILABLE else 1)" \
	    || (echo "  ✗ import cagoule a échoué OU le backend C n'a pas été détecté" && exit 1)
endif

# ── Vérifications ────────────────────────────────────────────────────────
check-openssl:
	@echo -n "OpenSSL disponible : "
	@pkg-config --exists openssl && echo "✓ ($(shell pkg-config --modversion openssl))" || echo "✗ (installer libssl-dev)"

sysinfo:
	@echo "Compilateur     : $(CC) ($(shell $(CC) --version | head -1))"
	@echo "CFLAGS          : $(CFLAGS)"
	@echo "LDFLAGS         : $(LDFLAGS)"
	@echo "__uint128_t     : $(HAS_UINT128)"
	@echo "AVX2            : $(HAS_AVX2)"
	@echo "OpenSSL (pkg)   : $(HAS_OPENSSL)"
	@echo "Architecture    : $(shell uname -m)"

# ── Nettoyage ────────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
	rm -f test_math test_matrix test_sbox test_cipher test_omega 
	rm -f test_ctr test_format test_constant_time test_api_raw
	rm -f test_math_avx2 test_matrix_avx2 test_sbox_avx2 test_cipher_pipeline4 test_mersenne
	rm -f test_params_kat test_stream test_error_paths
	rm -f *.gcda *.gcno *.gcov
	rm -f /tmp/_chk_ossl /tmp/valgrind_*.log
	rm -f fuzz_cipher crash-* fuzz_cipher.log
	@echo "✓ clean terminé"

# ── Fuzz targets ─────────────────────────────────────────────────────────
# Requires clang with libFuzzer (-fsanitize=fuzzer)
fuzz_cipher: fuzz/fuzz_cipher.c $(LIB)
	clang -O1 -g -fsanitize=fuzzer,address,undefined \
	      -Iinclude $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

fuzz: fuzz_cipher
	@echo "══════════════════════════════════════════════════════"
	@echo "  libFuzzer — 1M runs (CBC + CTR)"
	@echo "══════════════════════════════════════════════════════"
	./fuzz_cipher -max_len=65536 -runs=1000000
	@echo "✓ Fuzzer 1M runs : 0 crashes"

fuzz-long: fuzz_cipher
	@echo "Starting fuzzer (10M iterations, may take hours)..."
	./fuzz_cipher -max_len=65536 -runs=10000000

# ── Aide ─────────────────────────────────────────────────────────────────
help:
	@echo "══════════════════════════════════════════════════════"
	@echo "  CAGOULE v3.1.0 — Cibles disponibles"
	@echo "══════════════════════════════════════════════════════"
	@echo "  make              → compile libcagoule.so"
	@echo "  make tests        → tous les tests C (16 binaires)"
	@echo "  make test-avx2    → tests AVX2 (Mersenne + matrice + S-box)"
	@echo "  make test-scalar  → force fallback scalaire"
	@echo "  make test-ctr     → tests CTR + format + api_raw (v3.1.0)"
	@echo "  make test-ct      → test constant-time (dudect)"
	@echo "  make profile      → build profiling isolé (PROFILE_CTR), clean avant/après"
	@echo "  make bench        → benchmarks de performance (inclut CTR)"
	@echo "  make debug        → build avec ASan + UBSan"
	@echo "  make valgrind     → vérification fuites mémoire (inclut CTR)"
	@echo "  make fuzz         → libFuzzer 1M runs (CBC + CTR)"
	@echo "  make fuzz-long    → libFuzzer 10M runs"
	@echo "  make install      → copie libcagoule.so dans le package Python"
	@echo "  make release      → build production : LTO + NDEBUG + strip"
	@echo "  make benchmark    → CTR, runs répétés + warmup, rapporte mean/min/max"
	@echo "  make dist         → archive de distribution (clean + release + tests)"
	@echo "  make sysinfo      → affiche les infos système"
	@echo "  make check-openssl → vérifie la disponibilité d'OpenSSL"
	@echo "  make clean        → supprime les artefacts"
	@echo "══════════════════════════════════════════════════════"