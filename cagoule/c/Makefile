# Makefile — CAGOULE v2.1.0 libcagoule.so
#
# Cibles principales :
#   make            → compile libcagoule.so
#   make tests      → exécute tous les tests (256 tests)
#   make valgrind   → vérifie les fuites mémoire
#   make debug      → compile avec ASan + UBSan
#   make install    → copie dans le package Python
#   make clean      → nettoie

CC       = gcc
CFLAGS   = -O2 -std=c99 -Wall -Wextra -fPIC -Iinclude
CFLAGS  += -D_POSIX_C_SOURCE=200809L
LDFLAGS  = -shared
LDLIBS   = -lm -lcrypto

PYTHON  ?= python3

ifeq ($(shell uname -m),x86_64)
    CFLAGS += -march=native
endif

# Détection __uint128_t
HAS_UINT128 := $(shell echo 'int main() { __uint128_t x = 0; return 0; }' | \
               $(CC) -x c -o /dev/null - 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_UINT128),no)
    $(error Ce compilateur ne supporte pas __uint128_t. Besoin de GCC >= 4.6 ou Clang >= 3.1)
endif

# Détection OpenSSL
HAS_OPENSSL := $(shell pkg-config --exists openssl 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_OPENSSL),yes)
    CFLAGS  += $(shell pkg-config --cflags openssl)
    LDLIBS  += $(shell pkg-config --libs-only-l openssl)
else
    $(warning OpenSSL non trouvé via pkg-config, utilisation de -lcrypto direct)
endif

# Sources
SRCS     = src/cagoule_matrix.c \
           src/cagoule_sbox.c   \
           src/cagoule_cipher.c \
           src/cagoule_omega.c
OBJS     = $(SRCS:.c=.o)
DEPS     = $(SRCS:.c=.d)
LIB      = libcagoule.so

# Cibles
.PHONY: all tests bench clean install check-openssl debug valgrind coverage help

all: $(LIB)

$(LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "✓ $(LIB) compilé (CAGOULE v2.1.0)"

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(DEPS)

# ── Tests ──────────────────────────────────────────────────────────────
tests: $(LIB) test_math test_matrix test_sbox test_cipher test_omega
	@echo ""
	@echo "══════════════════════════════════════════════════════"
	@echo "  Exécution des tests CAGOULE v2.1.0"
	@echo "══════════════════════════════════════════════════════"
	@status=0; \
	./test_math   && echo "✓ test_math   OK" || { echo "✗ test_math   FAIL"; status=1; }; \
	./test_matrix && echo "✓ test_matrix OK" || { echo "✗ test_matrix FAIL"; status=1; }; \
	./test_sbox   && echo "✓ test_sbox   OK" || { echo "✗ test_sbox   FAIL"; status=1; }; \
	./test_cipher && echo "✓ test_cipher OK" || { echo "✗ test_cipher FAIL"; status=1; }; \
	./test_omega  && echo "✓ test_omega  OK" || { echo "✗ test_omega  FAIL"; status=1; }; \
	echo "══════════════════════════════════════════════════════"; \
	[ $$status -eq 0 ] && echo "  ✅ Tous les tests passent (256 tests)" || echo "  ❌ Certains tests ont échoué"; \
	echo "══════════════════════════════════════════════════════"; \
	exit $$status

# Compilation des exécutables de test
test_math: tests/test_math.c include/cagoule_math.h
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

test_matrix: tests/test_matrix.c $(LIB) include/cagoule_math.h include/cagoule_matrix.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_sbox: tests/test_sbox.c $(LIB) include/cagoule_math.h include/cagoule_sbox.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_cipher: tests/test_cipher.c $(LIB) include/cagoule_cipher.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

test_omega: tests/test_omega.c $(LIB) include/cagoule_omega.h include/cagoule_math.h
	$(CC) $(CFLAGS) $< -L. -lcagoule -Wl,-rpath,. -o $@ $(LDLIBS)

# ── Benchmarks ─────────────────────────────────────────────────────────
bench: $(LIB) test_math test_matrix test_sbox test_omega
	@echo "══════════════════════════════════════════════════════"
	@echo "  Benchmarks CAGOULE v2.1.0"
	@echo "══════════════════════════════════════════════════════"
	@./test_math && ./test_matrix && ./test_sbox && ./test_omega

# ── Debug (ASan + UBSan) ───────────────────────────────────────────────
debug: CFLAGS  += -g -fsanitize=address,undefined -DDEBUG -O0
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean $(LIB) tests
	@echo "✓ Build debug avec sanitizers"

# ── Valgrind ───────────────────────────────────────────────────────────
valgrind: $(LIB) test_math test_matrix test_sbox test_cipher test_omega
	@echo "══════════════════════════════════════════════════════"
	@echo "  Valgrind — vérification des fuites mémoire"
	@echo "══════════════════════════════════════════════════════"
	@for t in test_math test_matrix test_sbox test_cipher test_omega; do \
	    echo "  → $$t"; \
	    valgrind --leak-check=full --error-exitcode=1 ./$$t > /tmp/valgrind_$$t.log 2>&1 \
	    && echo "    ✓ $$t : pas de fuite" \
	    || { echo "    ✗ $$t : fuite détectée (voir /tmp/valgrind_$$t.log)"; exit 1; }; \
	done
	@echo "✅ Aucune fuite mémoire détectée"

# ── Installation ────────────────────────────────────────────────────────
install: $(LIB)
	@mkdir -p ../cagoule
	cp $(LIB) ../cagoule/$(LIB)
	@echo "✓ $(LIB) → ../cagoule/$(LIB)"
	@echo "  Pensez à : $(PYTHON) regenerate_kat.py --omega"

# ── Vérifications ───────────────────────────────────────────────────────
check-openssl:
	@echo -n "OpenSSL disponible : "
	@pkg-config --exists openssl && echo "✓ ($(shell pkg-config --modversion openssl))" || echo "✗ (installer libssl-dev)"

sysinfo:
	@echo "Compilateur     : $(CC) ($(shell $(CC) --version | head -1))"
	@echo "CFLAGS          : $(CFLAGS)"
	@echo "LDFLAGS         : $(LDFLAGS)"
	@echo "__uint128_t     : $(HAS_UINT128)"
	@echo "OpenSSL (pkg)   : $(HAS_OPENSSL)"
	@echo "Architecture    : $(shell uname -m)"

# ── Nettoyage ───────────────────────────────────────────────────────────
clean:
	rm -f $(OBJS) $(DEPS) $(LIB)
	rm -f test_math test_matrix test_sbox test_cipher test_omega
	rm -f *.gcda *.gcno *.gcov
	rm -f /tmp/_chk_ossl /tmp/valgrind_*.log
	@echo "✓ clean terminé"

# ── Aide ────────────────────────────────────────────────────────────────
help:
	@echo "══════════════════════════════════════════════════════"
	@echo "  CAGOULE v2.1.0 — Cibles disponibles"
	@echo "══════════════════════════════════════════════════════"
	@echo "  make              → compile libcagoule.so"
	@echo "  make tests        → exécute tous les tests (256 tests)"
	@echo "  make bench        → benchmarks de performance"
	@echo "  make debug        → build avec ASan + UBSan"
	@echo "  make valgrind     → vérification fuites mémoire"
	@echo "  make install      → copie libcagoule.so dans le package Python"
	@echo "  make sysinfo      → affiche les infos système"
	@echo "  make check-openssl → vérifie la disponibilité d'OpenSSL"
	@echo "  make clean        → supprime les artefacts"
	@echo "══════════════════════════════════════════════════════"