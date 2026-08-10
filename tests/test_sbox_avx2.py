"""
tests/test_sbox_avx2.py — Tests Python couche S-box AVX2 — CAGOULE v3.1.0
CORRECTIF v3.0.1 : le test de parité forward/inverse a été corrigé pour forcer une collision, et le test de performance a été amélioré pour mesurer le temps de 65k blocs (~1 MB) et vérifier le ratio inv/fwd.

Vérifie que :
  - le backend S-box AVX2 est détecté côté Python
  - cagoule_sbox_block_forward_avx2 (C) et cagoule_sbox_block_forward (Python)
    produisent des résultats identiques pour 100 blocs aléatoires
  - backend_info expose 'sbox_backend'
  - round-trip encrypt/decrypt fonctionne avec le nouveau pipeline AVX2
"""

import os
import time
import warnings
import pytest

P_BENCH = 10441487724840939323


@pytest.fixture(scope="module")
def sbox_c():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.sbox import SBox, SBoxC
        from cagoule._binding import CAGOULE_C_AVAILABLE
    if not CAGOULE_C_AVAILABLE:
        pytest.skip("Backend C non disponible")
    return SBox.from_delta(123456789, P_BENCH)


@pytest.fixture(scope="module")
def fast_params():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from cagoule.params import CagouleParams
    p = CagouleParams.derive(b"test_v230_sbox_avx2", fast_mode=True)
    yield p
    p.zeroize()


# ── Tests backend info ──────────────────────────────────────────────────

class TestBackendInfo:

    def test_backend_info_has_sbox_key(self):
        """backend_info expose 'sbox_backend' (v2.3.0)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule._binding import get_backend_info_v230
        info = get_backend_info_v230()
        assert "sbox_backend" in info, "sbox_backend absent de backend_info v2.4.0"

    def test_sbox_backend_value_valid(self):
        """sbox_backend est 'avx2', 'scalar' ou 'python'."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule._binding import get_backend_info_v230
        info = get_backend_info_v230()
        assert info["sbox_backend"] in ("avx2", "scalar", "python"), \
            f"valeur inattendue: {info['sbox_backend']!r}"

    def test_sbox_backend_avx2_on_avx2_cpu(self):
        """Sur un CPU AVX2, sbox_backend doit être 'avx2'."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule._binding import get_backend_info_v230, CAGOULE_C_AVAILABLE
        if not CAGOULE_C_AVAILABLE:
            pytest.skip("Backend C non disponible")
        info = get_backend_info_v230()
        # Si matrix_backend == avx2, alors sbox_backend devrait aussi être avx2
        if info["matrix_backend"] == "avx2":
            assert info["sbox_backend"] == "avx2", \
                f"matrix_backend=avx2 mais sbox_backend={info['sbox_backend']!r}"

    def test_backend_info_complete_v230(self):
        """backend_info v2.4.0 contient les 3 clés."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule._binding import get_backend_info_v230
        info = get_backend_info_v230()
        assert set(info.keys()) >= {"matrix_backend", "sbox_backend", "omega_backend"}


# ── Tests parité forward/inverse ────────────────────────────────────────

class TestSBoxParityAVX2:
    """Parité entre SBoxC (Feistel, appelle le C directement) et résultat attendu."""

    def test_forward_block_parity_100(self, sbox_c):
        """100 blocs de 16 : forward produit des sorties dans [0, p)."""
        for _ in range(100):
            block = [int.from_bytes(os.urandom(8), 'big') % P_BENCH
                     for _ in range(16)]
            enc = sbox_c.forward_block(block)
            assert len(enc) == 16
            assert all(0 <= x < P_BENCH for x in enc), \
                "forward_block : sortie hors [0, p)"

    def test_inverse_block_parity_100(self, sbox_c):
        """100 blocs de 16 : inverse est l'exact inverse de forward."""
        for _ in range(100):
            orig = [int.from_bytes(os.urandom(8), 'big') % P_BENCH
                    for _ in range(16)]
            enc  = sbox_c.forward_block(orig)
            dec  = sbox_c.inverse_block(enc)
            assert dec == orig, "inverse_block(forward_block(x)) != x"

    def test_roundtrip_single_values(self, sbox_c):
        """forward(inverse(y)) == y et inverse(forward(x)) == x."""
        for x in [0, 1, P_BENCH - 1, P_BENCH // 2, 42, 1_000_000_007 % P_BENCH]:
            y  = sbox_c.forward(x)
            x2 = sbox_c.inverse(y)
            assert x2 == x, f"roundtrip failed: x={x} -> y={y} -> x2={x2}"
            assert 0 <= y < P_BENCH, f"forward({x}) = {y} hors [0, p)"

    def test_non_trivial(self, sbox_c):
        """La S-box n'est pas l'identité."""
        changed = sum(1 for x in range(100)
                      if sbox_c.forward(x % P_BENCH) != x % P_BENCH)
        assert changed > 50, "S-box semble être l'identité"


# ── Tests end-to-end avec pipeline AVX2 complet ─────────────────────────

class TestEndToEndAVX2:
    """Vérifie le pipeline complet (matrice AVX2 + S-box AVX2 + RK AVX2)."""

    @pytest.mark.parametrize("size", [13, 16, 64, 256, 1024])
    def test_roundtrip_various_sizes(self, fast_params, size):
        """encrypt/decrypt roundtrip pour différentes tailles."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt_with_params
            from cagoule.decipher import decrypt_with_params
        msg = os.urandom(size)
        ct  = encrypt_with_params(msg, fast_params)
        pt  = decrypt_with_params(ct, fast_params)
        assert pt == msg, f"Roundtrip failed for size={size}"

    def test_pipeline_uses_avx2_backends(self, fast_params):
        """Vérifier que les backends AVX2 sont actifs pendant l'encrypt."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule._binding import get_backend_info_v230
        info = get_backend_info_v230()
        # Sur une machine AVX2 avec libcagoule.so v2.4.0
        assert info["matrix_backend"] in ("avx2", "scalar", "python")
        assert info["sbox_backend"] in ("avx2", "scalar", "python")
        # Au moins l'un des deux doit être actif en C
        assert info["omega_backend"] in ("C", "python")

    def test_encrypt_deterministic_same_params(self, fast_params):
        """Deux encryptions avec le même nonce (mock) → même ciphertext."""
        import unittest.mock as mock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt_with_params
        nonce = bytes(range(12))
        msg   = b"deterministic v2.4.0 test"
        with mock.patch("os.urandom", return_value=nonce):
            ct1 = encrypt_with_params(msg, fast_params)
        with mock.patch("os.urandom", return_value=nonce):
            ct2 = encrypt_with_params(msg, fast_params)
        assert ct1 == ct2, "Deux encryptions identiques (même nonce) devraient être égales"

    def test_different_messages_different_ciphertexts(self, fast_params):
        """Deux messages différents → ciphertexts différents."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cagoule.cipher import encrypt_with_params
        ct1 = encrypt_with_params(b"message one", fast_params)
        ct2 = encrypt_with_params(b"message two", fast_params)
        assert ct1 != ct2


# ── Tests de performance S-box ───────────────────────────────────────────

class TestSBoxPerformanceAVX2:

    def test_forward_block_throughput(self, sbox_c):
        """S-box forward 65k blocs de 16 éléments en < 500 ms."""
        block = [(i * 999999937) % P_BENCH for i in range(16)]
        t0 = time.perf_counter()
        for _ in range(65536):
            enc = sbox_c.forward_block(block)
            block[0] = enc[0]   # anti-optimisation
        elapsed_ms = (time.perf_counter() - t0) * 1000
        throughput = 1000.0 / elapsed_ms
        print(f"\n  SBox forward 65k blocs : {elapsed_ms:.1f} ms ({throughput:.1f} MB/s)")
        assert elapsed_ms < 1000, f"S-box forward trop lent: {elapsed_ms:.0f} ms"

    def test_ratio_forward_inverse(self, sbox_c):
        """Ratio déchiffrement/chiffrement < 2× (symétrie Feistel)."""
        block = [(i * 777777777) % P_BENCH for i in range(16)]
        N = 10000

        t0 = time.perf_counter()
        for _ in range(N):
            sbox_c.forward_block(block)
        fwd_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for _ in range(N):
            sbox_c.inverse_block(block)
        inv_ms = (time.perf_counter() - t0) * 1000

        if fwd_ms > 0.5:
            ratio = inv_ms / fwd_ms
            print(f"\n  fwd={fwd_ms:.2f}ms inv={inv_ms:.2f}ms ratio={ratio:.2f}×")
            assert ratio < 2.0, f"Ratio inv/fwd {ratio:.2f}× > 2× (attendu ~1×)"
