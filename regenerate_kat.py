#!/usr/bin/env python3
"""
regenerate_kat.py — Régénération des vecteurs KAT — CAGOULE v3.1.0  
Usage :
    python3 regenerate_kat.py           # KAT chiffrement uniquement
    python3 regenerate_kat.py --omega   # + KAT omega
    python3 regenerate_kat.py --all     # tout
    python3 regenerate_kat.py --check   # vérifie sans écraser

Fichiers modifiés :
    cagoule/kat_vectors.json
    tests/kat_omega_vectors.json  (si --omega ou --all)
"""

import argparse
import hashlib
import json
import os
import sys
import warnings

# ── Monkey-patch os.urandom pour forcer un nonce fixe pour les KAT ─────
_original_urandom = os.urandom
_nonce_counter = 0

def _fixed_urandom(size: int) -> bytes:
    """Retourne un nonce fixe pour les KAT (nonce = compteur incrémenté)."""
    global _nonce_counter
    if size == 12:
        if _nonce_counter == 0:
            _nonce_counter += 1
            return bytes.fromhex("000102030405060708090a0b")
        result = (bytes([_nonce_counter >> 24, (_nonce_counter >> 16) & 0xFF,
                         (_nonce_counter >> 8) & 0xFF, _nonce_counter & 0xFF]) * 3)[:12]
        _nonce_counter += 1
        return result
    return _original_urandom(size)

os.urandom = _fixed_urandom

# ============================================================

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

so_path = os.path.join(os.path.dirname(__file__), "cagoule", "libcagoule.so")
if os.path.exists(so_path):
    os.environ["LIBCAGOULE_PATH"] = so_path

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from cagoule.params import CagouleParams
    from cagoule.cipher import encrypt as encrypt_cbc, encrypt_with_params
    from cagoule._binding import CAGOULE_C_AVAILABLE
    from cagoule.omega import generate_round_keys, OMEGA_BACKEND


def banner():
    print("═" * 60)
    print("  regenerate_kat.py — CAGOULE v3.1.0")
    print(f"  Backend chiffrement : {'C (libcagoule.so)' if CAGOULE_C_AVAILABLE else 'Python pur'}")
    print(f"  Backend omega       : {OMEGA_BACKEND}")
    print("═" * 60)


# ── Paramètres de référence ───────────────────────────────────────────
PASSWORD  = "CAGOULE_KAT_2026_MASTER_FIXED"
SALT_HEX  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
NONCE_HEX = "000102030405060708090a0b"
PT_HEX    = "48656c6c6f2c20576f726c6421"

SALT      = bytes.fromhex(SALT_HEX)
NONCE     = bytes.fromhex(NONCE_HEX)
PLAINTEXT = bytes.fromhex(PT_HEX)
PASSWORD_B = PASSWORD.encode()

OMEGA_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
OMEGA_P        = 10441487724840939323
OMEGA_N        = 16
OMEGA_NUM_KEYS = 4


def regenerate_cipher_kat(params: CagouleParams) -> dict:
    """Régénère kat_vectors.json avec nonce fixe et paramètres dérivés."""
    print("\n── KAT chiffrement ──────────────────────────────────────")

    # Vecteur 1 : chiffrement complet
    ct = encrypt_cbc(PLAINTEXT, PASSWORD_B, salt=SALT, params=params)
    print(f"  Plaintext  : {PLAINTEXT.decode()!r}")
    print(f"  CT (hex)   : {ct.hex()[:48]}…")

    # Construire les paramètres dérivés pour le KAT
    mu_int = params.mu.as_int() if not params.mu.in_fp2 else None
    derived = {
        "sbox_type":    "feistel",
        "n_zeta":       params.n,
        "p":            params.p,
        "k_mersenne":   params.k_mersenne,
        "mu_strategy":  params.mu.strategy,
        "mu_hex":       format(mu_int, 'x') if mu_int is not None else "",
        "k_stream_hex": params.k_stream.hex(),
        "round_key_0":  params.round_keys[0],
        "round_key_63": params.round_keys[63],
        "z_offset_0":   params.z_offset[0] if params.z_offset else 0,
    }

    # Vecteurs de test
    vectors = []
    for msg_hex, label in [
        (PT_HEX, "hello_world"),
        ("", "empty"),
        ("ff" * 16, "block_exact"),
        ("42" * 64, "multi_block"),
    ]:
        msg = bytes.fromhex(msg_hex) if msg_hex else b""
        ct_v = encrypt_cbc(msg, PASSWORD_B, salt=SALT, params=params)
        vectors.append({
            "label":      label,
            "plaintext":  msg_hex,
            "ciphertext": ct_v.hex(),
            "sha256":     hashlib.sha256(ct_v).hexdigest(),
        })
        print(f"  [{label:12s}] SHA256: {hashlib.sha256(ct_v).hexdigest()[:16]}…")

    return {
        "version":      "3.1.0",
        "backend":      "C" if CAGOULE_C_AVAILABLE else "Python",
        "password":     PASSWORD,
        "salt":         SALT_HEX,
        "nonce":        NONCE_HEX,
        "derived":      derived,
        "vectors":      vectors,
    }


def regenerate_omega_kat() -> dict:
    """Régénère les vecteurs KAT pour test_omega.py."""
    print("\n── KAT omega (ζ(2n) → round keys) ──────────────────────")

    omega_salt = bytes.fromhex(OMEGA_SALT_HEX)
    keys = generate_round_keys(OMEGA_N, omega_salt, OMEGA_P, num_keys=OMEGA_NUM_KEYS)

    for i, k in enumerate(keys):
        print(f"  round_key[{i}] = {k}")

    assert all(0 <= k < OMEGA_P for k in keys), "Clés hors de [0, p) — ERREUR"
    print(f"  ✓ {OMEGA_NUM_KEYS} clés dans [0, p={OMEGA_P})")

    return {
        "version":    "3.1.0",
        "backend":    OMEGA_BACKEND,
        "n":          OMEGA_N,
        "salt":       OMEGA_SALT_HEX,
        "p":          OMEGA_P,
        "num_keys":   OMEGA_NUM_KEYS,
        "round_keys": [str(k) for k in keys],
        "sha256":     hashlib.sha256(
            "".join(str(k) for k in keys).encode()
        ).hexdigest(),
    }


def main():
    global _nonce_counter
    parser = argparse.ArgumentParser(description="Régénération KAT CAGOULE v3.1.0")
    parser.add_argument("--omega", action="store_true",
                        help="Régénère aussi les vecteurs KAT omega")
    parser.add_argument("--all", action="store_true",
                        help="Régénère tous les vecteurs (chiffrement + omega)")
    parser.add_argument("--check", action="store_true",
                        help="Vérifie les vecteurs existants sans écraser")
    parser.add_argument("--update-tests", action="store_true",
                        help="Met à jour le SHA-256 attendu dans test_kat.py")
    args = parser.parse_args()

    banner()

    if not CAGOULE_C_AVAILABLE:
        print("⚠  Backend C non disponible — vecteurs générés avec Python pur.")
        resp = input("Continuer quand même ? (y/N) : ")
        if resp.lower() != 'y':
            sys.exit(1)

    _nonce_counter = 0

    print(f"\nDérivation des paramètres de référence (fast_mode=True)…")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        params = CagouleParams.derive(PASSWORD_B, salt=SALT, fast_mode=True)
    print(f"  p = {params.p}")
    print(f"  n = {params.n}")
    print(f"  µ = {params.mu}")
    print(f"  k_stream = {params.k_stream.hex()[:16]}…")
    print(f"  rk[0] = {params.round_keys[0]}")
    print(f"  rk[63] = {params.round_keys[63]}")
    print(f"  k_mersenne = {params.k_mersenne}  (p=2^64-{params.k_mersenne})")
    print(f"  z_offset[0] = {params.z_offset[0] if params.z_offset else 'N/A'}")

    do_cipher = True
    do_omega  = args.omega or args.all

    if do_cipher:
        kat_data = regenerate_cipher_kat(params)
        kat_path = os.path.join(os.path.dirname(__file__), "cagoule", "kat_vectors.json")
        if not args.check:
            with open(kat_path, 'w', encoding='utf-8') as f:
                json.dump(kat_data, f, indent=2, ensure_ascii=False)
            print(f"\n  ✓ kat_vectors.json écrit → {kat_path}")
        else:
            with open(kat_path) as f:
                existing = json.load(f)
            if existing.get("vectors") == kat_data.get("vectors"):
                print("\n  ✓ Vecteurs existants valides")
            else:
                print("\n  ✗ Vecteurs obsolètes — relancer sans --check")
                sys.exit(1)

    if do_omega:
        omega_data = regenerate_omega_kat()
        omega_path = os.path.join(os.path.dirname(__file__), "tests", "kat_omega_vectors.json")
        if not args.check:
            os.makedirs(os.path.dirname(omega_path), exist_ok=True)
            with open(omega_path, 'w', encoding='utf-8') as f:
                json.dump(omega_data, f, indent=2, ensure_ascii=False)
            print(f"\n  ✓ kat_omega_vectors.json écrit → {omega_path}")
        else:
            with open(omega_path) as f:
                existing = json.load(f)
            if existing.get("round_keys") == omega_data.get("round_keys"):
                print("\n  ✓ Vecteurs omega existants valides")
            else:
                print("\n  ✗ Vecteurs omega obsolètes — relancer sans --check")
                sys.exit(1)

    # Auto-update expected SHA-256 in test_kat.py if requested
    if args.update_tests and do_cipher:
        new_sha = kat_data["vectors"][0]["sha256"]
        kat_test_path = os.path.join(os.path.dirname(__file__), "tests", "test_kat.py")
        if os.path.exists(kat_test_path):
            with open(kat_test_path, 'r') as f:
                test_content = f.read()
            import re
            test_content = re.sub(
                r'expected_sha = "[a-f0-9]{64}"',
                f'expected_sha = "{new_sha}"',
                test_content
            )
            with open(kat_test_path, 'w') as f:
                f.write(test_content)
            print(f"\n  ✓ test_kat.py SHA-256 mis à jour → {new_sha}")

    params.zeroize()
    os.urandom = _original_urandom
    
    print("\n✅ Régénération terminée.\n")


if __name__ == "__main__":
    try:
        main()
    finally:
        os.urandom = _original_urandom