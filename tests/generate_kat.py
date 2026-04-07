#!/usr/bin/env python3
"""
generate_kat.py — Génération des Known Answer Tests (KAT) pour CAGOULE v1.1

Ce script génère kat_vectors.json une fois pour toutes.
RÈGLE ABSOLUE : Une fois généré, ce fichier ne doit PLUS JAMAIS être modifié.

Usage :
    python generate_kat.py              # Génère kat_vectors.json
    python generate_kat.py --verify    # Vérifie que le fichier existant est correct
    python generate_kat.py --force     # Force la régénération (attention !)

Les KAT sont utilisés pour :
  - Valider l'implémentation Python après modifications
  - Valider le portage C (doit produire exactement les mêmes valeurs intermédiaires)
  - Détecter les régressions
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# ------------------------------------------------------------------ #
#  Configuration                                                     #
# ------------------------------------------------------------------ #

# Ajouter le parent au path
_SCRIPT_DIR = Path(__file__).parent
_PROJECT_DIR = _SCRIPT_DIR.parent if _SCRIPT_DIR.name == "tests" else _SCRIPT_DIR
sys.path.insert(0, str(_PROJECT_DIR))

# Fichier de sortie
_KAT_PATH = _PROJECT_DIR / "kat_vectors.json"

# Mode fast pour la génération (Argon2id avec paramètres allégés)
FAST_MODE = True


# ------------------------------------------------------------------ #
#  Imports CAGOULE                                                   #
# ------------------------------------------------------------------ #

from params import CagouleParams
from cipher import encrypt
from decipher import decrypt
from format import parse, MAGIC, VERSION, SALT_SIZE, NONCE_SIZE, TAG_SIZE


# ------------------------------------------------------------------ #
#  Paramètres KAT figés                                              #
# ------------------------------------------------------------------ #

# Ces valeurs sont FIXÉES pour que les KAT soient reproductibles
# Elles ne doivent JAMAIS changer

KAT_PASSWORD = "CAGOULE_KAT_2026_MASTER_FIXED"
KAT_SALT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KAT_NONCE_HEX = "000000000000000000000000"  # 12 octets de zéros
KAT_PLAINTEXT_HEX = "48656c6c6f2c20576f726c642100"  # "Hello, World!" + null byte


# ------------------------------------------------------------------ #
#  Fonctions de génération                                           #
# ------------------------------------------------------------------ #

def _bytes_from_hex(hex_str: str) -> bytes:
    """Convertit une chaîne hex en bytes."""
    return bytes.fromhex(hex_str)


def generate_kat() -> dict[str, Any]:
    """
    Génère l'intégralité des vecteurs KAT.
    
    Returns:
        Dictionnaire complet des KAT prêt à être sérialisé en JSON.
    """
    print("🔐 Génération des Known Answer Tests CAGOULE v1.1")
    print("=" * 60)
    
    # ------------------------------------------------------------------
    # 1. Paramètres d'entrée
    # ------------------------------------------------------------------
    password = KAT_PASSWORD.encode('utf-8')
    salt = _bytes_from_hex(KAT_SALT_HEX)
    nonce = _bytes_from_hex(KAT_NONCE_HEX)
    plaintext = _bytes_from_hex(KAT_PLAINTEXT_HEX)
    
    print(f"\n📥 Paramètres d'entrée :")
    print(f"   Password    : {KAT_PASSWORD}")
    print(f"   Salt        : {salt.hex()}")
    print(f"   Nonce       : {nonce.hex()}")
    print(f"   Plaintext   : {plaintext.hex()} ({len(plaintext)} octets)")
    
    # ------------------------------------------------------------------
    # 2. Dérivation des paramètres
    # ------------------------------------------------------------------
    print(f"\n🔧 Dérivation des paramètres (fast_mode={FAST_MODE})...")
    
    params = CagouleParams.derive(password, salt, fast_mode=FAST_MODE)
    
    # Collecte des valeurs dérivées
    derived = {
        "n_zeta": params.n,
        "p": params.p,
        "p_bytes": params.p_bytes,
        "mu_strategy": "A" if not params.mu.in_fp2 else "C",
        "mu_hex": _mu_to_hex(params),
        "k_stream_hex": params.k_stream.hex(),
        "round_key_0": params.round_keys[0],
        "round_key_63": params.round_keys[63],
    }
    
    print(f"   n_zeta      : {derived['n_zeta']}")
    print(f"   p           : {derived['p']} ({derived['p_bytes']} octets)")
    print(f"   μ strategy  : {derived['mu_strategy']}")
    print(f"   μ value     : {derived['mu_hex'][:32]}...")
    print(f"   K_stream    : {derived['k_stream_hex'][:32]}...")
    print(f"   round_key_0 : {derived['round_key_0']}")
    print(f"   round_key_63: {derived['round_key_63']}")
    
    # ------------------------------------------------------------------
    # 3. Chiffrement avec salt/nonce forcés
    # ------------------------------------------------------------------
    print(f"\n🔒 Chiffrement avec salt/nonce forcés...")
    
    # Créer un ciphertext avec salt/nonce fixes
    # Note: encrypt() normale utilise des valeurs aléatoires
    # Nous devons utiliser l'API interne ou créer un encrypt_with_params
    
    from cipher import _cbc_encrypt, _build_aad
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    
    # Étape 1: T(message) interne
    t_message = _cbc_encrypt(plaintext, params)
    print(f"   T(message)  : {t_message.hex()[:32]}... ({len(t_message)} octets)")
    
    # Étape 2: AEAD avec ChaCha20-Poly1305
    aad = _build_aad(salt)
    cipher = ChaCha20Poly1305(params.k_stream)
    ct_with_tag = cipher.encrypt(nonce, t_message, aad)
    # ct_with_tag = ciphertext (N octets) + tag (16 octets)
    
    tag = ct_with_tag[-TAG_SIZE:]
    ciphertext = ct_with_tag[:-TAG_SIZE]
    
    print(f"   Ciphertext  : {ciphertext.hex()[:32]}... ({len(ciphertext)} octets)")
    print(f"   Tag         : {tag.hex()}")
    
    # ------------------------------------------------------------------
    # 4. Construction du paquet CGL1
    # ------------------------------------------------------------------
    cgl1 = MAGIC + bytes([1]) + salt + nonce + ciphertext + tag
    cgl1_hex = cgl1.hex()
    cgl1_sha256 = hashlib.sha256(cgl1).hexdigest()
    
    print(f"\n📦 Paquet CGL1 :")
    print(f"   Taille      : {len(cgl1)} octets")
    print(f"   SHA256      : {cgl1_sha256}")
    
    # ------------------------------------------------------------------
    # 5. Vérification du roundtrip
    # ------------------------------------------------------------------
    print(f"\n🔄 Vérification roundtrip...")
    
    decrypted = decrypt(cgl1, password, fast_mode=FAST_MODE)
    assert decrypted == plaintext, "ERREUR: Roundtrip échoué !"
    print(f"   ✅ Déchiffrement OK : {decrypted.hex()} == {plaintext.hex()}")
    
    # ------------------------------------------------------------------
    # 6. Construction du dictionnaire KAT complet
    # ------------------------------------------------------------------
    kat = {
        "version": "1.1",
        "generated_at": _iso_timestamp(),
        "description": "Known Answer Tests - CAGOULE v1.1 - NE PAS MODIFIER",
        "parameters": {
            "password": KAT_PASSWORD,
            "salt_hex": KAT_SALT_HEX,
            "nonce_hex": KAT_NONCE_HEX,
            "plaintext_hex": KAT_PLAINTEXT_HEX,
            "plaintext_utf8": bytes.fromhex(KAT_PLAINTEXT_HEX).decode('utf-8', errors='replace'),
        },
        "derived": derived,
        "output": {
            "t_message_hex": t_message.hex(),
            "t_message_len": len(t_message),
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_len": len(ciphertext),
            "tag_hex": tag.hex(),
            "cgl1_hex": cgl1_hex,
            "cgl1_len": len(cgl1),
            "sha256_cgl1": cgl1_sha256,
        },
        "performance": {
            "fast_mode": FAST_MODE,
            "kdf_type": "Argon2id (light)" if FAST_MODE else "Argon2id (production)",
        },
    }
    
    return kat


def _mu_to_hex(params: CagouleParams) -> str:
    """Convertit μ en représentation hexadécimale standardisée."""
    if params.mu.in_fp2:
        # Fp2: a (16 hex) + b (16 hex) = 32 hex
        return format(params.mu.mu.a, '016x') + format(params.mu.mu.b, '016x')
    else:
        # Z/pZ: 16 hex
        return format(params.mu.as_int(), '016x')


def _iso_timestamp() -> str:
    """Retourne le timestamp ISO courant."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


# ------------------------------------------------------------------ #
#  Vérification                                                      #
# ------------------------------------------------------------------ #

def verify_kat(existing_kat: dict) -> bool:
    """
    Vérifie que les KAT existants sont toujours valides.
    
    Returns:
        True si valide, False sinon.
    """
    print("🔍 Vérification des KAT existants...")
    print("=" * 60)
    
    # Générer des KAT frais
    fresh_kat = generate_kat()
    
    # Comparer les champs critiques
    fields_to_check = [
        ("parameters.password", "parameters.password"),
        ("parameters.salt_hex", "parameters.salt_hex"),
        ("parameters.nonce_hex", "parameters.nonce_hex"),
        ("parameters.plaintext_hex", "parameters.plaintext_hex"),
        ("derived.n_zeta", "derived.n_zeta"),
        ("derived.p", "derived.p"),
        ("derived.mu_strategy", "derived.mu_strategy"),
        ("derived.mu_hex", "derived.mu_hex"),
        ("derived.k_stream_hex", "derived.k_stream_hex"),
        ("derived.round_key_0", "derived.round_key_0"),
        ("derived.round_key_63", "derived.round_key_63"),
        ("output.t_message_hex", "output.t_message_hex"),
        ("output.tag_hex", "output.tag_hex"),
        ("output.sha256_cgl1", "output.sha256_cgl1"),
    ]
    
    all_match = True
    
    for existing_path, fresh_path in fields_to_check:
        # Navigation dans les dictionnaires
        existing_val = _get_nested(existing_kat, existing_path.split('.'))
        fresh_val = _get_nested(fresh_kat, fresh_path.split('.'))
        
        if existing_val != fresh_val:
            print(f"   ❌ {existing_path} diverge")
            print(f"      existant: {str(existing_val)[:64]}")
            print(f"      fresh   : {str(fresh_val)[:64]}")
            all_match = False
        else:
            print(f"   ✅ {existing_path}: OK")
    
    if all_match:
        print("\n✅ TOUS LES KAT SONT VALIDES")
        print("   (Le fichier kat_vectors.json est cohérent avec le code)")
    else:
        print("\n❌ LES KAT NE CORRESPONDENT PAS")
        print("   Régénérez avec: python generate_kat.py --force")
    
    return all_match


def _get_nested(d: dict, keys: list) -> Any:
    """Récupère une valeur dans un dictionnaire imbriqué."""
    for key in keys:
        d = d.get(key, {})
        if d is None:
            break
    return d


# ------------------------------------------------------------------ #
#  Sauvegarde                                                        #
# ------------------------------------------------------------------ #

def save_kat(kat: dict, path: Path, force: bool = False) -> bool:
    """
    Sauvegarde les KAT dans un fichier JSON.
    
    Args:
        kat: Dictionnaire KAT
        path: Chemin du fichier
        force: Forcer l'écrasement
    
    Returns:
        True si sauvegardé, False sinon
    """
    if path.exists() and not force:
        print(f"\n⚠ Fichier {path} existe déjà.")
        response = input("  Voulez-vous le régénérer ? (y/N) : ")
        if response.lower() != 'y':
            print("  Annulation.")
            return False
    
    # Sauvegarder avec formatage lisible
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(kat, f, indent=2, ensure_ascii=False)
        f.write('\n')
    
    print(f"\n💾 KAT sauvegardés dans : {path}")
    print(f"   Taille : {path.stat().st_size} octets")
    return True


# ------------------------------------------------------------------ #
#  Main                                                              #
# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(
        description="Génération des Known Answer Tests pour CAGOULE v1.1"
    )
    parser.add_argument(
        "--verify", "-v",
        action="store_true",
        help="Vérifie que kat_vectors.json est cohérent avec le code"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force la régénération (écrase le fichier existant)"
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Chemin de sortie (défaut: kat_vectors.json)"
    )
    
    args = parser.parse_args()
    
    output_path = args.output or _KAT_PATH
    
    if args.verify:
        if not output_path.exists():
            print(f"❌ Fichier introuvable : {output_path}")
            print("   Générez-le d'abord avec: python generate_kat.py")
            return 1
        
        with open(output_path, 'r', encoding='utf-8') as f:
            existing_kat = json.load(f)
        
        success = verify_kat(existing_kat)
        return 0 if success else 1
    
    # Génération
    kat = generate_kat()
    
    if save_kat(kat, output_path, force=args.force):
        print("\n" + "=" * 60)
        print("✅ KAT GÉNÉRÉS AVEC SUCCÈS")
        print("=" * 60)
        print("\n⚠ RAPPEL : Ce fichier est FIGÉ.")
        print("   - Ne plus jamais le modifier")
        print("   - Le portage C doit reproduire exactement ces valeurs")
        print("   - Tout changement dans le code doit maintenir ces KAT")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())