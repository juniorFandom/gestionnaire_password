"""
Tests unitaires pour les fonctions de dérivation de clés (utils.py).

Ces tests n'utilisent PAS la base de données : on utilise SimpleTestCase
et un faux objet "vault" (SimpleNamespace) qui n'a que les attributs
dont les fonctions ont réellement besoin (kdf_params, vault_key_encrypted).
C'est ce qui rend ces tests unitaires, rapides, et isolés.

Adapte le chemin d'import ci-dessous ("mon_app.utils") au nom réel
de ton app Django.
"""
import json
from types import SimpleNamespace

from django.test import SimpleTestCase
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils import derive_master_key, derive_vault_key


def make_vault_stub(password, iterations=100_000):
    """
    Construit un faux vault de bout en bout : dérive une master_key à
    partir du mot de passe donné, génère une vraie vault_key aléatoire,
    la chiffre avec la master_key (comme le ferait le vrai système), et
    renvoie le stub ainsi que la vault_key en clair (pour comparaison).
    """
    salt = get_random_bytes(16)
    kdf_params = json.dumps({"salt": salt.hex(), "iterations": iterations}).encode()

    vault_stub = SimpleNamespace(kdf_params=kdf_params, vault_key_encrypted=None)
    master_key = derive_master_key(password, vault_stub)

    vault_key = get_random_bytes(32)
    iv = get_random_bytes(12)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(vault_key)

    # Format attendu par derive_vault_key : IV(12) | TAG(16) | ciphertext
    vault_stub.vault_key_encrypted = iv + tag + ciphertext
    return vault_stub, vault_key


class DeriveMasterKeyTestCase(SimpleTestCase):
    def _make_stub(self, iterations=100_000):
        salt = get_random_bytes(16)
        kdf_params = json.dumps({"salt": salt.hex(), "iterations": iterations}).encode()
        return SimpleNamespace(kdf_params=kdf_params)

    def test_meme_mot_de_passe_et_memes_parametres_donnent_la_meme_cle(self):
        vault_stub = self._make_stub()
        cle_1 = derive_master_key("motdepasse123", vault_stub)
        cle_2 = derive_master_key("motdepasse123", vault_stub)
        self.assertEqual(cle_1, cle_2)

    def test_mot_de_passe_different_donne_une_cle_differente(self):
        vault_stub = self._make_stub()
        cle_1 = derive_master_key("motdepasse123", vault_stub)
        cle_2 = derive_master_key("autre_mot_de_passe", vault_stub)
        self.assertNotEqual(cle_1, cle_2)

    def test_cle_derivee_fait_32_bytes(self):
        vault_stub = self._make_stub()
        cle = derive_master_key("motdepasse123", vault_stub)
        self.assertEqual(len(cle), 32)  # requis pour AES-256


class DeriveVaultKeyTestCase(SimpleTestCase):
    def test_bon_mot_de_passe_retrouve_la_cle_originale(self):
        vault_stub, vault_key_original = make_vault_stub("bon_mot_de_passe")
        vault_key_dechiffree = derive_vault_key("bon_mot_de_passe", vault_stub)
        self.assertEqual(vault_key_dechiffree, vault_key_original)

    def test_mauvais_mot_de_passe_leve_une_exception(self):
        vault_stub, _ = make_vault_stub("bon_mot_de_passe")
        with self.assertRaises(Exception):
            derive_vault_key("mauvais_mot_de_passe", vault_stub)

    def test_donnees_corrompues_levent_une_exception(self):
        vault_stub, _ = make_vault_stub("bon_mot_de_passe")
        # On altère un octet du ciphertext : le tag GCM ne doit plus correspondre
        data = bytearray(vault_stub.vault_key_encrypted)
        data[-1] ^= 0xFF
        vault_stub.vault_key_encrypted = bytes(data)

        with self.assertRaises(Exception):
            derive_vault_key("bon_mot_de_passe", vault_stub)
