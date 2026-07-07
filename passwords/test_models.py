"""
Tests d'intégration pour Vault.check_password et le déchiffrement
des Credentials (models.py).

Ces tests touchent la vraie base de données de test (via TestCase) et
passent par de vrais objets Django — c'est ce qui en fait des tests
d'intégration, contrairement aux tests purement unitaires de test_utils.py.

Adapte les chemins d'import ("mon_app.models") au nom réel de ton app.
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from django.contrib.auth import get_user_model
from django.test import TestCase

from models import Credential, Vault
from test_utils import make_vault_stub

User = get_user_model()


class VaultCheckPasswordTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email="test@exemple.com", password="x")
        vault_stub, _ = make_vault_stub("bon_mot_de_passe")

        self.vault = Vault.objects.create(
            user=self.user,
            name="Mon coffre",
            kdf_params=vault_stub.kdf_params,
            vault_key_encrypted=vault_stub.vault_key_encrypted,
        )

    def test_bon_mot_de_passe_retourne_true(self):
        self.assertTrue(self.vault.check_password("bon_mot_de_passe"))

    def test_mauvais_mot_de_passe_retourne_false(self):
        self.assertFalse(self.vault.check_password("mauvais_mot_de_passe"))

    def test_vault_sans_cle_configuree_retourne_false(self):
        vault_vide = Vault.objects.create(user=self.user, name="Vide")
        self.assertFalse(vault_vide.check_password("peu_importe"))


class CredentialDecryptionTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email="test@exemple.com", password="x")
        vault_stub, self.vault_key = make_vault_stub("bon_mot_de_passe")

        self.vault = Vault.objects.create(
            user=self.user,
            name="Mon coffre",
            kdf_params=vault_stub.kdf_params,
            vault_key_encrypted=vault_stub.vault_key_encrypted,
        )

        # On chiffre un identifiant de test avec la vraie vault_key,
        # exactement comme le ferait l'application en conditions réelles.
        secret = b"mon_super_mot_de_passe"
        iv = get_random_bytes(12)
        cipher = AES.new(self.vault_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(secret)

        self.credential = Credential.objects.create(
            vault=self.vault,
            title="Compte test",
            secret_encrypted=ciphertext,
            iv=iv,
            tag=tag,
        )

    def test_decrypt_with_vault_key_retrouve_le_secret_original(self):
        resultat = self.credential.decrypt_with_vault_key(self.vault_key)
        self.assertEqual(resultat, "mon_super_mot_de_passe")

    def test_get_decrypted_password_avec_bon_mot_de_passe(self):
        resultat = self.credential.get_decrypted_password("bon_mot_de_passe")
        self.assertEqual(resultat, "mon_super_mot_de_passe")

    def test_get_decrypted_password_avec_mauvais_mot_de_passe_leve_erreur(self):
        with self.assertRaises(Exception):
            self.credential.get_decrypted_password("mauvais_mot_de_passe")
