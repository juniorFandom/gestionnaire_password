import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.conf import settings
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .utils import derive_master_key




# ==========================
#   USER PERSONNALISÉ
# ==========================

class CustomUserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("L'adresse email est obligatoire")
        email = self.normalize_email(email)
        extra_fields.setdefault("username", email.split("@")[0])  # username auto
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra_fields)
    


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True



## pour générer un salt binaire pour chaque utilisateur (un callable)
def generate_salt():
    return get_random_bytes(16)


class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, blank=True)
    email = models.EmailField(unique=True)
    salt = models.BinaryField(default=generate_salt)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['']  

    def __str__(self):
        return self.email



## models du coffre (vault)

class Vault(TimeStampedModel):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='users')
    slug = models.SlugField(unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    vault_key_encrypted = models.BinaryField(blank=True, null=True)  # clé AES chiffrée
    kdf_params = models.BinaryField(blank=True, null=True)  # sel + itérations pour dérivation de master_key


    class Meta:
        indexes = [
            models.Index(fields=["user", "name"]),
        ]
        unique_together = ("user", "name")
        ordering = ["name"]

    def __str__(self):
        return f"{self.name}--{self.user.username}----{self.slug}-----{self.kdf_params}"
    

    def check_password(self, password: str) -> bool:
        if not self.vault_key_encrypted or not self.kdf_params:
            return False

        try:
            #dériver la clé maître
            master_key = derive_master_key(password, self)

            # extraire IV / TAG / CIPHERTEXT
            data = self.vault_key_encrypted
            iv = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]

            # déchiffrement AES-GCM
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
            cipher.decrypt_and_verify(ciphertext, tag)

            return True

        except Exception:
            return False




#model des categories 

class Category(TimeStampedModel):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name="categories")
    name = models.CharField(max_length=80)
    parent = models.ForeignKey(
        "self", on_delete=models.CASCADE, related_name="children", blank=True, null=True
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ("vault", "name", "parent")
        ordering = ["order", "name"]

    def __str__(self):
        return self.name


# model des credentials (identifiants)
class Credential(models.Model):
    """
    Représente un mot de passe CHIFFRÉ.
    Le serveur ne connaît JAMAIS la valeur en clair.
    """

    vault = models.ForeignKey(
        Vault,
        on_delete=models.CASCADE,
        related_name="credentials"
    )
    # Coffre auquel appartient l'identifiant

    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="credentials"
    )
    # Catégorie optionnelle

    title = models.CharField(
        max_length=150
    )
    # Nom lisible (ex: "Compte Gmail")

    username = models.CharField(
        max_length=150,
        blank=True
    )
    # Identifiant (email / login)

    url = models.URLField(
        blank=True
    )
    # URL du service

    notes = models.TextField(
        blank=True
    )
    # Notes personnelles (NON sensibles)

    secret_encrypted = models.BinaryField()
    # Mot de passe chiffré (AES-GCM)

    iv = models.BinaryField()
    # Nonce AES-GCM (indispensable au déchiffrement)

    tag = models.BinaryField(default=b'')
    # Tag d’authenticité (garantit l'intégrité)

    created_at = models.DateTimeField(
        auto_now_add=True
    )
    # Date de création

    updated_at = models.DateTimeField(
        auto_now=True
    )
    # Dernière modification
    slug = models.SlugField(unique=True, default=uuid.uuid4, editable=False)
    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f'{self.title}----mot de passe : {self.secret_encrypted}'

    def get_decrypted_password(self, master_password):
        from .utils import derive_vault_key
        vault_key = derive_vault_key(master_password, self.vault)

        cipher = AES.new(vault_key, AES.MODE_GCM, nonce=self.iv)
        decrypted_password = cipher.decrypt_and_verify(self.secret_encrypted, self.tag)
        return decrypted_password.decode('utf-8')
    
    
    def decrypt_with_vault_key(self, vault_key: bytes) -> str:
        cipher = AES.new(vault_key, AES.MODE_GCM, nonce=self.iv)
        password = cipher.decrypt_and_verify(
            self.secret_encrypted,
            self.tag
        )
        return password.decode("utf-8")


# model des historiques du password
class PasswordHistory(models.Model):
    credential = models.ForeignKey(Credential, on_delete=models.CASCADE, related_name="histories")
    secret_encrypted = models.BinaryField()
    iv = models.BinaryField()
    auth_tag = models.BinaryField()

    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-changed_at"]


class Tag(models.Model):
    name = models.CharField(max_length=40, unique=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class CredentialTag(models.Model):
    credential = models.ForeignKey(Credential, on_delete=models.CASCADE)
    tag = models.ForeignKey(Tag, on_delete=models.CASCADE)

    
    class Meta:
        unique_together = ("credential", "tag")



class AuditLog(models.Model):
    ACTION_CHOICES = (
        ("create", "create"),
        ("read", "read"),
        ("update", "update"),
        ("delete", "delete"),
        ("export", "export"),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    vault = models.ForeignKey(Vault, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=12, choices=ACTION_CHOICES)
    target_type = models.CharField(max_length=40, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["vault", "action", "created_at"]),
        ]
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.user}======{self.target_type}"
