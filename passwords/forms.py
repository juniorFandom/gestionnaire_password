import json
import os
from django import forms
from django.contrib.auth import get_user_model
from .models import Vault, Category, Credential
from .utils import derive_master_key, derive_vault_key
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import uuid

User = get_user_model()

class InscriptionForm(forms.ModelForm):
    nom = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom"})
    )
    password1 = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Mot de passe"})
    )
    password2 = forms.CharField(
        label="Confirmer le mot de passe",
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirmer le mot de passe"})
    )

    class Meta:
        model = User
        fields = ["nom", "email"]
        widgets = {
            "email": forms.EmailInput(attrs={"class": "form-control", "placeholder": "Adresse e-mail"}),
        }

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")
        email = cleaned_data.get("email")

        if password1 != password2:
            self.add_error('password2', "Les mots de passe ne correspondent pas.")

        if User.objects.filter(email=email).exists():
            self.add_error("email", "Un utilisateur avec cette adresse e-mail existe déjà.")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = self.cleaned_data["nom"]  # stocke le nom dans username
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        max_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Code OTP'})
    )


class VaultForm(forms.ModelForm):
    master_password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe maître'
        }),
        required=True,
        label="Mot de passe maître"
    )

    class Meta:
        model = Vault
        fields = ['name']  # Exemple : nom du coffre
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom du coffre'}),
        }

    def save(self, commit=True, user=None, master_password=None):
        vault = super().save(commit=False)
        if user:
            vault.user = user

        # --- Génération des paramètres KDF ---
        salt_bytes = get_random_bytes(16)
        kdf_params_dict = {
            'salt': salt_bytes.hex(),
            'iterations': 100_000,
            'algorithm': 'PBKDF2-HMAC-SHA256'
        }
        vault.kdf_params = json.dumps(kdf_params_dict).encode('utf-8')

        # --- Génération de la clé du Vault ---
        vault_key = get_random_bytes(32)  # AES-256

        # --- Chiffrement de la clé du Vault avec le mot de passe maître ---
        if master_password:
            master_key = derive_master_key(master_password, vault)
            iv = get_random_bytes(12)
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(vault_key)
            vault.vault_key_encrypted = iv + tag + ciphertext

        if commit:
            vault.save()
        return vault



        

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['vault', 'name', 'parent']
        widgets = {
            'vault': forms.Select(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom de la catégorie'}),
            'parent': forms.Select(attrs={'class': 'form-control'}),
            
        }

class CredentialForm(forms.ModelForm):
    # Mot de passe maître pour vérifier l'utilisateur
    master_password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe maître'
        }),
        required=True,
        label="Mot de passe maître"
    )

    # Champ pour saisir le mot de passe en clair (sera chiffré)
    secret_plain = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mot de passe du service'
        }),
        required=False,  
        label="Mot de passe"
    )

    class Meta:
        model = Credential  
        fields = ['vault', 'category', 'title', 'username', 'url', 'notes']
        widgets = {
            'vault': forms.Select(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom du compte/service'}),
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': "Nom d'utilisateur"}),
            'url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'URL'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Notes'}),
        }

    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('request_user', None)
        super().__init__(*args, **kwargs)
        
        # Ajuster le placeholder pour les modifications
        if self.instance and self.instance.pk:
            self.fields['secret_plain'].required = False
            self.fields['secret_plain'].widget.attrs['placeholder'] = 'Laissez vide pour conserver le mot de passe actuel'
            # Stocker les valeurs originales
            self._original_vault_id = self.instance.vault_id
        else:
            self.fields['secret_plain'].required = True
            self.fields['secret_plain'].widget.attrs['placeholder'] = 'Mot de passe du service'

        def clean(self):
            """Validation avec gestion d'erreur détaillée"""
            cleaned_data = super().clean()
            
            print("\n CredentialForm.clean()")
            
            # Récupérer les données
            vault = cleaned_data.get('vault')
            master_password = cleaned_data.get('master_password')
            secret_plain = cleaned_data.get('secret_plain')
            
            print(f"  - vault: {vault.name if vault else 'None'}")
            print(f"  - master_password: {'PRÉSENT' if master_password else 'MANQUANT'}")
            print(f"  - secret_plain: {'PRÉSENT' if secret_plain else 'VIDE'}")
            print(f"  - instance.pk: {self.instance.pk if self.instance else 'None'}")
            
            # Vérification CRITIQUE: le mot de passe maître est requis
            if not master_password:
                print("   Mot de passe maître manquant")
                raise forms.ValidationError(
                    {'master_password': "Le mot de passe maître est requis."}
                )
            
            # Vérification du vault
            if vault:
                if not vault.vault_key_encrypted:
                    print(f"   Vault {vault.name} non initialisé (clé manquante)")
                    raise forms.ValidationError(
                        {'vault': "Le Vault sélectionné n'est pas initialisé correctement."}
                    )
                if not vault.kdf_params:
                    print(f"   Vault {vault.name} non initialisé (KDF params manquants)")
                    raise forms.ValidationError(
                        {'vault': "Le Vault sélectionné n'est pas initialisé correctement."}
                    )
            else:
                print("   Aucun vault sélectionné")
                raise forms.ValidationError(
                    {'vault': "Un vault est requis."}
                )
            
            # Vérification du mot de passe maître
            if self.request_user and master_password:
                if not self.request_user.check_password(master_password):
                    print("   Mot de passe maître incorrect")
                    raise forms.ValidationError(
                        {'master_password': "Mot de passe maître incorrect."}
                    )
                else:
                    print("   Mot de passe maître valide")
            
            # Pour les modifications
            if self.instance and self.instance.pk:
                vault_changed = self.instance.vault_id != vault.id
                print(f"  - vault_changed: {vault_changed}")
                
                # Si le vault a changé, un nouveau mot de passe est OBLIGATOIRE
                if vault_changed and not secret_plain:
                    print("   Changement de vault sans nouveau mot de passe")
                    raise forms.ValidationError(
                        {'secret_plain': "Vous devez fournir un nouveau mot de passe car le Vault a changé."}
                    )
                
                # Si pas de nouveau mot de passe, c'est OK (on garde l'ancien)
                if not secret_plain:
                    print("  ℹ Pas de nouveau mot de passe - conservation de l'existant")
            
            # Pour les créations
            elif not self.instance.pk and not secret_plain:
                print("  Création sans mot de passe")
                raise forms.ValidationError(
                    {'secret_plain': "Le mot de passe est requis."}
                )
            
            print("   Validation réussie")
            return cleaned_data

    def save(self, commit=True):
        """Sauvegarde avec chiffrement"""
        print("\n CredentialForm.save()")
        
        credential = super().save(commit=False)
        
        master_password = self.cleaned_data.get("master_password")
        secret_plain = self.cleaned_data.get("secret_plain")
        
        print(f"  - master_password: {'PRÉSENT' if master_password else 'MANQUANT'}")
        print(f"  - secret_plain: {'PRÉSENT' if secret_plain else 'VIDE'}")
        print(f"  - vault: {credential.vault.name if credential.vault else 'None'}")
        print(f"  - commit: {commit}")
        
        # CAS 1: Nouveau mot de passe fourni
        if secret_plain and master_password:
            print("   Chiffrement du nouveau mot de passe...")
            
            try:
                # Dériver la clé
                key = derive_vault_key(master_password, credential.vault)
                print(f"   Clé dérivée avec succès")
                
                # Chiffrement
                iv = get_random_bytes(12)
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                ciphertext, tag = cipher.encrypt_and_digest(secret_plain.encode('utf-8'))
                
                credential.secret_encrypted = ciphertext
                credential.iv = iv
                credential.tag = tag
                
                print(f"   Chiffrement réussi")
                print(f"    - IV: {iv.hex()[:16]}...")
                print(f"    - Tag: {tag.hex()[:16]}...")
                
            except Exception as e:
                print(f"   Erreur de chiffrement: {str(e)}")
                raise forms.ValidationError(
                    {'secret_plain': f"Erreur de chiffrement: {str(e)}"}
                )
        
        # CAS 2: Modification sans nouveau mot de passe
        elif self.instance.pk and not secret_plain:
            print("   Conservation du mot de passe existant")
            
            if self.instance.secret_encrypted:
                credential.secret_encrypted = self.instance.secret_encrypted
                credential.iv = self.instance.iv
                credential.tag = self.instance.tag
                print(f"   Données chiffrées conservées")
            else:
                print(f"   Aucun mot de passe existant à conserver")
                raise forms.ValidationError(
                    {'secret_plain': "Aucun mot de passe existant à conserver."}
                )
        
        # CAS 3: Erreur - pas de mot de passe
        else:
            print(f"   Aucun mot de passe fourni")
            raise forms.ValidationError(
                {'secret_plain': "Le mot de passe est requis."}
            )
        
        # Générer le slug
        if not credential.slug:
            credential.slug = uuid.uuid4().hex()
            print(f"   Slug généré: {credential.slug}")
        
        # Sauvegarde
        if commit:
            try:
                print(f"   Sauvegarde en base de données...")
                credential.save()
                self.save_m2m()
                print(f"   Sauvegarde réussie (ID: {credential.id})")
            except Exception as e:
                print(f"   Erreur de sauvegarde: {str(e)}")
                raise
        
        return credential

    