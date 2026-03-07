import json
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from django.conf import settings
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.decorators import login_required
from .forms import InscriptionForm, LoginForm, OTPVerificationForm, VaultForm, CategoryForm, CredentialForm
from django.contrib.auth import get_user_model, logout
from .models import CustomUser, Vault, Category, Credential, AuditLog
from django.db.models import Max
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from .utils import derive_vault_key, derive_master_key
from django.core.paginator import Paginator
from django.core.mail import EmailMessage
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import  A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
import io
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.db import transaction




User = get_user_model()


# ---------- 1. Fonction pour envoyer un OTP par email ----------
def send_otp_email(request, user):
    otp = get_random_string(length=6, allowed_chars='0123456789')  # Génère un code OTP à 6 chiffres
    request.session['otp'] = otp  # Stocker dans la session
    request.session['pre_otp_user_id'] = user.id  # Lier l'utilisateur avant validation

    try:
        send_mail(
            'Votre code OTP',
            f'Bonjour {user.username},\n\nVotre code OTP est : {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        # Affichage dans la console pour le développement
        print("=" * 50)
        print(f"📧 EMAIL OTP ENVOYÉ")
        print(f"👤 Utilisateur: {user.username} ({user.email})")
        print(f"🔐 Code OTP: {otp}")
        print("=" * 50)
    except Exception as e:
        # En cas d'erreur d'envoi d'email, on affiche l'OTP dans la console
        print("=" * 50)
        print(f"❌ ERREUR EMAIL: {e}")
        print(f"👤 Utilisateur: {user.username} ({user.email})")
        print(f"🔐 Code OTP: {otp}")
        print("=" * 50)


# ---------- 2. Vue pour l’inscription ----------
def register(request):
    if request.method == "POST":
        form = InscriptionForm(request.POST)
        if form.is_valid():
            user = form.save(commit=True)
            messages.success(request, "Inscription réussie. Un code OTP a été envoyé à votre adresse email.")
            send_otp_email(request, user)  # Envoi OTP à l’inscription
            return redirect("verify_otp")  # Redirige vers saisie OTP
    else:
        form = InscriptionForm()
    return render(request, "passwords/register.html", {"form": form})




# ---------- 3. Vue pour la connexion ----------
def login_view(request):
    if request.session.get('is_connected'):
        return redirect('home')  
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]

            user_auth = authenticate(request, email=email, password=password)

            if user_auth is not None:
                # Envoi OTP avant connexion
                send_otp_email(request, user_auth)
                messages.info(request, "Un code OTP a été envoyé à votre email.")
                request.session['preauth_user_id'] = user_auth.id  # Stocker temporairement l'utilisateur
                return redirect("verify_otp")
            else:
                messages.error(request, "Email ou mot de passe incorrect.")
        else:
            messages.error(request, "Formulaire invalide.")
    else:
        form = LoginForm()
    
    return render(request, "passwords/login.html", {"form": form})


# ---------- 4. Vue pour vérifier l’OTP ----------
def verify_otp(request):
    if request.method == "POST":
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp_saisi = form.cleaned_data["otp"]
            otp_session = request.session.get("otp")
            user_id = request.session.get("pre_otp_user_id")

            if not user_id or not otp_session:
                messages.error(request, "Session expirée, veuillez vous reconnecter.")
                return redirect("login")

            if otp_saisi == otp_session:
                user = get_object_or_404(User, id=user_id)
                auth_login(request, user)  # Authentifie l’utilisateur définitivement
                messages.success(request, "Connexion réussie ! ")
                request.session['is_connected'] = True
                # Nettoyage des sessions OTP
                del request.session["otp"]
                del request.session["pre_otp_user_id"]

                return redirect("home")  # Redirige vers la page d’accueil
            else:
                messages.error(request, "Code OTP invalide.")
    else:
        form = OTPVerificationForm()

    return render(request, "passwords/verify_otp.html", {"form": form})


def home(request):
    """Vue d'accueil avec statistiques dynamiques pour l'utilisateur connecté"""
    context = {}
    
    if request.user.is_authenticated:
        # Récupération des statistiques pour l'utilisateur connecté
        vault_count = Vault.objects.filter(user=request.user).count()
        
        # Nombre total d'identifiants dans tous les coffres de l'utilisateur
        credential_count = Credential.objects.filter(vault__user=request.user).count()
        
        # Nombre total de catégories dans tous les coffres de l'utilisateur
        category_count = Category.objects.filter(vault__user=request.user).count()
        
        # Derniers identifiants ajoutés (pour un éventuel widget)
        recent_credentials = Credential.objects.filter(
            vault__user=request.user
        ).order_by('-created_at')[:5]
        
        context.update({
            'vault_count': vault_count,
            'credential_count': credential_count,
            'category_count': category_count,
            'recent_credentials': recent_credentials,
        })
    
    return render(request, 'passwords/home.html', context)

# vue pour la deconnexion 
@login_required
def logout_view(request):
    logout(request)
    messages.success(request, "Vous avez été déconnecté avec succès.")
    return redirect('login')  



@login_required
def profile_view(request):
    # On peut afficher des infos de l'utilisateur
    user = request.user
    return render(request, 'passwords/profile.html', {'user': user})

    
# vue qui affiche la liste de coffre 
@login_required
def vault_list(request):
    vaults = Vault.objects.filter(user=request.user)
    vault_form = VaultForm()  
    print(f"liste de coffre :{vaults}")
    return render(request, 'passwords/vaults/vault_list.html', {
        'vaults': vaults,
        'vault_form': vault_form,
    })

# vue qui affiche les details d'un coffre 
@login_required
def vault_detail(request, slug):
    vault = get_object_or_404(Vault, slug=slug, user=request.user)
    credentials = Credential.objects.filter(vault=vault)
    return render(request, 'passwords/vaults/vault_detail.html', {
        'vault': vault,
        'credentials': credentials
    })


# vue qui affiche les identifiants d'un coffre
@login_required
def vault_credentials(request, slug):
    if request.method != "POST":
        return JsonResponse({"error": "Méthode non autorisée"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
        master_password = data.get("vault_password")

        vault = get_object_or_404(Vault, slug=slug, user=request.user)

        # cette instruction permet d'ouvrir le vault (UNE SEULE FOIS)
        vault_key = derive_vault_key(master_password, vault)

        #  déchiffrer tous les credentials du coffre
        credentials = []
        for cred in vault.credentials.all():
            credentials.append({
                "title": cred.title,
                "username": cred.username,
                "url": cred.url,
                "password": cred.decrypt_with_vault_key(vault_key)
            })

        return JsonResponse({
            "success": True,
            "credentials": credentials
        })

    except Exception as e:
        print("❌ vault_credentials error:", repr(e))
        return JsonResponse(
            {"success": False, "error": "Mot de passe incorrect ou vault corrompu"},
            status=403
        )

# vue qui permet l'acces a un coffre 
@login_required
def access_vault_api(request, slug):
    
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Méthode non autorisée"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
        master_password = data.get("vault_password")
        if not master_password:
            return JsonResponse({"success": False, "error": "Mot de passe requis"}, status=400)

        vault = get_object_or_404(Vault, slug=slug, user=request.user)

        vault_key = derive_vault_key(master_password, vault)

        credentials_data = []
        for cred in vault.credentials.all():
            credentials_data.append({
                "title": cred.title,
                "username": cred.username,
                "url": cred.url,
                "notes": cred.notes,
                "password": cred.decrypt_with_vault_key(vault_key)
            })

        return JsonResponse({
            "success": True,
            "vault": {
                "name": vault.name,
                "credentials": credentials_data
            }
        })

    except Exception as e:
        print("❌ access_vault_api error:", repr(e))
        return JsonResponse({"success": False, "error": "Mot de passe incorrect ou vault corrompu"}, status=403)


# vue aui permet de creer un coffre (vault)
@login_required
@transaction.atomic()
def vault_create(request):
    if request.method == 'POST':
        form = VaultForm(request.POST)
        master_password = request.POST.get('master_password')

        if form.is_valid():
            vault = form.save(user=request.user, master_password=master_password)
            print('----------------------------------------')      
            print('Coffre créé avec succès et initialisé avec les paramètres KDF.')
            print(f'vault.kdf_params = {vault.kdf_params}')
            print(f'vault.vault_key_encrypted = {vault.vault_key_encrypted}')
            print(f'Utilisateur: {vault.user.username} ({vault.user.email})')
            print('----------------------------------------')

            messages.success(request, 'Coffre créé avec succès.')
            return redirect('vault_list')
    else:
        form = VaultForm()

    return render(request, 'passwords/vaults/vault_form.html', {
        'form': form,
        'title': 'Créer un coffre'
    })


# vue qui permet la mise a jour d'un coffre
@login_required
@transaction.atomic()
def vault_update(request, pk):
    vault = get_object_or_404(Vault, pk=pk, user=request.user)
    
    if request.method == 'POST':
        # Vérifier si c'est une requête AJAX
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # AJAX request - retourner JSON
            master_password = request.POST.get('master_password')
            vault_name = request.POST.get('name', '').strip()
            vault_description = request.POST.get('description', '').strip()
            
            # Validation du mot de passe maître
            try:
                # Vérifier le mot de passe en tentant de déchiffrer la clé du vault
                test_key = derive_vault_key(master_password, vault)
                
                # Mot de passe correct - mettre à jour le coffre
                vault.name = vault_name
                vault.description = vault_description
                # NE PAS modifier kdf_params ou vault_key_encrypted
                vault.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Coffre mis à jour avec succès.'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': 'Mot de passe maître incorrect.'
                }, status=400)
        else:
            # Regular form submission
            form = VaultForm(request.POST, instance=vault)
            if form.is_valid():
                master_password = form.cleaned_data.get('master_password')
                try:
                    # Vérifier le mot de passe
                    test_key = derive_vault_key(master_password, vault)
                    vault.name = form.cleaned_data['name']
                    vault.save()
                    messages.success(request, 'Coffre mis à jour avec succès.')
                    return redirect('vault_list')
                except:
                    form.add_error('master_password', 'Mot de passe maître incorrect.')
    else:
        form = VaultForm(instance=vault)
    
    return render(request, 'passwords/vaults/vault_form.html', {'form': form, 'title': 'Modifier le coffre'})


# vue qui permet de changer le mot de passe d'un coffre
@login_required
@transaction.atomic()
def vault_change_password(request, slug):
    vault = get_object_or_404(Vault, slug=slug, user=request.user)
    
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        
        print(f"\n=== CHANGEMENT MOT DE PASSE VAULT ===")
        print(f"Vault ID: {vault.id}")
        print(f"Vault slug: {vault.slug}")
        print(f"Old password length: {len(old_password) if old_password else 0}")
        print(f"New password length: {len(new_password) if new_password else 0}")
        print(f"Vault KDF params: {vault.kdf_params}")
        print(f"Vault key encrypted length: {len(vault.vault_key_encrypted) if vault.vault_key_encrypted else 0}")
        
        if not old_password or not new_password:
            return JsonResponse({
                'success': False,
                'message': 'Les mots de passe sont requis.'
            }, status=400)
        
        try:
            # Vérifier l'ancien mot de passe en tentant de dériver la vault_key
            print(f"Tentative de dérivation de vault_key avec l'ancien mot de passe...")
            old_vault_key = derive_vault_key(old_password, vault)
            print(f"Succès ! Vault key dérivée: {old_vault_key.hex()[:32]}...")
        except Exception as e:
            print(f"Erreur lors de la vérification du mot de passe: {str(e)}")
            print(f"Type d'erreur: {type(e).__name__}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            return JsonResponse({
                'success': False,
                'message': 'Mot de passe maître incorrect.'
            }, status=400)
        
        try:
            # Récupérer tous les credentials du vault
            credentials = Credential.objects.filter(vault=vault)
            
            # Déchiffrer tous les credentials avec l'ancienne clé
            decrypted_credentials = []
            for cred in credentials:
                try:
                    # Déchiffrer le mot de passe
                    cipher = AES.new(old_vault_key, AES.MODE_GCM, nonce=cred.iv)
                    plaintext = cipher.decrypt_and_verify(cred.secret_encrypted, cred.tag)
                    decrypted_credentials.append({
                        'credential': cred,
                        'plaintext': plaintext
                    })
                except Exception as e:
                    print(f"Erreur déchiffrement credential: {str(e)}")
                    return JsonResponse({
                        'success': False,
                        'message': f'Erreur lors du déchiffrement des identifiants.'
                    }, status=400)
            
            # Générer une nouvelle clé pour le vault
            new_vault_key = get_random_bytes(32)
            
            # Dériver le master_key avec le MÊME vault (pour utiliser les mêmes KDF params)
            new_master_key = derive_master_key(new_password, vault)
            
            # Chiffrer la nouvelle clé du vault avec le nouveau mot de passe
            iv = get_random_bytes(12)
            cipher = AES.new(new_master_key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(new_vault_key)
            vault.vault_key_encrypted = iv + tag + ciphertext
            vault.save()
            
            # Re-chiffrer tous les credentials avec la nouvelle clé
            for item in decrypted_credentials:
                cred = item['credential']
                plaintext = item['plaintext']
                
                # Générer une nouvelle IV
                new_iv = get_random_bytes(12)
                cipher = AES.new(new_vault_key, AES.MODE_GCM, nonce=new_iv)
                new_ciphertext, new_tag = cipher.encrypt_and_digest(plaintext)
                
                # Mettre à jour le credential
                cred.secret_encrypted = new_ciphertext
                cred.iv = new_iv
                cred.tag = new_tag
                cred.save()
            
            # Enregistrer l'action dans l'audit log
            AuditLog.objects.create(
                user=request.user,
                action='update',
                vault=vault,
                target_type='vault',
                target_id=str(vault.id)
            )
            
            print(f"Mot de passe du vault {vault.id} changé avec succès")
            return JsonResponse({
                'success': True,
                'message': 'Mot de passe du coffre changé avec succès.'
            })
        
        except Exception as e:
            print(f"Erreur générale lors du changement de mot de passe: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': 'Erreur lors du changement de mot de passe.'
            }, status=400)
    
    return JsonResponse({
        'success': False,
        'message': 'Méthode non autorisée.'
    }, status=405)


# vue qui permet de supprimer un coffre
@login_required
def vault_delete(request, slug):
    vault = get_object_or_404(Vault, slug=slug, user=request.user)
    
    if request.method == 'POST':
        # Vérifier si c'est une requête AJAX
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            password = request.POST.get('password')
            
            if not password:
                return JsonResponse({
                    'success': False,
                    'message': 'Le mot de passe est requis.'
                }, status=400)
            
            try:
                # Vérifier le mot de passe en tentant de dériver la vault_key
                test_key = derive_vault_key(password, vault)
                
                # Mot de passe correct - supprimer le coffre
                vault_name = vault.name
                vault.delete()
                
                # Enregistrer l'action dans l'audit log
                AuditLog.objects.create(
                    user=request.user,
                    action='delete',
                    target_type='vault',
                    target_id=str(vault.id)
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'Coffre "{vault_name}" supprimé avec succès.'
                })
            except Exception as e:
                print(f"Erreur lors de la suppression du vault: {str(e)}")
                return JsonResponse({
                    'success': False,
                    'message': 'Mot de passe incorrect.'
                }, status=400)
        else:
            # Regular form submission (pour compatibilité)
            vault.delete()
            messages.success(request, 'Coffre supprimé avec succès.')
            return redirect('vault_list')
    
    return render(request, 'passwords/vaults/vault_confirm_delete.html', {'vault': vault})



# vue aui affiche les categories 
@login_required
def category_list(request):
    categories = Category.objects.filter(vault__user=request.user)
    vaults = Vault.objects.filter(user = request.user)
    category_form = CategoryForm()
    return render(request, 'passwords/categories/category_list.html', {
        'categories': categories,
        'category_form': category_form,
        'vaults':vaults
    })


# vue qui permet la creation d'un coffre
@login_required
def category_create(request, vault_id=None):
    # Si vault_id est fourni, on récupère le coffre spécifique
    vault = None
    if vault_id:
        vault = get_object_or_404(Vault, pk=vault_id, user=request.user)

    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save(commit=False)
            # Associer le coffre si non choisi
            if not category.vault:
                category.vault = vault
            # Calcul automatique de l'ordre
            max_order = Category.objects.filter(
                vault=category.vault,
                parent=category.parent
            ).aggregate(Max('order'))['order__max']
            category.order = 1 if max_order is None else max_order + 1
            category.save()
            messages.success(request, 'Catégorie créée avec succès.')
            return redirect('category_list')
    else:
        form = CategoryForm()
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['parent'].queryset = Category.objects.filter(vault__user=request.user)

    return render(request, 'passwords/categories/category_form.html', {
        'form': form,
        'title': 'Créer une catégorie'
    })


# vue qui permet la mise a jour d'un coffre
@login_required
def category_update(request, pk):
    category = get_object_or_404(Category, pk=pk, vault__user=request.user)
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            # Si parent ou vault change, on peut recalculer l'ordre automatiquement si nécessaire
            if 'parent' in form.changed_data or 'vault' in form.changed_data:
                max_order = Category.objects.filter(
                    vault=category.vault,
                    parent=form.cleaned_data['parent']
                ).aggregate(Max('order'))['order__max']
                category.order = 1 if max_order is None else max_order + 1

            form.save()
            messages.success(request, 'Catégorie mise à jour avec succès.')
            return redirect('category_list')
    else:
        form = CategoryForm(instance=category)
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['parent'].queryset = Category.objects.filter(vault__user=request.user).exclude(pk=category.pk)

    return render(request, 'passwords/categories/category_form.html', {
        'form': form,
        'title': 'Modifier la catégorie'
    })

# vue qui permet la suppression d'une categorie
@login_required
def category_delete(request, pk):
    category = get_object_or_404(Category, pk=pk, vault__user=request.user)
    if request.method == 'POST':
        category.delete()
        messages.success(request, 'Catégorie supprimée avec succès.')
        return redirect('category_list')
    return render(request, 'passwords/categories/category_confirm_delete.html', {'category': category})


# vue qui affiche a liste des identifaints 
@login_required
def credential_list(request):
    credentials = Credential.objects.filter(vault__user=request.user)
    vaults = Vault.objects.filter(user=request.user)
    categories = Category.objects.filter(vault__user=request.user)
    
    return render(request, 'passwords/credentials/credential_list.html', {
        'credentials': credentials,
        'vaults': vaults,
        'categories': categories
    })

# vue qui permet de creer un identifiant
@login_required
@transaction.atomic()
def credential_create(request):
    if request.method == 'POST':
        print("methode post")
        form = CredentialForm(request.POST)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        if form.is_valid():
            print("formulaire valide")
            credential = form.save(commit=False)
            
            credential.vault = form.cleaned_data['vault']
            if not credential.vault.vault_key_encrypted or not credential.vault.kdf_params:
                form.add_error('vault', "Le Vault sélectionné n'est pas initialisé correctement.")
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'errors': {'vault': ["Le Vault sélectionné n'est pas initialisé correctement."]}
                    }, status=400) 
                return render(request, 'passwords/credentials/credential_form_fields.html', {'form': form, 'title': 'Ajouter un identifiant'})

            # Vérifier le mot de passe maître
            master_password = form.cleaned_data.get("master_password")
            if not request.user.check_password(master_password):
                form.add_error('master_password', "Mot de passe maître incorrect.")
                if is_ajax:
                    return JsonResponse({
                        'success': False,
                        'errors': {'master_password': ["Mot de passe maître incorrect."]}
                    }, status=400) 
                return render(request, 'passwords/credentials/credential_form_fields.html', {'form': form, 'title': 'Ajouter un identifiant'})

            # Sauvegarde et chiffrement
            credential.save()
            print(f"Credential '{credential.title}' créé pour le vault '{credential.vault.name}'")
            
            if is_ajax:
                return JsonResponse({
                    'success': True,
                    'message': 'Identifiant créé avec succès.'
                })
            
            messages.success(request, "Identifiant créé avec succès.")
            return redirect("credential_list")
        else:
            print("Form errors:", form.errors)
            if is_ajax:
                # Convertir les erreurs du formulaire en dictionnaire
                errors = {}
                for field, field_errors in form.errors.items():
                    errors[field] = field_errors
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)

    else:
        form = CredentialForm()
        print("aucune methone post")
        # Filtrer les vaults et catégories par utilisateur
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['category'].queryset = Category.objects.filter(vault__user=request.user)

    return render(request, 'passwords/credentials/credential_form_fields.html', {'form': form, 'title': 'Ajouter un identifiant'})


# vue qui permet de dechifrer dechffrer un mot de passe de l'affciher
@login_required
def get_credential_password_api(request, slug):
    """
    Déchiffre le mot de passe d'un Credential avec le mot de passe du coffre.
    Retourne la réponse en JSON pour AJAX.
    """
    credential = get_object_or_404(Credential, slug=slug, vault__user=request.user)
    vault = credential.vault

    if request.method == "POST":
        master_password = request.POST.get("master_password")

        if not master_password:
            return JsonResponse({'success': False, 'error': 'Mot de passe maître requis.'}, status=400)

        try:
            # Vérifier le mot de passe du coffre en tentant de dériver la vault_key
            vault_key = derive_vault_key(master_password, vault)
            
            # Déchiffrer le mot de passe du credential avec la vault_key
            cipher = AES.new(vault_key, AES.MODE_GCM, nonce=credential.iv)
            plaintext = cipher.decrypt_and_verify(credential.secret_encrypted, credential.tag)
            decrypted_password = plaintext.decode('utf-8')
            
            return JsonResponse({'success': True, 'password': decrypted_password})
        except Exception as e:
            print(f"Erreur déchiffrement credential {slug}: {str(e)}")
            return JsonResponse({'success': False, 'error': 'Mot de passe maître incorrect.'}, status=403)

    # GET : indiquer qu'il faut le mot de passe maître
    return JsonResponse({'success': False, 'requires_password': True})


#vue qui permet de creer un identifiant 
@login_required
@transaction.atomic()
def credential_create(request):
    """Vue pour créer un nouveau credential"""
    if request.method == 'POST':
        form = CredentialForm(
            request.POST, 
            request_user=request.user 
        )
    
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['category'].queryset = Category.objects.filter(vault__user=request.user)
        
        if form.is_valid():
            credential = form.save() 
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'Identifiant créé avec succès.'
                })
            
            messages.success(request, "Identifiant créé avec succès.")
            return redirect('credential_list')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                errors = {field: [str(error) for error in error_list] for field, error_list in form.errors.items()}
                return JsonResponse({'success': False, 'errors': errors}, status=400)
    
    else:
        form = CredentialForm(request_user=request.user)
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['category'].queryset = Category.objects.filter(vault__user=request.user)
    
    return render(request, 'passwords/credentials/credential_form_fields.html', {
        'form': form,
        'title': 'Ajouter un identifiant'
    })

# vue qui permet la mise a jour d'un identifiant
@login_required
@transaction.atomic()
def credential_update(request, slug):
    """Vue pour modifier un credential existant"""
    credential = get_object_or_404(Credential, slug=slug, vault__user=request.user)
    
    print("\n" + "="*60)
    print(" DÉBUT DE LA REQUÊTE DE MODIFICATION")
    print(f" Credential: {credential.title} (ID: {credential.id})")
    print(f"Méthode: {request.method}")
    print(f" AJAX: {request.headers.get('X-Requested-With')}")
    print("="*60 + "\n")
    
    if request.method == 'POST':
        # DEBUG: Afficher les données POST reçues
        print(" DONNÉES POST REÇUES:")
        for key, value in request.POST.items():
            if key in ['master_password', 'secret_plain']:
                print(f"  - {key}: [MASQUÉ] (longueur: {len(value) if value else 0})")
            else:
                print(f"  - {key}: {value}")
        
        print("\n" + "-"*60)
        
        # Créer le formulaire avec l'utilisateur
        form = CredentialForm(
            request.POST, 
            instance=credential,
            request_user=request.user
        )
        
        # Filtrer les querysets
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['category'].queryset = Category.objects.filter(vault__user=request.user)
        
        # DEBUG: Vérifier les données du formulaire avant validation
        print("\n DONNÉES DU FORMULAIRE AVANT VALIDATION:")
        print(f"  - secret_plain: {request.POST.get('secret_plain', 'NON FOURNI')}")
        print(f"  - master_password: {'PRÉSENT' if request.POST.get('master_password') else 'MANQUANT'}")
        print(f"  - vault: {request.POST.get('vault', 'NON FOURNI')}")
        print(f"  - title: {request.POST.get('title', 'NON FOURNI')}")
        
        # Vérifier si le formulaire est valide
        print("\n VALIDATION DU FORMULAIRE...")
        is_valid = form.is_valid()
        print(f"  → Formulaire valide: {is_valid}")
        
        if not is_valid:
            print("\n ERREURS DE VALIDATION:")
            for field, errors in form.errors.items():
                print(f"  - {field}: {', '.join(errors)}")
        
        if is_valid:
            try:
                # Sauvegarde (le formulaire fait tout le travail)
                print("\n SAUVEGARDE...")
                credential = form.save()
                print(f"  → Sauvegarde réussie! ID: {credential.id}")
                
                # Réponse AJAX
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': True,
                        'message': 'Identifiant mis à jour avec succès.'
                    })
                
                messages.success(request, "Identifiant mis à jour avec succès.")
                return redirect('credential_list')
                
            except Exception as e:
                print(f"\n EXCEPTION PENDANT LA SAUVEGARDE: {str(e)}")
                import traceback
                traceback.print_exc()
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False,
                        'errors': {'__all__': [str(e)]}
                    }, status=400)
                else:
                    form.add_error(None, str(e))
        else:
            # Réponse AJAX avec erreurs
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                errors = {}
                for field, error_list in form.errors.items():
                    errors[field] = [str(error) for error in error_list]
                
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
    
    else:
        # GET: Afficher le formulaire
        form = CredentialForm(instance=credential, request_user=request.user)
        form.fields['vault'].queryset = Vault.objects.filter(user=request.user)
        form.fields['category'].queryset = Category.objects.filter(vault__user=request.user)
    
    # Rendu du template
    return render(request, 'passwords/credentials/credential_form_fields.html', {
        'form': form,
        'title': 'Modifier un identifiant',
        'credential': credential
    })

#vue qui permet la suppresion d'un identifiant
@login_required
@transaction.atomic()
def credential_delete(request, slug):
    try:
        credential = Credential.objects.get(slug=slug, vault__user=request.user)
        credential.delete()
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'message': 'Identifiant supprimé avec succès'
            })
        
        messages.success(request, "Identifiant supprimé avec succès.")
        return redirect('credential_list')
        
    except Credential.DoesNotExist:
        messages.error(request, "Identifiant non trouvé.")
        return redirect('credential_list')


# vue qui retoune la liste des logs d'acces 
@login_required
def audit_log(request):
    logs = AuditLog.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(logs, 25)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'audit_logs': page_obj.object_list,
        'page_obj': page_obj,
        'is_paginated': page_obj.has_other_pages(),
    }
    return render(request, "passwords/audit_log.html", context)

# vue du profil
@login_required
def profile(request):
    # Version debug avec requêtes séparées
    user_vaults = Vault.objects.filter(user=request.user)
    vault_count = user_vaults.count()
    
    # Requête plus explicite pour les credentials
    credential_count = Credential.objects.filter(
        vault__in=user_vaults
    ).count()
    
    # Requête plus explicite pour les catégories
    category_count = Category.objects.filter(
        vault__in=user_vaults
    ).count()
    
    print(f"Vaults: {vault_count}")
    print(f"Credentials: {credential_count}") 
    print(f"Categories: {category_count}")
    
    # Vérifions s'il y a des données
    if vault_count == 0:
        print("Aucun coffre trouvé pour l'utilisateur")
    else:
        # Afficher les IDs des coffres trouvés
        vault_ids = list(user_vaults.values_list('id', flat=True))
        print(f"IDs des coffres: {vault_ids}")
    
    context = {
        'vault_count': vault_count,
        'credential_count': credential_count,
        'category_count': category_count
    }
    
    return render(request, "passwords/profile.html", context)


@login_required
@require_POST
def export_vault_pdf(request, vault_slug):
    """Exporte les identifiants d'un coffre au format PDF et les envoie par email"""
    try:
        # Récupérer le coffre
        vault = Vault.objects.get(slug=vault_slug, user=request.user)
        
        # Vérifier le mot de passe du coffre
        vault_password = request.POST.get('vault_password')
        if not vault_password:
            return JsonResponse({'success': False, 'message': 'Mot de passe requis'})
        
        # Vérifier que le mot de passe est correct
        if not vault.check_password(vault_password):
            return JsonResponse({'success': False, 'message': 'Mot de passe incorrect'})
        
        # Récupérer tous les identifiants du coffre
        credentials = Credential.objects.filter(vault=vault)
        
        if not credentials.exists():
            return JsonResponse({'success': False, 'message': 'Aucun identifiant dans ce coffre'})
        
        # Déchiffrer les identifiants avec la clé du vault
        vault_key = derive_vault_key(vault_password, vault)
        
        credentials_data = []
        for cred in credentials:
            try:
                decrypted_password = cred.decrypt_with_vault_key(vault_key)
                credentials_data.append({
                    'title': cred.title,
                    'username': cred.username,
                    'password': decrypted_password,
                    'url': cred.url,
                    'notes': cred.notes,
                    'category': cred.category.name if cred.category else None,
                    'created_at': cred.created_at,
                    'updated_at': cred.updated_at,
                })
            except Exception as e:
                # Si un identifiant ne peut pas être déchiffré, on le skip
                continue
        
        # Générer le PDF
        pdf_buffer = generate_vault_pdf(vault, credentials_data, request.user)
        
        # Envoyer l'email
        send_vault_pdf_email(request.user.email, vault.name, pdf_buffer)
        
        # Journaliser l'export
        AuditLog.objects.create(
            user=request.user,
            vault=vault,
            action='export',
            target_type='Vault',
            target_id=str(vault.id),
            ip=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return JsonResponse({
            'success': True, 
            'message': f'Le PDF a été envoyé à {request.user.email}'
        })
        
    except Vault.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Coffre introuvable'})
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Erreur: {str(e)}'})


def generate_vault_pdf(vault, credentials_data, user):
    """Génère un PDF avec la liste des identifiants"""
    buffer = io.BytesIO()
    
    # Créer le document PDF
    doc = SimpleDocTemplate(buffer, pagesize=A4, 
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=72)
    
    # Conteneur pour les éléments du PDF
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#6C8CFF'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    # Titre
    elements.append(Paragraph(f"Coffre: {vault.name}", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Informations
    info_style = ParagraphStyle(
        'Info',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    elements.append(Paragraph(f"Exporté le: {timezone.now().strftime('%d/%m/%Y %H:%M')}", info_style))
    elements.append(Paragraph(f"Utilisateur: {user.email}", info_style))
    elements.append(Paragraph(f"Nombre d'identifiants: {len(credentials_data)}", info_style))
    elements.append(Spacer(1, 0.3*inch))
    
    if credentials_data:
        # En-tête du tableau
        data = [['Service', 'Catégorie', 'Identifiant', 'Mot de passe', 'URL']]
        
        # Données
        for cred in credentials_data:
            # Tronquer les mots de passe trop longs pour le PDF
            password = cred['password']
            if len(password) > 20:
                password = password[:20] + '...'
                
            data.append([
                cred['title'],
                cred['category'] or '-',
                cred['username'] or '-',
                password,
                cred['url'] or '-'
            ])
        
        # Créer le tableau
        table = Table(data, colWidths=[1.2*inch, 0.8*inch, 1.2*inch, 1.2*inch, 1.4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6C8CFF')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        
        # Ajouter les notes si présentes
        has_notes = any(cred.get('notes') for cred in credentials_data)
        if has_notes:
            elements.append(Spacer(1, 0.3*inch))
            elements.append(Paragraph("Notes:", styles['Heading2']))
            for cred in credentials_data:
                if cred.get('notes'):
                    notes_text = f"<b>{cred['title']}:</b> {cred['notes']}"
                    elements.append(Paragraph(notes_text, styles['Normal']))
                    elements.append(Spacer(1, 0.1*inch))
    else:
        elements.append(Paragraph("Aucun identifiant dans ce coffre", styles['Normal']))
    
    # Construire le PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer

def send_vault_pdf_email(user_email, vault_name, pdf_buffer):
    """Envoie le PDF par email"""
    subject = f" Export du coffre: {vault_name}"
    message = f"""
    Bonjour,
    
    Veuillez trouver ci-joint l'export PDF de votre coffre "{vault_name}".
    
     Récapitulatif:
    • Coffre: {vault_name}
    • Date d'export: {timezone.now().strftime('%d/%m/%Y %H:%M')}
    
      ATTENTION: Ce fichier contient tous vos identifiants en clair.
    • Conservez-le dans un endroit sécurisé (coffre-fort numérique, disque chiffré)
    • Ne le partagez jamais par email
    • Supprimez-le après usage si vous n'en avez plus besoin
    
    Pour toute question, contactez notre support.
    
    Cordialement,
    L'équipe SecureVault
    """
    
    email = EmailMessage(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user_email]
    )
    
    # Attacher le PDF avec un nom sécurisé
    safe_vault_name = vault_name.replace(' ', '_').replace('/', '_')
    email.attach(f"SecureVault_{safe_vault_name}_{timezone.now().strftime('%Y%m%d')}.pdf", 
                pdf_buffer.getvalue(), 
                'application/pdf')
    
    # Envoyer l'email
    email.send(fail_silently=False)