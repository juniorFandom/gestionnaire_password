import json
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ============================================================================
# FONCTION 1 : derive_master_key
# ============================================================================
# RÔLE : Transformer le mot de passe maître de l'utilisateur en une clé 
#        cryptographique de 32 bytes (256 bits) utilisable par AES.
# 
# ALGORITHME : PBKDF2 (Password-Based Key Derivation Function 2)
# SÉCURITÉ : 100 000 itérations + sel unique → résiste aux attaques par 
#            force brute et par rainbow tables.
# ============================================================================

def derive_master_key(master_password: str, vault) -> bytes:
    """
    Dérive une clé maître à partir du mot de passe de l'utilisateur.
    
    Args:
        master_password (str): Le mot de passe saisi par l'utilisateur
        vault (Vault): L'objet coffre contenant les paramètres KDF
    
    Returns:
        bytes: Une clé de 32 bytes (256 bits) prête pour AES
    """
    
    # ÉTAPE 1 : Récupérer les paramètres de dérivation stockés dans le vault
    # ------------------------------------------------------------------------
    # vault.kdf_params est un champ binaire qui contient un JSON avec :
    # - salt : valeur aléatoire unique (16 bytes en hexadécimal)
    # - iterations : nombre de répétitions (généralement 100 000)
    # 
    # Ces paramètres ont été générés à la création du vault et sont nécessaires
    # pour reproduire EXACTEMENT la même dérivation plus tard.
    params = json.loads(vault.kdf_params.decode())
    
    # Convertir le sel de format hexadécimal en bytes
    salt = bytes.fromhex(params["salt"])
    iterations = params["iterations"]
    
    # ÉTAPE 2 : Configuration de PBKDF2
    # ------------------------------------------------------------------------
    # PBKDF2 est une fonction standard (NIST) qui :
    # 1. Prend le mot de passe + sel
    # 2. Applique HMAC-SHA256 en boucle (iterations fois)
    # 3. Produit une clé de la longueur demandée (32 bytes)
    # 
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),           # Fonction de hachage utilisée
        length=32,                            # 32 bytes = 256 bits (AES-256)
        salt=salt,                            # Sel unique (évite rainbow tables)
        iterations=iterations,                 # 100 000 répétitions (ralentit)
        backend=default_backend()              # Implémentation optimisée
    )
    
    # ÉTAPE 3 : Dériver la clé
    # ------------------------------------------------------------------------
    # Prend le mot de passe (bytes) et applique PBKDF2 pour obtenir la clé
    # Résultat : une clé de 32 bytes dérivée du mot de passe
    return kdf.derive(master_password.encode())


# ============================================================================
# FONCTION 2 : derive_vault_key
# ============================================================================
# RÔLE : Déchiffrer la clé du vault (stockée chiffrée) en utilisant la clé
#        maître dérivée du mot de passe.
# 
# ALGORITHME : AES-256-GCM (Galois/Counter Mode)
# SÉCURITÉ : 
#   - Chiffrement + Authentification intégrée
#   - Vérification du tag garantit l'intégrité des données
#   - Double protection : mot de passe maître + clé de vault
# ============================================================================

def derive_vault_key(master_password: str, vault) -> bytes:
    """
    Déchiffre la clé du vault en utilisant le mot de passe maître.
    
    Args:
        master_password (str): Le mot de passe saisi par l'utilisateur
        vault (Vault): L'objet coffre contenant la clé chiffrée
    
    Returns:
        bytes: La clé du vault en clair (32 bytes)
        
    Raises:
        Exception: Si le mot de passe est incorrect ou si les données sont
                   corrompues (le tag de vérification échoue)
    """
    
    # ÉTAPE 1 : Obtenir la clé maître à partir du mot de passe
    # ------------------------------------------------------------------------
    # Appelle la fonction précédente pour transformer le mot de passe
    # utilisateur en une clé cryptographique utilisable pour AES
    master_key = derive_master_key(master_password, vault)
    
    # ÉTAPE 2 : Extraire les composants de vault_key_encrypted
    # ------------------------------------------------------------------------
    # vault.vault_key_encrypted contient un package binaire avec :
    # - IV (12 premiers bytes) : Vecteur d'initialisation (unique)
    # - TAG (12 à 28) : Code d'authentification (intégrité)
    # - Ciphertext (reste) : La clé du vault chiffrée
    # 
    # Format : [ IV (12) | TAG (16) | Ciphertext (32) ]
    data = vault.vault_key_encrypted
    iv = data[:12]           # 12 bytes - Nonce AES-GCM
    tag = data[12:28]        # 16 bytes - Tag d'authenticité
    ciphertext = data[28:]    # 32 bytes - Clé du vault chiffrée
    
    # ÉTAPE 3 : Déchiffrement avec AES-GCM
    # ------------------------------------------------------------------------
    # AES-GCM (Galois/Counter Mode) combine :
    # - Chiffrement AES-256 (confidentialité)
    # - GMAC (authentification) via le tag
    # 
    # Le mode GCM est particulièrement adapté car :
    # 1. Il authentifie les données (tag)
    # 2. Il est parallélisable (rapide)
    # 3. Il résiste aux attaques par texte chiffré
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
    
    # ÉTAPE 4 : Vérification et déchiffrement
    # ------------------------------------------------------------------------
    # decrypt_and_verify fait DEUX choses en une :
    # 1. Vérifie que le tag correspond (intégrité)
    #    - Si le tag ne correspond pas → Exception
    #    - Cela signifie que :
    #      a) Le mot de passe est incorrect, OU
    #      b) Les données ont été modifiées
    # 
    # 2. Déchiffre le ciphertext pour obtenir la clé du vault
    # 
    # Cette double vérification est essentielle pour la sécurité :
    # - Empêche les attaques par modification
    # - Garantit que le bon mot de passe a été utilisé
    vault_key = cipher.decrypt_and_verify(ciphertext, tag)
    
    # ÉTAPE 5 : Retourner la clé du vault
    # ------------------------------------------------------------------------
    # La clé du vault est maintenant en clair (32 bytes).
    # Cette clé servira à chiffrer/déchiffrer tous les credentials
    # de ce vault.
    return vault_key


# ============================================================================
# RÉSUMÉ DU PROCESSUS COMPLET
# ============================================================================
# 
# 1. L'utilisateur saisit son mot de passe maître
# 2. derive_master_key() transforme ce mot de passe en clé maître
#    (PBKDF2 avec sel + 100k itérations)
# 
# 3. derive_vault_key() utilise cette clé maître pour déchiffrer
#    la clé du vault stockée dans la base de données
#    (AES-GCM avec vérification du tag)
# 
# 4. Si tout réussit → on obtient la clé du vault en clair
#    Cette clé permettra de déchiffrer les credentials
# 
# 5. Si échec → Exception (mot de passe incorrect ou données corrompues)
# 
# SÉCURITÉ GARANTIE PAR :
# ------------------------
# ✓ Le mot de passe n'est JAMAIS stocké en clair
# ✓ La clé du vault n'est JAMAIS stockée en clair
# ✓ Double niveau de protection (maître + vault)
# ✓ Sel unique par vault contre rainbow tables
# ✓ Itérations PBKDF2 contre force brute
# ✓ Tag GCM contre modification des données
# ============================================================================