# Projet gestionnaire de mot de pass 

**SecureVault** est une application web monolithique de gestion de coffre-fort numérique développée avec **Django** et orchestrée sous **Docker Compose**, conçue pour centraliser et sécuriser le stockage d'identifiants selon un modèle de confiance « *Zero-Knowledge* ». L'application délègue l'authentification initiale à la plateforme **Google Identity (OAuth 2.0 / OpenID Connect)** via une route de *Callback* sécurisée, éliminant ainsi la gestion locale de mots de passe d'accès tout en protégeant l'interface contre les failles XSS et CSRF grâce aux sécurités natives du framework django. L'accès aux secrets repose sur un principe de chiffrement d'enveloppe hautement sécurisé : à chaque connexion, le mot de passe maître de l'utilisateur est transformé en une clé de 256 bits par la fonction de dérivation **PBKDF2-HMAC-SHA256** (100 000 itérations avec sel unique), laquelle est immédiatement utilisée pour déchiffrer la clé interne du coffre-fort via l'algorithme symétrique authentifié **AES-256-GCM**. Ce couplage garantit non seulement une confidentialité absolue des données—qui restent mathématiquement illisibles en base de données même en cas de compromission du serveur—mais assure également leur intégrité stricte grâce à la validation par tag d'authenticité (AEAD), offrant ainsi une solution robuste, performante en mémoire et simple à déployer.

## Prérequis

- Python 3.8+
- pip
- virtualenv (recommandé)

## Installation

1. Cloner le dépôt :
```bash
git clone <votre-repo>
```

2. Créer un environnement virtuel et l'activer :
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# ou
.venv\Scripts\activate  # Windows
```

3. Installer les dépendances :
```bash
pip install -r requirements.txt
```
## configuration de OIDC
4. Configurer le projet dans google console afin d'obtenir les paramettres (identifiants) pour inplementer le protocole OIDC
     
 Étape 1 : Aller sur la Console Google Cloud

    - Rendez-vous sur la Google Cloud Console.

    - Connectez-vous avec votre compte Google.

    - Si ce n'est pas déjà fait, créez un nouveau projet (cliquez sur la liste déroulante des projets en haut à gauche → Nouveau projet → Donnez-lui un nom comme "Gestionnaire Mots de Passe").

 Étape 2 : Configurer l'écran de consentement OAuth (Obligatoire d'abord)

    Avant de vous donner des clés, Google doit savoir à quoi va ressembler l'écran que verra votre utilisateur.

    - Dans le menu de gauche, allez dans API et services → Écran de consentement OAuth.

    - Choisissez le type Externe (ou Internal si vous utilisez un compte Google Workspace d'entreprise), puis cliquez sur Créer.

    - Remplissez uniquement les champs obligatoires (Nom de l'application, adresse email d'assistance).

    - Cliquez sur Enregistrer et continuer jusqu'au bout sans rien toucher d'autre.

 Étape 3 : Créer les identifiants (ID Client et Secret)

    C'est ici que l'on génère vos fameuses clés :

    - Dans le menu de gauche, cliquez sur Identifiants.

    - En haut, cliquez sur + Créer des identifiants → ID de client OAuth.

    - Dans Type d'application, sélectionnez Application Web.

    - Donnez-lui un nom (ex: "Django Local").

 Étape 4 : Configurer les URLs (Le point le plus important )

    Faites défiler la page vers le bas jusqu'aux sections d'URLs :

    - Origines JavaScript autorisées : Cliquez sur "Ajouter une URL" et mettez l'adresse de base de votre Django :
    http://127.0.0.1:8000 (et ajoute http://localhost:8000 par sécurité)

    - URI de redirection autorisés : C'est ici que vous déclarez votre fonction callback ! Cliquez sur "Ajouter une URL" et mettez l'exact chemin vers votre vue :
    http://127.0.0.1:8000/auth/callback/

    - Cliquez sur Créer.
 Étape 5 : Récupérer les clés

 Une fenêtre surgissante s'affiche avec :

    - Votre ID de client (Une longue chaîne qui finit par .apps.googleusercontent.com)

    - Votre Code secret du client (Une clé secrète).
 Etape 6: copier les identifianta dans les variables d'environnement dans le fichier .env


5. Configurer les variables d'environnement :
```bash
cp .env.example .env
# Modifier les valeurs dans .env selon vos besoins conculter le fichier .env.example pour la configuration du fichier .env
```

6. Appliquer les migrations :
```bash
python manage.py migrate
```

7. Créer un superutilisateur :
```bash
python manage.py createsuperuser
```

8. Lancer le serveur de développement :
```bash
python manage.py runserver
```
