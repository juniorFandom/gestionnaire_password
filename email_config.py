# Configuration d'email pour le développement
# Copiez ce fichier vers settings.py ou importez-le selon vos besoins

# ===========================================
# OPTIONS DE CONFIGURATION EMAIL
# ===========================================

# OPTION 1: Console Backend (Recommandé pour le développement)
# Les emails sont affichés dans la console Django
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# OPTION 2: File Backend (Alternative pour le développement)
# Les emails sont sauvegardés dans des fichiers
# EMAIL_BACKEND = 'django.core.mail.backends.filebased.EmailBackend'
# EMAIL_FILE_PATH = 'sent_emails'  # Dossier où sauvegarder les emails

# OPTION 3: SMTP Backend (Pour la production)
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.gmail.com'
# EMAIL_PORT = 587
# EMAIL_USE_TLS = True
# EMAIL_USE_SSL = False
# EMAIL_HOST_USER = 'votre_email@gmail.com'
# EMAIL_HOST_PASSWORD = 'votre_mot_de_passe_application'
# EMAIL_TIMEOUT = 30

# ===========================================
# INSTRUCTIONS D'UTILISATION
# ===========================================

"""
Pour utiliser cette configuration:

1. POUR LE DÉVELOPPEMENT (Recommandé):
   - Utilisez l'OPTION 1 (Console Backend)
   - Les emails seront affichés dans votre terminal Django
   - Aucune configuration SMTP nécessaire

2. POUR TESTER L'ENVOI D'EMAILS:
   - Utilisez l'OPTION 2 (File Backend)
   - Les emails seront sauvegardés dans le dossier 'sent_emails'

3. POUR LA PRODUCTION:
   - Utilisez l'OPTION 3 (SMTP Backend)
   - Configurez correctement vos identifiants Gmail
   - Assurez-vous d'utiliser un mot de passe d'application Gmail

PROBLÈMES COURANTS GMAIL:
- Activez l'authentification à 2 facteurs sur votre compte Gmail
- Générez un mot de passe d'application spécifique
- Vérifiez que "Accès moins sécurisé" n'est pas activé (obsolète)
- Assurez-vous que votre réseau/firewall permet les connexions SMTP
"""
