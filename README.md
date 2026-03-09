# Projet gestionnaire de mot de pass 

Application web de gestionnaire de mot de pass développée avec Django et Django REST Framework.

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

4. Configurer les variables d'environnement :
```bash
cp .env.example .env
# Modifier les valeurs dans .env selon vos besoins conculter le fichier .env.example pour la configuration du fichier .env
```

5. Appliquer les migrations :
```bash
python manage.py migrate
```

6. Créer un superutilisateur :
```bash
python manage.py createsuperuser
```

7. Lancer le serveur de développement :
```bash
python manage.py runserver
```
