FROM python:3.11-alpine   #permet de prendre la version la plus legere de python 
WORKDIR /app                # defini le working directory 

COPY  requirements.txt .    # copi le fichier requirements.txt dans le app/
RUN pip install -r requirements.txt   # install des dependance du projet
COPY . .        # copie requirements.txt ne change pas, docker reutilise la couche pip precedente
CMD ['python', 'manage.py', 'runserver', '0.0.0.0:8000']    # commande qui sera executer lors du lancement du conteneur

