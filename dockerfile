#permet de prendre la version la plus legere de python 
FROM python:3.11-alpine   

# defini le working directory 
WORKDIR /app                

# copi le fichier requirements.txt dans le app/
COPY  requirements.txt .   

# install des dependance du projet
RUN pip install -r --no-cache-dir --break-system-packages requirements.txt   

# copie requirements.txt ne change pas, docker reutilise la couche pip precedente
COPY . .        

# Appliquer les migrations de base de données pour initialiser la DB
RUN python manage.py migrate

# Appliquer les migrations de base de données pour initialiser la DB
RUN python manage.py makemigrations

# Collecter les fichiers statiques pour servir les assets
RUN python manage.py collectstatic --noinput

#permet de peciser le port expose du conteneur
EXPOSE 8000

#represente le point d'entre du conteneur 
ENTRYPOINT ["python", "manage.py"]

# arguments par defaut du point d'entrer  qui sera executer lors du lancement du conteneur
CMD ["runserver", "0.0.0.0:8000"]    

