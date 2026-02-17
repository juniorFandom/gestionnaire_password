import ssl, certifi
from django.core.mail import get_connection, send_mail
from django.conf import settings

def send_secure_mail(subject, message, recipient_list):
    # Créer un contexte SSL plus permissif pour éviter les erreurs de certificat
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = True
    context.verify_mode = ssl.CERT_OPTIONAL
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT
    
    connection = get_connection(
        host=settings.EMAIL_HOST,
        port=settings.EMAIL_PORT,
        username=settings.EMAIL_HOST_USER,
        password=settings.EMAIL_HOST_PASSWORD,
        use_tls=settings.EMAIL_USE_TLS,
        use_ssl=getattr(settings, 'EMAIL_USE_SSL', False),
        timeout=10,
        ssl_context=context
    )
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, recipient_list, connection=connection)
