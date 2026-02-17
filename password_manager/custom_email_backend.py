import ssl
from django.core.mail.backends.smtp import EmailBackend
from django.conf import settings

class CustomEmailBackend(EmailBackend):
    def open(self):
        # Utiliser le contexte SSL configuré dans settings.py
        if hasattr(settings, 'EMAIL_SSL_CONTEXT'):
            self.ssl_context = settings.EMAIL_SSL_CONTEXT
        else:
            # Fallback: contexte SSL permissif
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        
        return super().open()
